import logging
import re
import time
import requests_html

from dao.src_db_dao import DBInit, CVEDao, CveAffectDao, CveReferDao
from model.src_db_model import CveRecord, CveAffectRecord, CveReferRecord


class CveOnlineCollector:
    def __init__(self):
        db_init = DBInit()
        self.cve_dao = CVEDao(db_init.session)
        self.cve_affect_dao = CveAffectDao(db_init.session)
        self.cve_refer_dao = CveReferDao(db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        }
        logging.basicConfig(level=logging.INFO)

    def traversal_all_cve_list_page(self):
        url = "https://www.cvedetails.com/vulnerability-list.php"
        logging.info(f"start to get: {url}")
        all_cve_list_page = self.request_deal_timeout(url)
        all_cve_list_page_urls = all_cve_list_page.html.xpath('//*[@id="pagingb"]/a/@href')
        for tmp_page in all_cve_list_page_urls[1622:]:
            url = f"https://www.cvedetails.com{tmp_page}"
            # self.traversal_one_cve_list_page(url)
            logging.info(f"start to traversal: {url}")
            cve_list_page = self.request_deal_timeout(url)
            cve_lists = cve_list_page.html.xpath('//*[@id="vulnslisttable"]/tr/td[2]/a/text()')
            for cve in cve_lists:
                self.parse_cve_page(cve)


    # def traversal_one_cve_list_page(self,url):
    #     logging.info(f"start to traversal: {url}")
    #     cve_list_page = self.request_deal_timeout(url)
    #     cve_lists = cve_list_page.html.xpath('//*[@id="vulnslisttable"]/tr/td[2]/a/text()')
    #     for cve in cve_lists:
    #         self.parse_cve_page(cve)

    def trace_cve_entry(self):
        year = time.strftime("%Y",time.localtime())
        url = f"https://www.cvedetails.com/vulnerability-list/year-{year}/vulnerabilities.html"
        logging.info(f"start to traversal: {url}")
        cve_list_page = self.request_deal_timeout(url)
        cve_lists = cve_list_page.html.xpath('//*[@id="vulnslisttable"]/tr/td[2]/a/text()')
        new_cve = []
        for cve in cve_lists:
            result = self.parse_cve_page(cve,model="trace")
            if result == 1000:
                break
            else:
                new_cve.append(cve)
        #self.send_notify_email(new_cve)



    def request_deal_timeout(self,url):
        try:
            page = self.session.get(url,headers=self.headers)
            return page
        except:
            page = self.request_deal_timeout(url)
            return page

    def get_first_value(self,elements):
        try:
            value = elements[0].strip()
        except:
            value = ""
        return value


    def parse_cve_page(self,cve,model="build"):
        url = f"https://www.cvedetails.com/cve/{cve}/"
        logging.info(f"start to parse: {url}")
        cve_page = self.request_deal_timeout( url)
        if cve_page.status_code != 200:
            print(f"request error {cve_page.status_code}")
            cve_record = CveRecord(cve=cve)
            self.cve_dao.add(cve_record)
            return 201
        cve_record = self.parse_cve(cve,cve_page)
        result = self.cve_dao.add(cve_record)
        if result == 1000 and model == "trace":
            return 1000
        if result != 1000:
            no_affect_div = cve_page.html.xpath('//*[@id="vulnprodstable"]/tr[2]/td/div[@class="errormsg"]')
            if len(no_affect_div) == 0:
                cve_affect_records = self.parse_cve_affect(cve,cve_page)
                for record_tmp in cve_affect_records:
                    print(f"{record_tmp}")
                    self.cve_affect_dao.add(record_tmp)
            cve_refer_records = self.parse_cve_refer(cve,cve_page)
            for record_tmp in cve_refer_records:
                print(f"{record_tmp}")
                self.cve_refer_dao.add(record_tmp)
            # self.cve_refer_dao.add(cve_refer_records)
        logging.info(f"finish parse: {url}")
        return 200


    def parse_cve(self,cve,cve_page):
        cve_element_xpath = {
            'cve_describe': '//*[@id="cvedetails"]/div[1]/text()',
            'date': '//*[@id="cvedetails"]/div[1]/span/text()',
            'cve_cvss_score': '//*[@id="cvssscorestable"]/tr[1]/td/div/text()',
            'cve_confidentiality_impact': '//*[@id="cvssscorestable"]/tr[2]/td//text()',
            'cve_integrity_impact': '//*[@id="cvssscorestable"]/tr[3]/td//text()',
            'cve_availability_impact': '//*[@id="cvssscorestable"]/tr[4]/td//text()',
            'cve_access_complexity': '//*[@id="cvssscorestable"]/tr[5]/td//text()',
            'cve_authentication': '//*[@id="cvssscorestable"]/tr[6]/td//text()',
            'cve_gained_access': '//*[@id="cvssscorestable"]/tr[7]/td//text()',
            'cve_vulnerability_types': '//*[@id="cvssscorestable"]/tr[8]/td//text()',
            'cve_cwe_id': '//*[@id="cvssscorestable"]/tr[9]/td//text()',
        }

        cve_describe = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_describe"]))
        date = self.get_first_value(cve_page.html.xpath(cve_element_xpath["date"]))
        date_pattern = "\d{4}-\d{2}-\d{2}"
        dates = re.findall(date_pattern,date)
        if len(dates) == 1:
            cve_publish_date = dates[0]
            cve_update_date = ''
        elif len(dates) == 2:
            cve_publish_date = dates[0]
            cve_update_date = dates[1]
        cve_cvss_score = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_cvss_score"]))
        cve_confidentiality_impact = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_confidentiality_impact"]))
        cve_integrity_impact = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_integrity_impact"]))
        cve_availability_impact = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_availability_impact"]))
        cve_access_complexity = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_access_complexity"]))
        cve_authentication = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_authentication"]))
        cve_gained_access = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_gained_access"]))
        cve_vulnerability_types = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_vulnerability_types"]))
        cve_cwe_id = self.get_first_value(cve_page.html.xpath(cve_element_xpath["cve_cwe_id"]))

        cve_mitre_url = f"http://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
        cve_cvedetails_url = f"https://www.cvedetails.com/cve/{cve}/"
        cve_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        cve_record = CveRecord(cve=cve, cve_describe=cve_describe, cve_publish_date=cve_publish_date, cve_update_date=cve_update_date, cve_mitre_url=cve_mitre_url,
                               cve_cvedetails_url=cve_cvedetails_url, cve_cvss_score=cve_cvss_score, cve_confidentiality_impact=cve_confidentiality_impact,
                               cve_integrity_impact=cve_integrity_impact, cve_availability_impact=cve_availability_impact, cve_access_complexity=cve_access_complexity,
                               cve_authentication=cve_authentication, cve_gained_access=cve_gained_access, cve_vulnerability_types=cve_vulnerability_types,
                               cve_cwe_id=cve_cwe_id,cve_collect_date=cve_collect_date)

        return cve_record

    def parse_cve_affect(self, affect_cve, cve_page):
        cve_affect_xpath = {
            'affect_product_type': '//*[@id="vulnprodstable"]/tr[2]/td[2]/text()',
            'affect_vendor': '//*[@id="vulnprodstable"]/tr[2]/td[3]/a/text()',
            'affect_product': '//*[@id="vulnprodstable"]/tr[2]/td[4]/a/text()',
            'affect_version': '//*[@id="vulnprodstable"]/tr[2]/td[5]//text()',
            'affect_update': '//*[@id="vulnprodstable"]/tr[2]/td[6]//text()',
            'affect_edition': '//*[@id="vulnprodstable"]/tr[2]/td[7]//text()',
            'affect_language': '//*[@id="vulnprodstable"]/tr[2]/td[8]//text()',
        }

        affect_tr = cve_page.html.xpath('//*[@id="vulnprodstable"]/tr')
        affect_tr_count = len(affect_tr)
        for i in range(affect_tr_count):
            if i != 0:
                pattern = "tr[\d]"
                repl = f"tr[{i+2}]"
                for k,v in cve_affect_xpath.items():
                    cve_affect_xpath[k] = re.sub(pattern,repl,v)

            affect_product_type = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_product_type"]))
            affect_vendor = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_vendor"]))
            affect_product = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_product"]))
            affect_version = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_version"]))
            affect_update = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_update"]))
            affect_edition = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_edition"]))
            affect_language = self.get_first_value(cve_page.html.xpath(cve_affect_xpath["affect_language"]))

            affect_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            cve_affect_record = CveAffectRecord(affect_cve=affect_cve, product_type=affect_product_type, affect_vendor=affect_vendor,
                                                affect_product=affect_product,affect_version=affect_version, affect_update=affect_update,
                                                affect_edition=affect_edition, affect_language=affect_language, affect_collect_date=affect_collect_date)
            yield cve_affect_record

    def parse_cve_refer(self,refer_cve,cve_page):
        cve_refer_xpath = {
            'refer_url': '//*[@id="vulnrefstable"]/tr[1]/td/a/text()',
            'refer_comment': '//*[@id="vulnrefstable"]/tr[1]/td/text()',
        }

        refer_tr = cve_page.html.xpath('//*[@id="vulnrefstable"]/tr')
        refer_tr_count = len(refer_tr)

        for i in range(refer_tr_count):
            if i != 0:
                pattern = "tr[\d]"
                repl = f"tr[{i+2}]"
                for k,v in cve_refer_xpath.items():
                    cve_refer_xpath[k] = re.sub(pattern,repl,v)

            refer_url = self.get_first_value(cve_page.html.xpath(cve_refer_xpath["refer_url"]))
            refer_comment = self.get_first_value(cve_page.html.xpath(cve_refer_xpath["refer_comment"]))
            refer_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            cve_refer_record = CveReferRecord(refer_cve=refer_cve, refer_url=refer_url, refer_comment=refer_comment,refer_collect_date=refer_collect_date)
            yield cve_refer_record

if __name__ == "__main__":
    cve_collector = CveOnlineCollector()
    # cve_collector.traversal_all_cve_list_page()
    cve_collector.trace_cve_entry()
import io
import logging
import os
import time
import zipfile
import requests_html
from bs4 import BeautifulSoup

from config.setting import get_random_user_agent, PATH_SPLIT
from dao.src_db_dao import CveReferDao, CveAffectDao, CVEDao, DBInit
from model.src_db_model import CveRecord, CveAffectRecord, CveReferRecord

# cve收集类
class CveOfflineCollector:
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

    def request_deal_timeout(self,url):
        try:
            headers = {
                'user-agent': get_random_user_agent(),
            }
            page = self.session.get(url,headers=headers)
            return page
        except:
            page = self.request_deal_timeout(url)
            return page

    def get_value_with_try(self,element,flag):
        try:
            value = element[flag]
        except:
            value = ""
        return value


    # 追踪每日更新cve
    def trace_cve_entry(self):
        cve_dir = "cve"
        now_date = time.strftime("%Y-%m-%d",time.localtime())
        # now_time = datetime.datetime.now()
        # yes_time = now_time + datetime.timedelta(days=-1)
        # yes_time_nyr = yes_time.strftime('%Y%m%d')
        url = "https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-modified.xml.zip"
        xml_file = f"{cve_dir}{PATH_SPLIT}nvdcve-modified.xml"
        if os.path.exists(xml_file):
            os.remove(xml_file)
        logging.info(f"start to download: {url}")
        page = self.request_deal_timeout(url)
        zip_file = zipfile.ZipFile(io.BytesIO(page.content))
        for file in zip_file.namelist():
            zip_file.extract(file, cve_dir)
        logging.info(f"download finish :{url}")
        logging.info(f"start to parse {xml_file}")
        with open(xml_file, encoding="utf-8") as fp:
            xml_soup = BeautifulSoup(fp, "lxml-xml")
        for entry in xml_soup.find_all("entry"):
            entry_type = entry['type']
            if entry_type != "CVE":
                continue
            cve = entry['name']

            cve_record = self.parse_cve(entry)

            result = self.cve_dao.add(cve_record)
            if result != 1000:
                logging.info(f"{cve_record.cve} is not existed and insert success")
                cve_affect_records = self.parse_cve_affect(cve, entry)
                for record_tmp in cve_affect_records:
                    print(f"{record_tmp}")
                    self.cve_affect_dao.add(record_tmp)
                cve_refer_records = self.parse_cve_refer(cve, entry)
                for record_tmp in cve_refer_records:
                    print(f"{record_tmp}")
                    self.cve_refer_dao.add(record_tmp)
            elif result == 1000:
                result_update = self.cve_dao.update(cve_record)
                if result_update == 1000:
                    logging.info(f"{cve_record.cve} is not need to update")
                elif result_update == 200:
                    cve_affect_records = self.parse_cve_affect(cve, entry)
                    self.cve_affect_dao.update(cve,cve_affect_records)
                    cve_refer_records = self.parse_cve_refer(cve, entry)
                    self.cve_refer_dao.update(cve,cve_refer_records)
            logging.info(f"finish parse: {cve}")

    # 下载xml文件
    def start_parse(self):
        now_year = int(time.strftime("%Y", time.localtime()))
        cve_dir = "cve"
        xml_file = f"{cve_dir}{PATH_SPLIT}nvdcve-{now_year}.xml"
        if os.path.exists(xml_file):
            os.remove(xml_file)

        for year in range(2002,now_year+1):
            xml_file = f"{cve_dir}{PATH_SPLIT}nvdcve-{year}.xml"
            # cve_zip_dir = f"{cve_dir}\\zip"
            if not os.path.exists(cve_dir):
                os.mkdir(cve_dir)
            if not os.path.exists(xml_file):
                logging.info(f"start to deal with {year} xml")
                self.parse_xml_by_year(year)
            else:
                logging.info(f"{year} xml existed and will skip")

    # 逐年下载和解析xml文件
    def parse_xml_by_year(self, year):
        cve_dir = "cve"
        # if not os.path.exists(f"{cve_dir}\\nvdcve-{year}.xml"):
        url = f"https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-{year}.xml.zip"
        page = self.request_deal_timeout(url)
        zip_file = zipfile.ZipFile(io.BytesIO(page.content))
        # zip_file.extractall(cve_zip_dir)
        # file_name = f"{cve_zip_dir}\\nvdcve-{year}.xml.zip"
        # os.rename(f"{cve_zip_dir}\\master", file_name)
        for file in zip_file.namelist():
            zip_file.extract(file, cve_dir)
        logging.info(f"download finish :{url}")
        xml_file = f"{cve_dir}{PATH_SPLIT}nvdcve-{year}.xml"
        self.parse_xml(xml_file)

    # 解析xml文件
    def parse_xml(self,xml_file):
        if not os.path.exists(xml_file):
            logging.error(f"{xml_file} not exists")
            return 404
        logging.info(f"start to parse {xml_file}")
        with open(xml_file,encoding="utf-8") as fp:
            xml_soup = BeautifulSoup(fp,"lxml-xml")
        # xml_tree = ET.parse(xml_file)
        # xml_root = xml_tree.getroot()
        # tag_prefix = xml_root.tag.replace("","nvd$")
        for entry in xml_soup.find_all("entry"):
            entry_type = entry['type']
            if entry_type != "CVE":
                continue
            cve = entry['name']
            cve_record = self.parse_cve(entry)
            result = self.cve_dao.add(cve_record)
            if result != 1000:
                cve_affect_records = self.parse_cve_affect(cve, entry)
                for record_tmp in cve_affect_records:
                    print(f"{record_tmp}")
                    self.cve_affect_dao.add(record_tmp)
                cve_refer_records = self.parse_cve_refer(cve, entry)
                for record_tmp in cve_refer_records:
                    print(f"{record_tmp}")
                    self.cve_refer_dao.add(record_tmp)
                # self.cve_refer_dao.add(cve_refer_records)
            logging.info(f"finish parse: {cve}")
            # return 200


    # 解析xml文件中的cve
    def parse_cve(self,entry):
        cve = entry['name']
        cve_describe = entry.find("descript").string
        cve_publish_date = self.get_value_with_try(entry,'published')
        cve_update_date = self.get_value_with_try(entry,'modified')
        cve_cvss_score = self.get_value_with_try(entry,'CVSS_score')

        cve_mitre_url = f"http://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
        cve_cvedetails_url = f"https://www.cvedetails.com/cve/{cve}/"
        cve_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        cve_record = CveRecord(cve=cve, cve_describe=cve_describe, cve_publish_date=cve_publish_date, cve_update_date=cve_update_date, cve_mitre_url=cve_mitre_url,
                               cve_cvedetails_url=cve_cvedetails_url, cve_cvss_score=cve_cvss_score,cve_collect_date=cve_collect_date)

        return cve_record

    # 解析cve影响的产品及版本
    def parse_cve_affect(self, cve,entry):
        affect_cve = cve
        affect_products = entry.find_all("prod")
        for prod in affect_products:
            # affect_product_type =prod.
            affect_vendor = self.get_value_with_try(prod,'vendor')
            affect_product = self.get_value_with_try(prod,'name')
            for ver in prod.find_all("vers"):
                affect_version = self.get_value_with_try(ver,"num")
                affect_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                cve_affect_record = CveAffectRecord(affect_cve=affect_cve, affect_vendor=affect_vendor,
                                                    affect_product=affect_product,affect_version=affect_version,
                                                    affect_collect_date=affect_collect_date)
                yield cve_affect_record

    # 解析cve的参考页面
    def parse_cve_refer(self, cve, entry):
        refer_cve = cve
        refer_items = entry.find_all("ref")
        for refer_item in refer_items:
            refer_url = self.get_value_with_try(refer_item,"url")
            refer_comment = ""
            if refer_item.string != refer_url:
                refer_comment += f"{refer_item.string}-"
            refer_comment += self.get_value_with_try(refer_item,"source")
            refer_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            cve_refer_record = CveReferRecord(refer_cve=refer_cve, refer_url=refer_url, refer_comment=refer_comment,refer_collect_date=refer_collect_date)
            yield cve_refer_record

if __name__ == "__main__":
    cve_parse = CveOfflineCollector()
    cve_parse.start_parse()
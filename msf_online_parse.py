import logging
import random
import re
import time
import requests_html
from dao.src_db_dao import DBInit, MSFDao
from model.src_db_model import MsfRecord


class MsfOnlineCollector:
    def __init__(self):
        db_init = DBInit()
        self.msf_dao = MSFDao(db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        }
        logging.basicConfig(level=logging.INFO)

    def request_deal_timeout(self,url):
        time.sleep(random.random(3))
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

    def get_construct_value(self,elements):
        split = "、"
        try:
            value = elements[0].strip()
        except:
            value = ""
            return value
        if len(elements) > 1:
            value += split.join(elements[1:])
        return value

    def trace_msf_module(self):
        url = "https://www.rapid7.com/db/modules"
        module_list_page = self.request_deal_timeout(url)
        module_lists = module_list_page.html.xpath('//*[@id="torso"]/div/section/div/h4/a/@href')

        # new_module = []
        for module_url in module_lists:
            result = self.parse_module_page(module_url,model="trace")
            if result == 1000:
                break
            # time.sleep(1)
            # else:
            #     module_name = module_url[12:]
                # new_module.append(module_name)
            
    def traversal_all_module_list_page(self):
        url = "https://www.rapid7.com/db/modules/"
        module_page = self.request_deal_timeout(url)
        page_size = module_page.html.xpath('//*[@id="torso"]/div/div[2]/p/b[1]/text()')[0].strip()
        page_size_pattern = "\d+$"
        page_size = int(re.search(page_size_pattern,page_size).group())
        module_count = int(module_page.html.xpath('//*[@id="torso"]/div/div[2]/p/b[2]/text()')[0].strip())
        page_count = module_count // page_size
        page_left = module_count % page_size
        if page_left != 0:
            page_count += 1

        for page_num in range(1,page_count+1):
            url = f"https://www.rapid7.com/db/modules?page={page_num}"
            # self.traversal_one_module_list_page(url)
            module_list_page = self.request_deal_timeout(url)
            module_lists = module_list_page.html.xpath('//*[@id="torso"]/div/section/div/h4/a/@href')
            for module_url in module_lists:
                self.parse_module_page(module_url)

    # def traversal_one_module_list_page(self,url):
    #     logging.info(f"start to traversal: {url}")
    #     module_list_page = self.request_deal_timeout(url)
    #     module_lists = module_list_page.html.xpath('//*[@id="torso"]/div/section/div/h4/a/@href')
    #     for module_url in module_lists:
    #         self.parse_module_page(module_url)

    def parse_module_page(self,relative_url,model="build"):
        url = f"https://www.rapid7.com{relative_url}"
        logging.info(f"start to parse: {url}")
        module_page = self.request_deal_timeout( url)
        if module_page.status_code != 200:
            print(f"request error {module_page.status_code}")
            msf_record = MsfRecord(module_name=relative_url[11:])
            self.msf_dao.add(msf_record)
            return 201
        msf_record = self.parse_module(module_page)
        result = self.msf_dao.add(msf_record)
        if result == 1000:
            print(f"insert error: record {msf_record.module_name} existed ")
            if model == "trace":
                return 1000
        elif result == 5000:
            print(f"{msf_record.module_name} commit exception")

        return 200

    def parse_module(self,module_page):
        module_element_xpath = {
            'module_name': '//*[@id="torso"]/div/article/section[2]/p/text()',
            'module_title': '//*[@id="torso"]/div/article/h1/text()',
            'module_describe': '//*[@id="torso"]/div/article/section[1]/p/text()',
            'module_authors': '//*[@id="torso"]/div/article/section[3]/ul/li/text()',
            'module_cve': '//*[@id="torso"]/div/article/section[4]/ul/li//text()',
            'module_references': '//*[@id="torso"]/div/article/section[4]/ul/li//text()',
            'module_targets': '//*[@id="torso"]/div/article/section[5]/ul/li/text()',
            'module_platforms': '//*[@id="torso"]/div/article/section[6]/ul/li/text()',
            'module_architectures': '//*[@id="torso"]/div/article/section[7]/ul/li/text()',
            'module_related_modules': '//*[@id="torso"]/div/article/section[11]/ul/li/text()',
            # 'cwe_id': '//*[@id="cvssscorestable"]/tr[9]/td//text()',
        }

        module_name = self.get_first_value(module_page.html.xpath(module_element_xpath["module_name"]))
        module_url = f"https://www.rapid7.com/db/modules/{module_name}"
        module_title = self.get_first_value(module_page.html.xpath(module_element_xpath["module_title"]))
        module_describe = self.get_first_value(module_page.html.xpath(module_element_xpath["module_describe"]))
        module_authors = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_authors"]))
        # module_cve = self.get_first_value(module_page.html.xpath(module_element_xpath["module_cve"]))
        module_references = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_references"]))
        module_cve_pattern = "CVE-\d{4}-\d+"
        module_cve = re.findall(module_cve_pattern,module_references)
        if len(module_cve) == 0:
            module_cve = ""
        else:
            module_cve = self.get_construct_value(module_cve)
        module_targets = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_targets"]))
        module_platforms = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_platforms"]))
        module_architectures = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_architectures"]))
        module_related_modules = self.get_construct_value(module_page.html.xpath(module_element_xpath["module_related_modules"]))
        # cwe_id = self.get_first_value(module_page.html.xpath(module_element_xpath["cwe_id"]))
        module_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        msf_record = MsfRecord(module_name=module_name, module_url=module_url, module_title=module_title, module_describe=module_describe, module_authors=module_authors,
                                      module_cve=module_cve, module_targets=module_targets, module_platforms=module_platforms, module_architectures=module_architectures,
                                      module_related_modules=module_related_modules,module_collect_date=module_collect_date)

        return msf_record

if __name__ == "__main__":
    msf_collector = MsfOnlineCollector()
    msf_collector.traversal_all_module_list_page()
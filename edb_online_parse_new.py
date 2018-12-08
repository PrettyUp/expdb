import io
import json
import re
import time
import zipfile
import os

import requests
import requests_html
from config.setting import START_EXPLOIT_DB_ID, END_EXPLOIT_DB_ID, get_random_user_agent, PATH_SPLIT
from dao.src_db_dao import EDBDao, DBInit
from model.src_db_model import EdbRecord


# exploitdb代码收集类
class EdbOnlineCollector:
    def __init__(self):
        self.db_init = DBInit()
        self.edb_dao = EDBDao(self.db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
            'Host': 'www.exploit-db.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'https://www.exploit-db.com/',
            'Connection': 'close'
        }

    # 遍历id从start_exploit_db_id到end_exploit_db_id的所有exp
    def traversal_exploit(self,start_exploit_db_id, end_exploit_db_id):
        #session = requests_html.HTMLSession()
        #session.keep_alive = False
        for exploit_db_id in range(start_exploit_db_id,end_exploit_db_id):
            exploit_record = self.parse_exploit(exploit_db_id)
            result = self.edb_dao.add(exploit_record)
            if result == 1000:
                print(f"insert error: record {exploit_record.edb_id} existed ")
            elif result == 5000:
                print(f"{exploit_record.edb_id} commit exception, process force to exit since the db session have been disconnect")
            time.sleep(1)

    # 检测exploitdb更新使用此函数
    def trace_edb_exploit(self):
        # 这些参数有些删掉后会引起返回结果的变化，没一个个分析直接全都保留了
        url = 'https://www.exploit-db.com/?draw=1&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&' \
              'columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&' \
              'columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&' \
              'columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&' \
              'columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&' \
              'columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&' \
              'columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&' \
              'columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&' \
              'columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=code&columns%5B8%5D%5Bname%5D=code.code&' \
              'columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=id&columns%5B9%5D%5Bname%5D=id&' \
              'columns%5B9%5D%5Bsearchable%5D=false&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&' \
              'columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=9&order%5B0%5D%5Bdir%5D=desc&start=0&length=50&' \
              'search%5Bvalue%5D=&search%5Bregex%5D=false&author=&port=&type=&tag=&platform=&_=1544231433800'

        headers = self.headers
        headers['X-Requested-With'] = 'XMLHttpRequest'
        exploit_page = self.request_deal_timeout(url)
        exploit_json_objs = json.loads(exploit_page.content)['data']
        for exploit_json_obj in exploit_json_objs:
            edb_id = exploit_json_obj['id']
            exploit_record = self.parse_exploit(edb_id)
            result = self.edb_dao.add(exploit_record)
            if result == 1000:
                print(f"insert error: record {exploit_record.edb_id} existed ")
                break
            elif result == 5000:
                print(f"{exploit_record.edb_id} commit exception")
                # self.db_init = DBInit()
                # # self.db_init.recreate_session()
                # self.edb_dao = EDBDao(self.db_init.session)
            time.sleep(1)

    # 处理超时报错
    def request_deal_timeout(self,url):
        try:
            headers = self.headers
            headers['user_agent'] = get_random_user_agent()
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Cache-Control']='max-age=0'
            proxy = {
                'http':'127.0.0.1:8080',
                'https':'127.0.0.1:8080'
            }
            # page = self.session.get(url,proxies=proxy,headers=headers)
            page = self.session.get(url, headers=self.headers,verify=False)
            return page
        except:
            page = self.request_deal_timeout(url)
            return page

    # 获取xpath结果第一个节点的值
    def get_first_value(self,elements):
        try:
            value = elements[0].strip()
        except:
            value = ""
        return value

    # 解析exp页面获取exp记录
    def parse_exploit(self,exploit_db_id):
        edb_url = f"https://www.exploit-db.com/exploits/{exploit_db_id}/"
        print(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} start to parse {edb_url}')
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        }
        element_xpath = {
            'edb_id': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[1]/div/div/div/div[1]/h6/text()',
            'edb_author': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[1]/div/div/div/div[1]/h6/a/text()',
            'edb_published': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[2]/h6/text()',
            'edb_cve': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[1]/div/div/div/div[2]/h6/a/text()',
            'edb_type': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[1]/div/div/div/div[2]/h6/a/text()',
            'edb_platform': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[1]/h6/a/text()',
            'edb_vulnerable_app_url':'/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[2]/div/a/@href',
            'edb_verified':'/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[2]/div/i/@class',
            'edb_exploit_raw_url':'/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[2]/div/a[2]/@href',
            'edb_exploit_raw':'/html/body/div/div[2]/div[2]/div/div/div[2]/div[1]/pre/code/text()',
        }
        # session = requests_html.HTMLSession()
        # session.keep_alive = False

        exploit_page = self.request_deal_timeout(edb_url)
        content_type = exploit_page.headers["content-type"]
        # 处理非html页面。形如https://www.exploit-db.com/exploits/45608/
        if "html" not in content_type:
            download_dir = "download_files"
            if not os.path.exists(download_dir):
                os.mkdir(download_dir)
            file_name = exploit_page.url.rsplit('/', 1)[1]
            if not os.path.exists(f'{download_dir}{PATH_SPLIT}{file_name}'):
                # 下载zip文件
                if "zip" in file_name:
                    zip_file = zipfile.ZipFile(io.BytesIO(content_type.content))
                    zip_file.extractall(download_dir)
                    os.rename("master",file_name)
                else:
                    open(f'{download_dir}{PATH_SPLIT}{file_name}', 'wb').write(exploit_page.content)
            exploit_record = EdbRecord(edb_id=exploit_db_id)
            return exploit_record
        if exploit_page.status_code != 200:
            print(f"request error {exploit_page.status_code}")
            exploit_record = EdbRecord(edb_id=exploit_db_id)
            return exploit_record

        # 处理不存在但status_code仍为200的页面。形如https://www.exploit-db.com/exploits/45634/
        try:
            edb_id = exploit_page.html.xpath(element_xpath['edb_id'])[0].strip(':').strip()
        except:
            print("request error，maybe this page have been remove")
            exploit_record = EdbRecord(edb_id=exploit_db_id)
            return exploit_record
        edb_author = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_author']))
        edb_published = exploit_page.html.xpath(element_xpath['edb_published'])[0].strip(':').strip()
        try:
            edb_cve = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_cve']))
            if edb_cve !='' and edb_cve != 'N/A':
                edb_cve =f'CVE-{edb_cve}'
        except:
            edb_cve = 'N/A'
        edb_type = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_type']))
        edb_platform = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_platform']))

        edb_aliases = ''
        edb_advisory_or_source_url = ''
        edb_tags = ''
        edb_verified = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_verified']))
        if 'mdi-close' in edb_verified:
            edb_verified = 'Verified'
        else:
            edb_verified = 'Unverified'
        edb_exploit_raw_url = f'https://www.exploit-db.com/raw/{edb_id}'
        edb_vulnerable_app_url = self.get_first_value(exploit_page.html.xpath(element_xpath['edb_vulnerable_app_url']))
        if edb_vulnerable_app_url != '':
            edb_vulnerable_app_url = 'https://www.exploit-db.com' +edb_vulnerable_app_url

        edb_exploit_raw = exploit_page.html.xpath(element_xpath['edb_exploit_raw'])
        # logging.warning(f"edb_exploit_raw length:{len(edb_exploit_raw)}")
        if len(edb_exploit_raw) > 65535:
            # edb_exploit_raw = "this exp is out off limit length 16777215 bytes"
            edb_exploit_raw = edb_exploit_raw[0:66635]

        edb_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        exploit_record = EdbRecord(edb_id=edb_id, edb_url=edb_url, edb_author=edb_author, edb_published=edb_published, edb_cve=edb_cve,
                                   edb_type=edb_type, edb_platform=edb_platform, edb_aliases=edb_aliases,
                                   edb_advisory_or_source_url=edb_advisory_or_source_url, edb_tags=edb_tags, edb_verified=edb_verified,
                                   edb_vulnerable_app_url=edb_vulnerable_app_url,edb_exploit_raw_url=edb_exploit_raw_url,
                                   edb_exploit_raw=edb_exploit_raw,edb_collect_date=edb_collect_date)
        # session.close()
        return exploit_record

    def __del__(self):
        pass

# 运行此文件即会自动收集exploit的exp
if __name__ == "__main__":
    edb_collect = EdbOnlineCollector()
    # 起始exp由setting的START_EXPLOIT_DB_ID决定
    start_exploit_db_id = 45824
    # 终止exp由setting的END_EXPLOIT_DB_ID决定
    end_exploit_db_id = 45825
    edb_collect.traversal_exploit(start_exploit_db_id,end_exploit_db_id)
    # url = "https://www.exploit-db.com/exploits/45638/"
    # exploit_record = edb_collect.parse_exploit(url)
    # print(f"exploit_record ={exploit_record}")

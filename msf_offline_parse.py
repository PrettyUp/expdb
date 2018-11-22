import logging
import os
import re
import subprocess
import time
from config.setting import EXPLOIT_DIR, GIT_SYNC_FLAG, PATH_SPLIT
from dao.src_db_dao import DBInit, MSFDao
from model.src_db_model import MsfRecord

# 用于收集msf模块的类
class MsfOfflineCollector:
    def __init__(self):
        db_init = DBInit()
        self.msf_dao = MSFDao(db_init.session)
        logging.basicConfig(level=logging.INFO)
        # self.exp_files = []
        # self.session = requests_html.HTMLSession()
        # self.session.keep_alive = False
        # self.headers = {
        #     'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        # }

    # git下载/同步metasploit-framework
    def git_sync_metasploit(self):
        if not os.path.exists("metasploit-framework"):
            subprocess.run("git clone https://github.com/rapid7/metasploit-framework.git")
        else:
            os.chdir("metasploit-framework")
            subprocess.run("git pull")
            os.chdir("..")


    def traversal_all_exploit(self):
        if GIT_SYNC_FLAG:
            self.git_sync_metasploit()
        exploit_dir = EXPLOIT_DIR
        # exploit_dir = "F:\\github\\metasploit-framework\\modules\\exploits"
        if not os.path.exists(exploit_dir):
            logging.error(f"{exploit_dir} not exist")
            return 400
        self.traversal_dir(exploit_dir)

    def traversal_dir(self,dir):
        dir_contains = os.listdir(dir)
        for tmp in dir_contains:
            tmp_path = f"{dir}{PATH_SPLIT}{tmp}"
            if os.path.isfile(tmp_path) and tmp_path.find(".rb")!=-1:
                metasploit_record = self.parse_module(tmp_path)
                result = self.msf_dao.add(metasploit_record)
                if result == 1000:
                    print(f"insert error: record {metasploit_record.module_name} existed ")
                elif result == 5000:
                    print(f"{metasploit_record.module_name} commit exception")
                # time.sleep(1)
                # return 200

            elif os.path.isdir(tmp_path):
                sub_dir = tmp_path
                self.traversal_dir(sub_dir)

    # 解析获取msf模块
    def parse_module(self,module_file):
        logging.info(f"start to parse {module_file}")
        module_element_pattern = {
            'module_name': '//*[@id="torso"]/div/article/section[2]/p/text()',
            'module_title': "Name[ |\t|\S]+['|\"],\n",
            'module_publish_date':"['|\"]DisclosureDate['|\"][ |\t|\S]+['|\"],*\n",
            'module_describe': "['|\"]Description['|\"][^\}]+},\n",
            'module_authors': "['|\"]Author['|\"][^\]]+\],\n",
            'module_cve': "['|\"]CVE['|\"],\s['|\"]\d{4}-\d+['|\"]",
            'module_references': '//*[@id="torso"]/div/article/section[4]/ul/li//text()',
            'module_targets': '//*[@id="torso"]/div/article/section[5]/ul/li/text()',
            'module_platforms': "['|\"]Platform['|\"][ |\t]+=>[ |\t]+\[*[^\]]+\]*,\n",
            'module_architectures': '//*[@id="torso"]/div/article/section[7]/ul/li/text()',
            'module_related_modules': '//*[@id="torso"]/div/article/section[11]/ul/li/text()',
            # 'cwe_id': '//*[@id="cvssscorestable"]/tr[9]/td//text()',
        }
        file_obj = open(module_file,"r")
        file_content = file_obj.read()
        module_name_start_pos = module_file.find("exploits")
        module_name = module_file[module_name_start_pos:-3].replace("exploits","exploit")
        module_name = module_name.replace("\\","/")
        module_url = f"https://www.rapid7.com/db/modules/{module_name}"
        module_title = self.modify_module_title(self.get_first_value(re.findall(module_element_pattern['module_title'],file_content)))
        module_publish_date = self.get_first_value(re.findall(module_element_pattern['module_publish_date'],file_content))
        if module_publish_date != "":
            module_publish_date = self.modify_module_date(module_publish_date)
        module_describe = self.modify_module_describe(self.get_first_value(re.findall(module_element_pattern['module_describe'],file_content)))
        module_authors = self.get_first_value(re.findall(module_element_pattern['module_authors'],file_content))
        module_cve = self.modify_module_cve(self.get_first_value(re.findall(module_element_pattern['module_cve'], file_content)))
        module_platforms = self.modify_module_platforms(self.get_first_value(re.findall(module_element_pattern['module_platforms'],file_content)))

        module_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        metasploit_record = MsfRecord(module_name=module_name, module_url=module_url,module_title=module_title,module_publish_date=module_publish_date,
                                      module_describe=module_describe, module_authors=module_authors,
                                      module_cve=module_cve, module_platforms=module_platforms,module_collect_date=module_collect_date)
        file_obj.close()
        return metasploit_record

    # 以下几个modify都是用于标准化相应值
    def modify_module_title(self,module_title):
        module_titles = module_title.split("=>")
        try:
            mod_module_title = module_titles[1].strip().strip("'").strip('"')
        except:
            mod_module_title = ""
        return mod_module_title

    def modify_module_describe(self,module_describe):
        start_pos = module_describe.find("{")+1
        end_pos = module_describe.find("}")
        mod_module_describe = module_describe[start_pos:end_pos].strip()
        return mod_module_describe

    def modify_module_cve(self, module_cve):
        mod_cve = module_cve.replace('"', '').replace("'", "").replace(", ", "-")
        return mod_cve

    def modify_module_date(self, module_publish_date):
        comment_pos = module_publish_date.find("#")
        if comment_pos !=-1:
            module_publish_date=module_publish_date[:comment_pos]
        elements = module_publish_date.split("=>")
        mod_date = elements[1].strip().replace(",","").strip("'").strip('"')
        mod_date = time.strftime("%Y-%m-%d",time.strptime(mod_date,"%b %d %Y"))
        return mod_date

    def modify_module_platforms(self,module_platform):
        comment_pos = module_platform.find("#")
        if comment_pos != -1:
            module_platform = module_platform[:comment_pos]
        module_platforms = module_platform.split("=>")
        try:
            mod_module_platforms = module_platforms[1].strip()
        except:
            mod_module_platforms = ""
        return mod_module_platforms

    def get_first_value(self,values):
        if len(values) == 0:
            value = ""
        else:
            value = values[0]
        return value


# 此main实现msf所有模块的收集
if __name__ == "__main__":
    msf_collector = MsfOfflineCollector()
    msf_collector.traversal_all_exploit()
    # for file in msf_collector.exp_files:
    #     print(f"{file}")
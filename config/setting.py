import platform
import random

# all_request
# 系统目录分割符
SYSTEMOS = platform.system()
if "Windows" in SYSTEMOS:
    PATH_SPLIT = "\\"
else:
    PATH_SPLIT = "/"
# user-agnet头
USER_AGENT = [
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 UBrowser/6.2.4094.1 Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729;"
]

# 用于生成随机user-agent
def get_random_user_agent():
    user_agnet = random.choice(USER_AGENT)
    return user_agnet

# src_db_dao.py
# 数据库连接语句
DB_CONNECT_STRING = 'mysql+pymysql://root:root@10.10.6.91/expdb'

# cve_offline_parse.py

# edb_online_parse.py
# 要收集的exploitdb的起始id和结束id
START_EXPLOIT_DB_ID= 2
END_EXPLOIT_DB_ID = 46759

# msf_offline_parse.py
# 是否启用git从github下载msf
GIT_SYNC_FLAG = True
# 指定exploits文件夹位置
EXPLOIT_DIR = f"metasploit-framework{PATH_SPLIT}modules{PATH_SPLIT}exploits"

# daily_trace_report.py
# 用于发送邮件的邮箱
SENDER_SENDER_EMAIL_ADDRESS = "your_email@qq.com"
# 用于发送邮件的邮箱的密码
SENDER_EMAIL_PASSWORD = "your_email_passwd"
# 用于发送邮件的邮箱的服务器
SMTP_SERVER_HOST = "smtp.qq.com"
# 用于发送邮件的邮箱的服务器的端口
SMTP_SERVER_PORT = 465
# 报告要发送到的邮箱
RECEIVER_EMAIL = "your_target_email@qq.com"

# search_engine.py
# shodan的key
SHODAN_API_KEY = "2TmIvimpoSl17bytI2lJBtfSDJVpSE6F"

# exploit_tool.py
# 要获取其开放的服务，并查找相关cve、msf模块、edb模块的ip
IP_LISTS = ['192.146.137.131','37.233.84.212']
# 查找类型；可为cve/msf/edb
SEARCH_TYPE = "cve"
# 在查询结果中，用于查找适用ip的cve、msf模块、edb模块的起止记录
START_NUMBER = 14
TOTAL_COUNT = 50


import logging
import smtplib
import time
from email.header import Header
from email.mime.text import MIMEText

from cve_offline_parse import CveOfflineCollector
from edb_online_parse import EdbOnlineCollector
from msf_online_parse import MsfOnlineCollector
from config.setting import SENDER_SENDER_EMAIL_ADDRESS, SENDER_EMAIL_PASSWORD, SMTP_SERVER_HOST, SMTP_SERVER_PORT, RECEIVER_EMAIL
from dao.src_db_dao import DBInit, MSFDao, EDBDao, CVEDao
from model.src_db_model import CveRecord, MsfRecord, EdbRecord


# 收集cve、msf、edb更新情况类
class DailyTraceReportor:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        db_init = DBInit()
        self.cve_dao = CVEDao(db_init.session)
        self.msf_dao = MSFDao(db_init.session)
        self.edb_dao = EDBDao(db_init.session)

    #
    def gen_report(self):
        now_day = time.strftime("%Y-%m-%d", time.localtime())
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace cve entry')
        # CveOfflineCollector.trace_cve_entry()
        # new_cve_entrys = self.cve_dao.query(CveRecord,now_day in CveRecord.cve_collect_date)
        new_cve_entrys = []
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace cve entry finished')
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace msf module')
        MsfOnlineCollector.trace_msf_module()
        new_msf_modules = self.msf_dao.query(MsfRecord,now_day in MsfRecord.module_collect_date)
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace msf module finished')
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace edb exploit')
        EdbOnlineCollector.trace_edb_exploit()
        new_edb_exploits = self.edb_dao.query(EdbRecord,now_day in EdbRecord.edb_collect_date)
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace edb exploit finished')
        email_context = self.gen_email_context(new_cve_entrys,new_msf_modules,new_edb_exploits)
        self.send_notify_email(email_context)

    # 追踪更新
    def gen_report_test(self):
        now_day = time.strftime("%Y-%m-%d", time.localtime())
        new_cve_entrys = []
        new_msf_modules = []
        new_edb_exploits = []
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace cve entry')
        collector = CveOfflineCollector()
        collector.trace_cve_entry()
        new_cve_entrys = self.cve_dao.query(CveRecord, CveRecord.cve_collect_date.like(f"{now_day}%")).all()
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace cve entry finished')
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace msf module')
        collector = MsfOnlineCollector()
        collector.trace_msf_module()
        new_msf_modules = self.msf_dao.query(MsfRecord, MsfRecord.module_collect_date.like(f"{now_day}%")).all()
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace msf module finished')
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-start to trace edb exploit')
        collector = EdbOnlineCollector()
        collector.trace_edb_exploit()
        new_edb_exploits = self.edb_dao.query(EdbRecord, EdbRecord.edb_collect_date.like(f"{now_day}%")).all()
        logging.info(f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}-trace edb exploit finished')
        email_context = self.gen_email_context(new_cve_entrys,new_msf_modules,new_edb_exploits)

        self.send_notify_email(email_context)

    # 生成邮件主体内容
    def gen_email_context(self,new_cve_entrys,new_msf_modules,new_edb_exploits):
        email_context = ""
        date = time.strftime("%Y-%m-%d", time.localtime())

        if len(new_cve_entrys) == 0:
            email_context += f"<h3>一、{date}----mitre无新增CVE条目<h3>"
        else:
            email_context += f"<h3>一、{date}----mitre新增以下{len(new_cve_entrys)}个CVE：</h3>"
            email_context += "<table border=\"2\" style=\"border-collapse:collapse;\">"
            email_context += "<tr><th>CVE编号</th><th>mitre URL</th><th>cvedetails URL</th></tr>"
            for cve_entry in new_cve_entrys:
                email_context += f"<tr><td>{cve_entry.cve}</td>" \
                                 f"<td><a href=\"{cve_entry.cve_mitre_url}\">{cve_entry.cve_mitre_url}</a></td>" \
                                 f"<td><a href=\"{cve_entry.cve_cvedetails_url}\">{cve_entry.cve_cvedetails_url}</a></td></tr>"
            email_context += "</table>"
        email_context += "<br/><br/>"

        if len(new_msf_modules) == 0:
            email_context += f"<h3>二、{date}----msf无新收集模块</h3>"
        else:
            email_context += f"<h3>二、{date}----msf新收集以下{len(new_msf_modules)}个模块：</h3>"
            email_context += "<table border=\"2\" style=\"border-collapse:collapse;\">"
            email_context += "<tr><th>模块名称</th><th>模块URL</th><th>关联CVE</th></tr>"
            for msf_module in new_msf_modules:
                email_context += f"<tr><td>{msf_module.module_title}</td>" \
                                 f"<td><a href=\"https://www.rapid7.com/db/modules/{msf_module.module_name}\">https://www.rapid7.com/db/modules/{msf_module.module_name}</a></td>" \
                                 f"<td>{msf_module.module_cve}</td></tr>"

            email_context += "</table>"
        email_context += "<br/><br/>"

        if len(new_edb_exploits) == 0:
            email_context += f"<h3>三、{date}-----exploit-db无新收集exp</h3>"
        else:
            email_context += f"<h3>三、{date}-----exploit-db新收集以下{len(new_edb_exploits)}个exp：<h3>"
            email_context += "<table border=\"2\" style=\"border-collapse:collapse;\">"
            email_context += "<tr><th>模块ID</th><th>模块URL</th><th>关联CVE</th></tr>"
            for edb_exploit in new_edb_exploits:
                email_context += f"<tr><td>{edb_exploit.edb_id}</td>" \
                                     f"<td><a href=\"{edb_exploit.edb_url}\">{edb_exploit.edb_url}</a></td>" \
                                     f"<td>{edb_exploit.edb_cve}</td></tr>"
            email_context += "</table>"
        email_context += "<br/><br/>"

        return email_context

    # 发送邮件
    def send_notify_email(self,email_context):
        # 用于发送邮件的邮箱。修改成自己的邮箱
        sender_email_address = SENDER_SENDER_EMAIL_ADDRESS
        # 用于发送邮件的邮箱的密码。修改成自己的邮箱的密码
        sender_email_password = SENDER_EMAIL_PASSWORD
        # 用于发送邮件的邮箱的smtp服务器，也可以直接是IP地址
        # 修改成自己邮箱的sntp服务器地址；qq邮箱不需要修改此值
        smtp_server_host = SMTP_SERVER_HOST
        # 修改成自己邮箱的sntp服务器监听的端口；qq邮箱不需要修改此值
        smtp_server_port = SMTP_SERVER_PORT
        # 要发往的邮箱
        receiver_email = RECEIVER_EMAIL
        # 要发送的邮件主题
        date = time.strftime("%Y-%m-%d",time.localtime())
        message_subject = f"CVE更新通知（{date}）"
        # 要发送的邮件内容
        message_context = email_context

        # 邮件对象，用于构建邮件
        message = MIMEText(message_context, 'html', 'utf-8')
        # 设置发件人（声称的）
        message["From"] = Header(sender_email_address, "utf-8")
        # 设置收件人（声称的）
        message["To"] = Header(receiver_email, "utf-8")
        # 设置邮件主题
        message["Subject"] = Header(message_subject, "utf-8")

        # 连接smtp服务器。如果没有使用SSL，将SMTP_SSL()改成SMTP()即可其他都不需要做改动
        email_client = smtplib.SMTP_SSL(smtp_server_host, smtp_server_port)
        try:
            # 验证邮箱及密码是否正确
            email_client.login(sender_email_address, sender_email_password)
            print(f"smtp----login success, now will send an email to {receiver_email}")
        except:
            print("smtp----sorry, username or password not correct or another problem occur")
        else:
            # 发送邮件
            email_client.sendmail(sender_email_address, receiver_email, message.as_string())
            print(f"smtp----send email to {receiver_email} finish")
        finally:
            # 关闭连接
            email_client.close()


# 此main实现生成并发送每日cve、msf、edb更新报告
if __name__ == "__main__":
    reportor = DailyTraceReportor()
    reportor.gen_report_test()
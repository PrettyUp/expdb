import logging

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from search_engine import SearchEngine
from config.setting import DB_CONNECT_STRING
from model.src_db_model import Base, EdbRecord, CveRecord, CveAffectRecord, CveReferRecord, MsfRecord

# 数据库建立连接类
# 这种建立连接的方法不标准，但又不懂类似由框架管理数据库连接的方式怎么实现的
class DBInit():
    def __init__(self):
        exploit_db_name = 'exploit_db.db'
        #self.engine = create_engine(f'sqlite:///{exploit_db_name}?check_same_thread=False')
        self.engine = create_engine(DB_CONNECT_STRING)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        # 创建所有src_db_model.py中继承Base类的类对应的数据表
        # checkfirst=True表示创建之前先检测表是否已存在存在则不重新创建，其实默认就是True
        Base.metadata.create_all(self.engine, checkfirst=True)
        # self.recreate_session()

    # 这个本想用于数据库由于数据错误断开连接后重建连接，但并不能，所以其实没用
    def recreate_session(self):
        self.engine = create_engine(DB_CONNECT_STRING)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine, checkfirst=True)

# 基本dao类，其他后续dao继承该类
# 该类主要实现检测是否已存在同主键记录，及如果未存在则插入记录
class BaseDao():
    # def __init__(self,session,sub_dao_class):
    #     self.session = session
    #     self.sub_dao_class = sub_dao_class

    # 用于承接子类传过来的初始化数据
    def set_env(self,session,sub_dao_class,sub_dao_class_key):
        self.session = session
        self.sub_dao_class = sub_dao_class
        self.sub_dao_class_key = sub_dao_class_key

    # 实现插入单条记录操作
    def add(self,records=None):
        if records is None:
            return 4001
        key = inspect(self.sub_dao_class).primary_key[0].name
        try:
            exist_flag = self.exist(records.__getattribute__(key))
        except:
            exist_flag = False

        if exist_flag:
            return 1000
        if not isinstance(records, dict):
            self.session.add(records)
        elif isinstance(records, dict):
            self.session.add_all(records)
        # try:
        #     result = self.session.commit()
        # except:
        #     result = 5000
        #     return result
        try:
            result = self.session.commit()
        except:
            return 5000
        return result

    # 实现插入多条记录操作，实际都是单条的，这个方法并没用到
    def add_all(self,records=None):
        if records is None:
            return 4001
        self.session.add_all(records)
        result = self.session.commit()
        return result

    # 查询数据并返回所有记录
    def query(self,table_or_column_name=None,filter=None):
        if filter is None:
            result = self.session.query(table_or_column_name)
        else:
            result = self.session.query(table_or_column_name).filter(filter)
        return result

    # 查询数据并返回首条记录
    def query_first(self,table_or_column_name=None,filter=None):
        if filter is None:
            result = self.session.query(table_or_column_name).first()
        else:
            result = self.session.query(table_or_column_name).filter(filter).first()
        return result

    # 查询同主键记录是否已在表中存在
    def exist(self, key_value):
        # column_name = "func.count(exploit_info.edb_id)"
        # key = inspect(self.sub_dao_class).primary_key[0].name
        filter = (self.sub_dao_class_key == f'{key_value}')
        result = self.query(table_or_column_name=self.sub_dao_class,filter=filter)
        if result.count() != 0:
            return True
        return False

    # 这个是测试用的，实际并没用到
    def exist_query(self):
        edb_id = 5040
        filter = (self.sub_dao_class_key ==f'{edb_id}')
        table_name = self.sub_dao_class
        result = self.session.query(table_name).filter(filter)
        for row in result:
            print(f"{row}")
        pass

# 表cve_records相关操作dao类
class CVEDao(BaseDao):
    def __init__(self,session):
        self.session = session
        self.set_env(self.session,CveRecord,CveRecord.cve)

    def update(self,record):
        filter = (self.sub_dao_class_key == f'{record.cve}')
        exist_record = self.query_first(CveRecord,filter)
        record.cve_collect_date = exist_record.cve_collect_date
        # if record is exist_record:
        #     logging.info(f"{exist_record.cve} is not need to update")
        #     return 1000
        logging.info(f"{exist_record.cve} need to update")
        exist_record.cve_describe = record.cve_describe
        exist_record.cve_update_date = record.cve_update_date
        exist_record.cve_cvss_score = record.cve_cvss_score
        self.session.commit()
        return 200

# 表cve_affect_records相关操作dao类
class CveAffectDao(BaseDao):
    def __init__(self,session):
        self.session = session
        self.set_env(self.session, CveAffectRecord, CveAffectRecord.affect_id)

    def update(self,cve,records):
        filter = (CveAffectRecord.affect_cve == f'{cve}')
        exist_recoeds = self.query(CveAffectRecord,filter)
        for exist_recoed in exist_recoeds:
            self.session.delete(exist_recoed)
        self.add_all(records)
        self.session.commit()
        return 200

# 表cve_refer_records相关操作dao类
class CveReferDao(BaseDao):
    def __init__(self,session):
        self.session = session
        self.set_env(self.session, CveReferRecord, CveReferRecord.refer_id)

    def update(self, cve,records):
        filter = (CveReferRecord.refer_cve == f'{cve}')
        exist_recoeds = self.query(CveReferRecord, filter)
        for exist_recoed in exist_recoeds:
            self.session.delete(exist_recoed)
        self.add_all(records)
        self.session.commit()
        return 200

# 表msf_records相关操作dao类
class MSFDao(BaseDao):
    def __init__(self,session):
        self.session = session
        self.set_env(self.session, MsfRecord, MsfRecord.module_name)

# 表edb_records相关操作dao类
class EDBDao(BaseDao):
    def __init__(self,session):
        self.session = session
        self.set_env(session, EdbRecord, EdbRecord.edb_id)

# 自动化检索工具相关dao类
class ExploitToolDao():
    def __init__(self,session):
        self.session = session
        self.search_engine = SearchEngine()

    # 通过最新的cve，查找存在访cve的ip
    def query_ip_by_last_cve(self,start_cve,total_cve):
        sql = f"select * from cve_records order by cve desc limit {start_cve},{total_cve}"
        cve_records = self.session.execute(sql)
        for cve_record in cve_records:
            sql = f"select distinct cve_records.cve,cve_records.cve_describe, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from cve_records,cve_affect_records " \
                  f"where cve_records.cve = \'{cve_record.cve}\' and cve_records.cve = cve_affect_records.affect_cve"
            affect_records = self.session.execute(sql)
            for affect_record in affect_records:
                if affect_record.affect_version == "" or affect_record.affect_version == "-":
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product)
                else:
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product, affect_record.affect_version)
                if len(ip_list) != 0:
                    for ip in ip_list:
                        exploit_rerord = {'cve': cve_record.cve, 'describe': cve_record.cve_describe, 'product': affect_record.affect_product,
                                          'version': affect_record.affect_version, 'ip': ip['ip'], 'port': ip['port']}
                        yield exploit_rerord
                else:
                    print(f"sorry, have no ip come with {affect_record}")

    # 通过最新的msf模块来，查找适用该msf模块的ip
    def query_ip_by_last_msf(self,start_msf_module,num_msf_module):
        sql = f"select * from msf_records where module_cve !='' order by module_cve desc limit {start_msf_module},{num_msf_module}"
        msf_records = self.session.execute(sql)
        for msf_record in msf_records:
            sql = f"select distinct msf_records.module_name,msf_records.module_cve, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from msf_records,cve_affect_records " \
                  f"where msf_records.module_cve = \'{msf_record.module_cve}\' and msf_records.module_cve = cve_affect_records.affect_cve"
            affect_records = self.session.execute(sql)
            for affect_record in affect_records:
                if affect_record.affect_version == "" or affect_record.affect_version == "-":
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product)
                else:
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product,affect_record.affect_version)
                if len(ip_list) !=0:
                    for ip in ip_list:
                        exploit_rerord = {'exploit':msf_record.module_name,'cve':msf_record.module_cve,'product':affect_record.affect_product,
                                           'version':affect_record.affect_version,'ip':ip.ip,'port':ip.port}
                        yield exploit_rerord
                else:
                    print(f"sorry, have no ip come with {affect_record}")

    # 通过最新的exploitdb模块，查找适用该模块的ip
    def query_ip_by_last_edb(self,start_edb,total_edb):
        sql = f"select * from edb_records where edb_cve !='' and edb_cve !='N/A' order by edb_cve desc limit {start_edb},{total_edb}"
        edb_records = self.session.execute(sql)
        for edb_record in edb_records:
            sql = f"select distinct edb_records.edb_url,edb_records.edb_cve, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from edb_records,cve_affect_records " \
                  f"where edb_records.cve = \'{edb_record.module_cve}\' and edb_records.cve = cve_affect_records.affect_cve"
            affect_records = self.session.execute(sql)
            for affect_record in affect_records:
                if affect_record.affect_version == "" or affect_record.affect_version == "-":
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product)
                else:
                    ip_list = self.search_engine.shodan_service_get_ips(affect_record.affect_product,affect_record.affect_version)
                if len(ip_list) !=0:
                    for ip in ip_list:
                        exploit_rerord = {'exploit':edb_record.edb_url,'cve':edb_record.edb_cve,'product':affect_record.affect_product,
                                           'version':affect_record.affect_version,'ip':ip.ip,'port':ip.port}
                        yield exploit_rerord
                else:
                    print(f"sorry, have no ip come with {affect_record}")

    # 通过ip开放的服务及其版本，查找该服务及版本存在的cve
    def query_cve_entry_by_service(self,service,version):
        sql = f"select * from cve_affect_records where affect_product like \'%{service}%\' and affect_version = \'{version}\'"
        records = self.session.execute(sql)
        for record in records:
            sql = f"select distinct cve_records.cve,cve_records.cve_describe, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from msf_records,cve_affect_records " \
                  f"where cve_affect_records.affect_cve = \'{record.affect_cve}\' and cve_records.module_cve = cve_affect_records.affect_cve"
            cve_records = self.session.execute(sql)
            yield cve_records

    # 通过ip开放的服务及其版本，查找适用于该服务及版本的msf模块
    def query_msf_module_by_service(self,service,version):
        sql = f"select * from cve_affect_records where affect_product like \'%{service}%\' and affect_version = \'{version}\'"
        records = self.session.execute(sql)
        for record in records:
            sql = f"select distinct msf_records.module_name,msf_records.module_cve, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from msf_records,cve_affect_records " \
                  f"where cve_affect_records.affect_cve = \'{record.affect_cve}\' and msf_records.module_cve = cve_affect_records.affect_cve"
            module_records = self.session.execute(sql)
            yield module_records

    # 通过ip开放的服务及其版本，查找适用于该服务及版本的exploit模块
    def query_edb_exploit_by_service(self,service,version):
        sql = f"select * from cve_affect_records where affect_product like \'%{service}%\' and affect_version = \'{version}\'"
        records = self.session.execute(sql)
        for record in records:
            sql = f"select distinct edb_records.edb_url,edb_records.edb_cve, cve_affect_records.affect_product,cve_affect_records.affect_version " \
                  f"from edb_records,cve_affect_records " \
                  f"where cve_affect_records.affect_cve = \'{record.affect_cve}\' and edb_records.edb_cve = cve_affect_records.affect_cve"
            module_records = self.session.execute(sql)
            yield module_records


# 此main为测试所用实际没什么用
if __name__ == "__main__":
    exploit_db_name = 'exploit_db.db'
    engine = create_engine(f'sqlite:///{exploit_db_name}?check_same_thread=False')
    Session = sessionmaker(bind=engine)
    session = Session()
    Base.metadata.create_all(engine, checkfirst=True)
    edb_dao = EDBDao(session)
    edb_dao.exist_query()


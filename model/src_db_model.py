from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String,Text
from sqlalchemy.dialects.mysql import MEDIUMTEXT

# 各model必须继承的基类
Base = declarative_base()

# cve_records表对应model
class CveRecord(Base):
    __tablename__ = 'cve_records'

    # 类变量与表字段关联
    cve = Column(String(100),primary_key=True)
    cve_describe = Column(Text)
    cve_publish_date = Column(String(255),index=True)
    cve_update_date = Column(String(255),index=True)
    cve_mitre_url = Column(String(255))
    cve_cvedetails_url = Column(String(255))
    cve_cvss_score = Column(String(255),index=True)
    cve_confidentiality_impact = Column(String(255))
    cve_integrity_impact = Column(String(255))
    cve_availability_impact = Column(String(255))
    cve_access_complexity = Column(String(255))
    cve_authentication = Column(String(255))
    cve_gained_access = Column(String(255))
    cve_vulnerability_types = Column(String(255))
    cve_cwe_id = Column(String(100))
    cve_collect_date = Column(String(100))

    def __repr__(self):
        return f"<CveRecord(cve={self.cve}, cve_cve_describe={self.cve_describe},cve_publish_date={self.cve_publish_date}, " \
               f"cve_update_date={self.cve_update_date},cve_mitre_url={self.cve_mitre_url},cve_cvedetails_url={self.cve_cvedetails_url}," \
               f"cve_cvss_score={self.cve_cvss_score},cve_confidentiality_impact={self.cve_confidentiality_impact}," \
               f"cve_integrity_impact={self.cve_integrity_impact},cve_availability_impact={self.cve_availability_impact}," \
               f"cve_access_complexity={self.cve_access_complexity}," \
               f"cve_authentication={self.cve_authentication},cve_gained_access={self.cve_gained_access}" \
               f"cve_vulnerability_types={self.cve_vulnerability_types},cve_cwe_id={self.cve_cwe_id},cve_collect_date={self.cve_collect_date})>"

# cve_affect_records表对应model
class CveAffectRecord(Base):
    __tablename__ = 'cve_affect_records'

    # 类变量与表字段关联
    affect_id = Column(Integer, primary_key=True)
    affect_cve = Column(String(100),index=True)
    affect_product_type = Column(String(255))
    affect_vendor = Column(String(255),index=True)
    affect_product = Column(String(255),index=True)
    affect_version = Column(String(255),index=True)
    affect_update = Column(String(255))
    affect_edition = Column(String(255))
    affect_language = Column(String(255))
    affect_collect_date = Column(String(100))

    def __repr__(self):
        return f"<CveAffectRecord(affect_id={self.affect_id},affect_cve={self.affect_cve}, affect_product_type={self.affect_product_type}," \
               f"affect_affect_vendor={self.affect_vendor}, affect_product={self.affect_product},affect_version={self.affect_version}," \
               f"affect_update={self.affect_update},affect_edition={self.affect_edition},affect_language={self.affect_language}," \
               f"affect_collect_date ={self.affect_collect_date})>"

# cve_refer_records表对应model
class CveReferRecord(Base):
    __tablename__ = 'cve_refer_records'

    # 类变量与表字段关联
    refer_id = Column(Integer, primary_key=True)
    refer_cve = Column(String(100),index=True)
    refer_url = Column(String(255))
    refer_comment = Column(String(255))
    refer_collect_date = Column(String(100))

    def __repr__(self):
        return f"<CveReferRecord(refer_id={self.refer_id}, refer_cve={self.refer_cve},refer_url={self.refer_url}," \
               f"refer_comment={self.refer_comment},refer_collect_date={self.refer_collect_date})>"

# msf_records表对应model
class MsfRecord(Base):
    __tablename__ = 'msf_records'

    module_name = Column(String(255), primary_key=True)
    module_url = Column(String(255),index=True)
    module_title = Column(String(255),index=True)
    module_publish_date = Column(String(255),index=True)
    module_describe = Column(Text)
    module_authors = Column(String(255),index=True)
    module_cve = Column(String(255),index=True)
    module_references = Column(Text)
    module_targets = Column(String(255))
    module_platforms = Column(String(255))
    module_architectures = Column(String(255))
    module_related_modules = Column(Text)
    module_collect_date = Column(String(100))

    def __repr__(self):
        return f"<MsfRecord(module_name={self.module_name},module_url={self.module_url},module_title={self.module_title}," \
               f"module_publish_date={self.module_publish_date} module_describe={self.module_describe},module_authors={self.module_authors}, module_cve={self.module_cve}," \
               f"module_references={self.module_references},module_targets={self.module_targets},module_platforms={self.module_platforms}," \
               f"module_architectures={self.module_architectures},module_related_modules={self.module_related_modules}," \
               f"module_collect_date={self.module_collect_date})>"

# edb_records表对应model
class EdbRecord(Base):
    # 指定本类映射到users表
    __tablename__ = 'edb_records'

    # 类变量与表字段关联
    edb_id = Column(String(100), primary_key=True)
    edb_url = Column(String(255))
    edb_author = Column(String(255),index=True)
    edb_published = Column(String(255),index=True)
    edb_cve = Column(String(255),index=True)
    edb_type = Column(String(255))
    edb_platform = Column(String(255))
    edb_aliases = Column(String(255))
    edb_advisory_or_source_url = Column(String(255))
    edb_tags = Column(String(255))
    edb_verified = Column(String(255))
    edb_vulnerable_app_url = Column(String(255))
    edb_exploit_raw_url = Column(String(255))
    # Text 65535个字节，多处超过此长度所以需要MEDIUMTEXT。不过好像没用
    edb_exploit_raw = Column(MEDIUMTEXT)
    edb_collect_date = Column(String(100))

    def __repr__(self):
        return f"<EdbRecord(edb_id={self.edb_id}, edb_url={self.edb_url},edb_author={self.edb_author}, edb_published={self.edb_published}," \
               f"edb_cve={self.edb_cve},edb_type={self.edb_type},edb_platform={self.edb_platform},edb_aliases={self.edb_aliases}," \
               f"edb_advisory_or_source_url={self.edb_advisory_or_source_url},edb_verified={self.edb_verified},tags={self.edb_tags}," \
               f"edb_vulnerable_app={self.edb_vulnerable_app_url},edb_exploit_raw_url={self.edb_exploit_raw_url}," \
               f"edb_exploit_raw={self.edb_exploit_raw},edb_collect_date ={self.edb_collect_date})>"

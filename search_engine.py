import shodan
# SHODAN_API_KEY = "2TmIvimpoSl17bytI2lJBtfSDJVpSE6F"
from config.setting import SHODAN_API_KEY

# shodan操作类
class SearchEngine:
    def __init__(self):
        pass

    def get_value_deal_except(self,element,value_name):
        try:
            value = element[value_name]
        except:
            value = ""
        return value

    # 通过shodan获取ip上开放的服务及版本
    def shodan_ip_get_services(self,ip):
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        services = []
        host = shodan_api.host(ip)
        for item in host['data']:
            port = self.get_value_deal_except(item,'port')
            product = self.get_value_deal_except(item,'product')
            version = self.get_value_deal_except(item,'version')
            service = {'ip':ip,'port':port,'product':product,'version':version}
            yield service
        #     services.append(service)
        # return services

    # 通过shodan获取存在存在该版本的服务的ip
    def shodan_service_get_ips(self,service,version=""):
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        matches = []
        print(f"shodan search {service} {version}")
        results = shodan_api.search(f"{service} {version}")
        for item in results['matches']:
            ip = item['ip_str']
            port = item['port']
            # product = self.get_value_deal_except(item,'product')
            # version = self.get_value_deal_except(item, 'version')
            product = service
            version = version
            matche = {'ip': ip, 'port': port, 'product': product, 'version': version}
            matches.append(matche)
        return matches

# 此main只用于测试实际没用到
if __name__ == "__main__":
    search_engine = SearchEngine()
    ip = "89.135.83.205"
    services = search_engine.shodan_ip_get_services(ip)
    if len(services) == 0:
        print(f"sorry,{ip} have not any service")
    else:
        print(f"congratulation,{ip} have those services:")
        for service in services:
            print(f"{service['ip']}/{service['port']}/{service['product']}/{service['version']}")

    service = "tomcat"
    version = "7.0"
    ips = search_engine.shodan_service_get_ips(service,version)
    if len(ips) == 0:
        print(f"sorry,have not any ip open {service}-{version}")
    else:
        print(f"congratulation,those ip have operate {service}-{version}:")
        for matche in ips:
            print(f"{matche['ip']}/{matche['port']}/{matche['product']}/{matche['version']}")

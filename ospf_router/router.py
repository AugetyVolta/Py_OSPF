import psutil
import ipaddress

def get_network_realInter():
    realInters = psutil.net_if_addrs()
    return realInters


class MyRouter():
    def __init__(self):
        self.router_id = self.getRouterId()

    
    """
    所有接口的最小IP地址作为routerId,但是接口不能是回环接口localhost
    """
    def getRouterId(self):
        realInters = get_network_realInter()
        routerID = None
        for interface_name, addresses in realInters.items():
            for address in addresses:
                if interface_name != 'lo' and address.family.name == "AF_INET":
                    if routerID is None or ipaddress.IPv4Address(address.address) < ipaddress.IPv4Address(routerID):
                        routerID = address.address
        return routerID
    
    def disConfig(self):
        print("\033[1;32m===========MyConfig===========\033[0m")
        print(f"router_id: {self.router_id}")
        

        print("\033[1;32m==============================\033[0m")
    
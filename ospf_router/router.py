import psutil
import ipaddress
from ospf_interface.interface import Interface

def get_network_realInter():
    realInters = psutil.net_if_addrs()
    return realInters


class MyRouter():
    def __init__(self):
        self.router_id = self.getRouterId()
        # 接口表{ip : interface}
        self.interfaces = self.initInterfaces()

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
    
    def initInterfaces(self):
        interfaces = {}
        realInters = get_network_realInter()
        for interface_name, addresses in realInters.items():
            for address in addresses:
                if interface_name != 'lo' and address.family.name == "AF_INET":
                    interfaces[address.address] = Interface(ip=address.address, 
                                                                 mask=address.netmask,
                                                                 router=self)
        return interfaces
    
    def disConfig(self):
        print("\033[1;32m===========MyConfig===========\033[0m")
        print(f"router_id: {self.router_id}")
        for i,inter in enumerate(self.interfaces.values()):
            print(f"\033[1;33m=========Inter{i+1}=========\033[0m")
            inter.disConfig()
            print()
        print("\033[1;32m==============================\033[0m")
    
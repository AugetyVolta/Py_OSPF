import psutil
import ipaddress
from config import InitialSequenceNumber, InterfaceState, NeighborState, NetworkType,logger,Config
from ospf_interface.interface import Interface
from ospf_lsdatabase.lsdb import LSADataBase
from ospf_packet.packet import OSPF_NetworkLSA, OSPF_NetworkLSA_Item, OSPF_RouterLSA, OSPF_RouterLSA_Item

def get_network_realInter():
    realInters = psutil.net_if_addrs()
    return realInters


class MyRouter():
    def __init__(self):
        self.router_id = self.getRouterId()
        # 接口表{ip : interface}
        self.interfaces = self.initInterfaces()
        # lsa序号,默认最小值
        self.lsa_seq = InitialSequenceNumber
        # 链路状态数据库,{area_id:lsdb}不同的area有不同的数据库
        self.lsdbs = self.initLSDataBase()

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

    def initLSDataBase(self):
        lsdbs = {}
        for interface in self.interfaces.values():
            if interface.area_id not in lsdbs.keys():
                lsdbs[interface.area_id] = LSADataBase()
            interface.lsdb = lsdbs[interface.area_id]
        return lsdbs
    
    def disConfig(self):
        print("\033[1;32m===========MyConfig===========\033[0m")
        print(f"router_id: {self.router_id}")
        for i,inter in enumerate(self.interfaces.values()):
            print(f"\033[1;33m=========Inter{i+1}=========\033[0m")
            inter.disConfig()
            print()
        print("\033[1;32m==============================\033[0m")
    
    def genRouterLSAs(self):
        # 对于每一个区域生成Router_LSA
        for area_id, lsdb in self.lsdbs.items():
            # 生成RouterLSA
            router_lsa = OSPF_RouterLSA(
                age = 0,
                options = 0x02,
                type = 1, # router LSA
                lsa_id = self.router_id, # 生成路由器的路由器标识
                adv_router = self.router_id,
                seq = self.lsa_seq,
                flags = 0,
                links = 0
            )
            # lsa序号增加
            self.lsa_seq += 1
             # 加入连接描述
            for interface in self.interfaces.values():
                # 如果所接入的网络不属于区域A,不修改
                if area_id != interface.area_id:
                    continue
                # 如果接口状态为Down,不增加
                elif interface.state == InterfaceState.S_Down:
                    continue
                # 如果是loopback
                elif interface.state == InterfaceState.S_Loopback:
                    #TODO:这个状态目前用不上
                    pass 
                # 广播,NBMA
                elif interface.type == NetworkType.T_BROADCAST or interface.type == NetworkType.T_NBMA:
                    link_dscription = OSPF_RouterLSA_Item(
                        tos = 0,
                        metric = interface.cost
                    )
                    if interface.state == InterfaceState.S_Waiting:
                        link_dscription.type = 3
                        link_dscription.link_id = calculate_network_address(interface.ip,interface.mask)
                        link_dscription.link_data = interface.mask
                    # 如果路由器与DR完全邻接，或路由器自身为DR且与至少一台其他路由器邻接
                    # 在本项目中一定满足,因此可以直接else
                    else:
                        link_dscription.type = 2
                        link_dscription.link_id = interface.dr 
                        link_dscription.link_data = interface.ip
                    # 加入到RouterLSA中
                    router_lsa.lsa_routers.append(link_dscription)
                    router_lsa.links += 1
            # 计算校验和和长度
            # TODO:计算校验和
            router_lsa.len = 24 + 12 * router_lsa.links
            # 加入到lsdb中
            old_lsa = lsdb.getLSA(router_lsa.type,router_lsa.lsa_id,router_lsa.adv_router)
            if old_lsa == None:
                lsdb.addLSA(router_lsa)
                logger.debug("\033[1;32mGenerate new Router LSA\033[0m")
                if Config.is_debug:
                    router_lsa.show()
            elif router_lsa.is_newer(old_lsa):
                lsdb.delLSA(old_lsa)
                lsdb.addLSA(router_lsa)
                logger.debug("\033[1;32mUpdate old Router LSA\033[0m")
                if Config.is_debug:
                    router_lsa.show()
            else:
                logger.debug("\033[1;32mNew Router LSA exists\033[0m")
            # 洪泛
            # TODO: 先空着

    def genNetworkLSAs(self,interface):
        lsdb = interface.lsdb
        # 生成NetworkLSA
        network_lsa = OSPF_NetworkLSA(
            age = 0,
            options = 0x02,
            type = 2, # network LSA
            lsa_id = interface.dr, # 该网络上DR的IP接口地址
            adv_router = self.router_id,
            seq = self.lsa_seq,
            network_mask = interface.mask
        )
        # lsa序号增加
        self.lsa_seq += 1
        # Network-LSA 中包含了与 DR 完全邻接的邻居列表，各台路由器由其 OSPF 路由器标识来识别
        for neighbor in interface.neighbors.values():
            if neighbor.state == NeighborState.S_Full:
                network_lsa.attached_routers.append(
                    OSPF_NetworkLSA_Item(
                        attached_router = neighbor.hostInter.router.router_id
                    )
                )
        # DR自己也在列表中
        network_lsa.attached_routers.append(
            OSPF_NetworkLSA_Item(
                attached_router = self.router_id
                )
            )
        # 计算校验和和len
        # TODO:计算校验和
        network_lsa.len = 24 + 4 * len(network_lsa.attached_routers)
        # 加入lsdb中
        old_lsa = lsdb.getLSA(network_lsa.type,network_lsa.lsa_id,network_lsa.adv_router)
        if old_lsa == None:
            lsdb.addLSA(network_lsa)
            logger.debug("\033[1;32mGenerate new Network LSA\033[0m")
            if Config.is_debug:
                network_lsa.show()
        elif network_lsa.is_newer(old_lsa):
            lsdb.delLSA(old_lsa)
            lsdb.addLSA(network_lsa)
            logger.debug("\033[1;32mGenerate new Network LSA\033[0m")
            if Config.is_debug:
                network_lsa.show()
        else:
            logger.debug("\033[1;32mNew Network LSA exists\033[0m")


def calculate_network_address(ip_str, netmask_str):
        # 将IP地址和掩码转换为IPv4Address和IPv4Network对象
        ip = ipaddress.IPv4Address(ip_str)
        netmask = ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").netmask
        # 计算网络地址
        network_address = ipaddress.IPv4Address(int(ip) & int(netmask))
        return str(network_address)
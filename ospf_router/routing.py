import ipaddress
from pyroute2 import IPRoute
from config import RoutingType,logger
from threading import Lock
INF = 999999999999999999

class RoutingTable():
    def __init__(self,router,router_id,lsdbs):
        # router
        self.router = router
        # router_id
        self.router_id = router_id
        # lsdb {area_id,lsdb}
        self.lsdbs = lsdbs
        # {router_id : node}
        self.nodes = {}
        # 路由表 {ip,routing_item}
        self.routing_items = {}
        # 锁
        self.lock = Lock()
    
    def generateRoutings(self):
        self.lock.acquire()
        # 清空上次的路由表
        logger.debug(f"\033[1;32mReset Route\033[0m")
        self.resetRoute()
        # 根据lsdb初始化节点
        logger.debug(f"\033[1;32mInit Nodes\033[0m")
        self.initNodes()
        print([n.id for n in self.nodes.values()])
        # 生成最短路径树
        logger.debug(f"\033[1;32mGenerate Tree\033[0m")
        self.Dijkstra(self.router_id)
        # 生成下一跳信息
        logger.debug(f"\033[1;32mGenerate Next hop\033[0m")
        try:
            self.generateNextHop(self.router_id)
        except:
            self.resetRoute()
            self.lock.release()
            return
        logger.debug(f"\033[1;32mGenerate Routing\033[0m")
        # 生成路由表和写入路由表
        try:
            self.genAndWrite(self.router_id)
        except:
            self.resetRoute()
            self.lock.release()
            return
        self.lock.release()

    def initNodes(self):
        # 目前只有一个区域
        lsdb = self.lsdbs['0.0.0.0']
        for lsa in lsdb.LSAs:
            # 处理Router LSA,不处理Network LSA
            if lsa.type != 1:
                continue
            if lsa.adv_router not in self.nodes.keys():
                self.nodes[lsa.adv_router] = Node(lsa.adv_router)
            cur_node = self.nodes[lsa.adv_router]
            cur_lsa = lsa
            for link in cur_lsa.lsa_routers:
                # TransNet
                if link.type == 2:
                    # link_data是路由器接口的ip
                    src_ip = link.link_data
                    cost = link.metric
                    # link_id是dr接口的ip地址,也是networkLSA的link_id
                    dr_inter_ip = link.link_id
                    networkLSA = lsdb.getNetworkLSA(lsa_id=dr_inter_ip)
                    if networkLSA != None:
                        for item in networkLSA.attached_routers:
                            router_id = item.attached_router
                            if router_id != cur_node.id:
                                cur_node.adjs[router_id] = Adjacency(src_ip,router_id,cost,src_mask=networkLSA.network_mask)
                # StubNet
                elif link.type == 3:
                    cur_node.adjs[link.link_id] = Adjacency(link.link_id,link.link_id,cost=link.metric,src_mask=link.link_data)
                    self.nodes[link.link_id] = Node(link.link_id)

    def Dijkstra(self,src):
        self.nodes[src].cost = 0
        for _ in self.nodes.values():
            minCost = INF
            rec = None
            for node in self.nodes.values():
                if node.color == False and node.cost < minCost:
                    minCost = node.cost
                    rec = node
            if rec != None:
                for adj_id,e in rec.adjs.items():
                    adj = self.nodes[adj_id]
                    if rec.cost + e.cost < adj.cost:
                        adj.cost = rec.cost + e.cost
                        adj.pred = rec
                rec.color = True
    
    def generateNextHop(self,src):
        # 设置树根的next_hop和interface_name
        root = self.nodes[src]
        root.next_hop = "0.0.0.0"
        root.interface_name = "xxx" # 用不上
        # 设置树根的直接下一跳的next_hop和interface_name
        for router_id,node in self.nodes.items():
            if router_id != src and node.pred.id == src:
                node.next_hop = node.adjs[src].src_ip #对面的接口地址就是自己的下一跳
                node.interface_name = self.router.interfaces[root.adjs[router_id].src_ip].ethname # 找到接口的名字
        
        # 设置其他的
        for router_id,node in self.nodes.items():
            if router_id != src and node.next_hop == None and node.cost != INF: # 防止多网卡无用表项
                pred = node.pred
                while pred.next_hop == None:
                    pred = pred.pred
                node.next_hop = pred.next_hop
                node.interface_name = pred.interface_name
    
    def genAndWrite(self,src):
        # 首先处理树根路由器直连的网段的路由
        root = self.nodes[src]
        for _,adj in root.adjs.items():
            # src_ip是interface ip
            dest_id = calculate_network_address(adj.src_ip,adj.src_mask)
            interface_name = self.router.interfaces[adj.src_ip].ethname
            new_rt_item = RoutingItem(
                destination_id=dest_id,
                mask=adj.src_mask,
                cost=root.cost+adj.cost,
                next_hop="0.0.0.0",
                adv_router=root.id,
                interface_name=interface_name
            )
            self.routing_items[dest_id] = new_rt_item
        
        # 接下来处理其他的路由
        for router_id,node in self.nodes.items():
            # 如果是根或者不可达的节点，忽略
            if router_id == src or node.cost == INF:
                continue
            for _,adj in node.adjs.items():
                # 根据邻接的接口ip和mask计算网络地址
                dest_id = calculate_network_address(adj.src_ip,adj.src_mask)
                new_rt_item = RoutingItem(
                    destination_id=dest_id,
                    mask=adj.src_mask,
                    cost=node.cost+adj.cost,
                    next_hop=node.next_hop,
                    adv_router=node.id,
                    interface_name=node.interface_name
                )
                if dest_id in self.routing_items.keys():
                    old_rt_item = self.routing_items[dest_id]
                    if new_rt_item.cost < old_rt_item.cost:
                        self.routing_items[dest_id] = new_rt_item
                else:
                    self.routing_items[dest_id] = new_rt_item

        # 写系统路由表
        for rtitem in self.routing_items.values():
            self.add_ipv4_route(rtitem)

    def resetRoute(self):
        for rtitem in self.routing_items.values():
            self.del_ipv4_route(rtitem)
        self.routing_items.clear()
        self.nodes.clear()

    def add_ipv4_route(self, rtitem):
        ip = IPRoute()
        try:
            ip.route("add",
                    dst=f"{rtitem.destination_id}/{mask_to_length(rtitem.mask)}",
                    gateway=rtitem.next_hop,
                    oif=ip.link_lookup(ifname=rtitem.interface_name)[0])
            print("IPv4 route added successfully")
        except Exception as e:
            print(f"Failed to add IPv4 route: {e}")
        finally:
            ip.close()
    
    def del_ipv4_route(self, rtitem):
        ip = IPRoute()
        try:
            ip.route("del",
                    dst=f"{rtitem.destination_id}/{mask_to_length(rtitem.mask)}",
                    gateway=rtitem.next_hop,
                    oif=ip.link_lookup(ifname=rtitem.interface_name)[0])
            print("IPv4 route deleted successfully")
        except Exception as e:
            print(f"Failed to del IPv4 route: {e}")
        finally:
            ip.close()

class RoutingItem():
    def __init__(self,destination_id,mask,cost,next_hop,adv_router,interface_name,area_id="0.0.0.0",destination_type = RoutingType.Network):
        # 目标类型 网络/路由器,因为不存在ABR和ASBR,所有类型都为Network
        self.destination_type = destination_type
        # 目标标识，对网络项，标识是所关联的 IP 地址；对路由器项，标识是 OSPF 的路由器标识
        self.destination_id = destination_id
        # 仅为网络项定义。网络的 IP 地址与地址掩码一起，定义了 IP 地址的范围
        self.mask = mask
        # 总cost
        self.cost = cost
        # 下一跳
        self.next_hop = next_hop
        # 宣告路由器 对应的Node节点中的id
        self.adv_router = adv_router
        # 区域id
        self.area_id = area_id
        # 接口网卡名
        self.interface_name = interface_name

class Node():
    def __init__(self,id):
        # 节点的标识，对于路由器节点，节点标识就是 OSPF 路由器标识；对于网络节点，就是网络上 DR 的 IP 地址
        self.id = id
        # 节点的邻居 {node_id, edge}
        self.adjs = {}
        # 前驱节点
        self.pred = self
        # 距离树根的距离,初始化为∞
        self.cost = INF
        # 在Dijkstra算法中是否变为黑色
        self.color = False
        # 从树根出发的下一跳
        self.next_hop = None
        # 出发的接口名字
        self.interface_name = None

class Adjacency():
    def __init__(self,src_ip,end_node_id,cost,src_mask = "255.255.255.0"):
        # 路由器接口的ip
        self.src_ip = src_ip
        # 路由器接口的mask
        self.src_mask = src_mask
        # 对面的node id
        self.end_node_id = end_node_id
        # cost
        self.cost = cost

def mask_to_length(mask):
    # 将掩码字符串拆分成四个部分
    parts = mask.split('.')
    # 将每个部分转换为二进制字符串并去掉前缀 '0b'
    binary_str = ''.join([bin(int(part)).lstrip('0b').zfill(8) for part in parts])
    # 计算二进制字符串中 '1' 的数量
    length = binary_str.count('1')
    return length

def calculate_network_address(ip_str, netmask_str):
    # 将IP地址和掩码转换为IPv4Address和IPv4Network对象
    ip = ipaddress.IPv4Address(ip_str)
    netmask = ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").netmask
    # 计算网络地址
    network_address = ipaddress.IPv4Address(int(ip) & int(netmask))
    return str(network_address)

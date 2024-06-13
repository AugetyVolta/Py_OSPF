from enum import Enum
from config import NetworkType,InterfaceState,InterfaceEvent
from ospf_neighbor.neighbor import Neighbor

class Interface():
    def __init__(self, ip, router, mask = "255.255.255.0", area_id = "0.0.0.0"):
        self.type = NetworkType.T_BROADCAST
        self.state = InterfaceState.S_Down
        
        # string, 使用ipaddress方法转
        self.ip = ip
        self.mask = mask
        self.area_id = area_id

        # hello报文间隔
        self.hello_interval = 10
        # 邻居存活时限
        self.router_dead_interval = 40
        # 发送LSU大致时间，单位是秒
        self.intf_trans_delay = 1
        # 向该接口的邻接重传LSA所间隔的秒数
        self.rxmt_interval = 5
        # 路由器优先级
        self.router_priority = 1

        # 初始的dr,bdr为0.0.0.0,表示不存在
        self.dr = "0.0.0.0"
        self.bdr = "0.0.0.0"

        # 从接口发送数据的输出值，在连接状态距离中表示。
        # 这一数值在 Router-LSA 中宣告为该接口的连接状态距离值。该数值必须大于 0。
        self.cost = 1
        self.mtu = 1500

        # 邻居列表字典{ip : neighbor}
        self.neighbors = {}

        # 接口所在router
        self.router = router

    def addNeighbor(self,ip):
        neighbor = Neighbor(ip,self)
        self.neighbors[ip] = neighbor
        return neighbor
    
    def getNeighbor(self,ip):
        if ip in self.neighbors.keys():
            return self.neighbors[ip]
        else:
            return None
        
    def disConfig(self):
        print(f'ip : {self.ip}')
        print(f'mask : {self.mask}')
        print(f'area_id : {self.area_id}')
        print(f'dr : {self.dr}')
        print(f'bdr : {self.bdr}')
        print(f'mtu : {self.mtu}')
        print(f'cost : {self.cost}')
        print(f"neighbors : {list(self.neighbors.keys())}")

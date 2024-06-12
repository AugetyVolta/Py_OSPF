from enum import Enum

"network type"
class NetworkType(Enum):
    T_P2P = 1,
    T_BROADCAST = 2,
    T_NBMA = 3,
    T_P2MP = 4,
    T_VIRTUAL = 5,

"interface states"
class InterfaceState(Enum):
    S_Down = 0,
    S_Loopback = 1,
    S_Waiting = 2,
    S_PointToPoint = 3,
    S_DROther = 4,
    S_Backup = 5,
    S_DR = 6

"interface events"
class InterfaceEvent(Enum):
    E_InterfaceUp = 0,
    E_WaitTimer = 1,
    E_BackupSeen = 2,
    E_NeighborChange = 3,
    E_LoopInd = 4,
    E_UnloopInd = 5,
    E_InterfaceDown = 6

class Interface():
    def __init__(self, ip, mask = "255.255.255.0", area_id = "0.0.0.0"):
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
    
    def addNeighbor(self,ip,neighbor):
        self.neighbors[ip] = neighbor
    
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

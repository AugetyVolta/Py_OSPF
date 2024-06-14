from config import NeighborState, NetworkType,InterfaceState,logger
from ospf_neighbor.neighbor import Neighbor
import ipaddress

class Interface():
    def __init__(self, ip, router, mask = "255.255.255.0", area_id = "0.0.0.0"):
        self.type = NetworkType.T_BROADCAST
        self.state = InterfaceState.S_Waiting
        
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

    def eventInterfaceUp(self):
        pass# TODO

    def eventWaitTimer(self):
        pass# TODO

    def eventBackupSeen(self):
        if self.state == InterfaceState.S_Waiting:
            # 选举DR,BDR
            self.selectDR_BDR()
            if self.ip == self.dr:
                logger.debug(f"\033[1;36mInterface {self.ip} Event BackupSeen State {self.state.name} --> {InterfaceState.S_DR.name}\033[0m")
                self.state = InterfaceState.S_DR
            elif self.ip == self.bdr:
                logger.debug(f"\033[1;36mInterface {self.ip} Event BackupSeen State {self.state.name} --> {InterfaceState.S_Backup.name}\033[0m")
                self.state = InterfaceState.S_Backup
            else:
                logger.debug(f"\033[1;36mInterface {self.ip} Event BackupSeen State {self.state.name} --> {InterfaceState.S_DROther.name}\033[0m")
                self.state = InterfaceState.S_DROther

        else:
            logger.debug(f"\033[1;36mInterface {self.ip} Event BackupSeen Pass\033[0m")
    
    def eventNeighborChange(self):
        if self.state == InterfaceState.S_DR or \
            self.state == InterfaceState.S_Backup or \
            self.state == InterfaceState.S_DROther:
            # 选举DR,BDR
            self.selectDR_BDR()
            if self.ip == self.dr:
                logger.debug(f"\033[1;36mInterface {self.ip} Event NeighborChange State {self.state.name} --> {InterfaceState.S_DR.name}\033[0m")
                self.state = InterfaceState.S_DR
            elif self.ip == self.bdr:
                logger.debug(f"\033[1;36mInterface {self.ip} Event NeighborChange State {self.state.name} --> {InterfaceState.S_Backup.name}\033[0m")
                self.state = InterfaceState.S_Backup
            else:
                logger.debug(f"\033[1;36mInterface {self.ip} Event NeighborChange State {self.state.name} --> {InterfaceState.S_DROther.name}\033[0m")
                self.state = InterfaceState.S_DROther

        else:
            logger.debug(f"\033[1;36mInterface {self.ip} Event NeighborChange Pass\033[0m")

    def InterfaceDown(self):
        pass

    def selectDR_BDR(self):
        final_dr = None
        final_bdr = None
        prev_dr = self.dr
        prev_bdr = self.bdr

        neighbor_list = []
        # 将自己加入列表中 
        my_self_neighbor = Neighbor(ip=self.ip,hostInter=self)
        my_self_neighbor.state = NeighborState.S_2Way # 必须得设置
        my_self_neighbor.id = self.router.router_id
        my_self_neighbor.priority = self.router_priority
        my_self_neighbor.ndr = self.dr
        my_self_neighbor.nbdr = self.bdr
        # 将自己加入列表中       
        neighbor_list.append(my_self_neighbor)
        
        # 可用的neighbor,状态>=2Way,且优先级不能为0
        for neighbor in self.neighbors.values():
            if neighbor.state.value >= NeighborState.S_2Way.value and neighbor.priority != 0:
                neighbor_list.append(neighbor)
            
        # (2)计算BDR
        for neighbor in neighbor_list:
            # 不宣告自己为DR的才开始选BDR
            if neighbor.ndr != neighbor.ip and neighbor.nbdr == neighbor.ip:
                if final_bdr == None:
                    final_bdr = neighbor
                elif neighbor.priority > final_bdr.priority or neighbor.priority == final_bdr.priority and \
                ipaddress.IPv4Address(neighbor.id) > ipaddress.IPv4Address(final_bdr.id):
                    final_bdr = neighbor
        
        # 如果没有宣告自己为bdr的, 选择最高优先级的成为BDR，如果相同，再根据router_id
        if final_bdr == None:
            for neighbor in neighbor_list:
                # 不宣告自己为DR的才开始选BDR
                if neighbor.ndr != neighbor.ip:
                    if final_bdr == None:
                        final_bdr = neighbor
                    elif neighbor.priority > final_bdr.priority or neighbor.priority == final_bdr.priority and \
                    ipaddress.IPv4Address(neighbor.id) > ipaddress.IPv4Address(final_bdr.id):
                        final_bdr = neighbor

        # (3)计算DR
        for neighbor in neighbor_list:
            # 宣告自己为DR
            if neighbor.ndr == neighbor.ip:
                if final_dr == None:
                    final_dr = neighbor
                elif neighbor.priority > final_dr.priority or neighbor.priority == final_dr.priority and \
                ipaddress.IPv4Address(neighbor.id) > ipaddress.IPv4Address(final_dr.id):
                    final_dr = neighbor
        
        # 如果没有路由器宣告自己为 DR，将新选举出的 BDR 设定为 DR
        if final_dr == None:
            final_dr = final_bdr
        
        # (4)如果路由器 X 新近成为 DR 或 BDR，或者不再成为 DR 或 BDR,重复2和3
        if (self.ip == self.dr) != (self.ip == final_dr.ip) or (self.ip == self.bdr) != (self.ip == final_bdr.ip):
            pass
            # TODO:重复选举
        
        # (5)设置接口的DR,BDR
        self.dr = final_dr.ip
        self.bdr = final_bdr.ip

        # (6)与Numba网络相关
        pass

        # (7)DR 或 BDR 的改变, 对所有达到至少 2-Way 状态的邻居调用事件 AdjOK
        if self.dr != prev_dr or self.bdr != prev_bdr:
            for neighbor in self.neighbors.values():
                if neighbor.state.value >= NeighborState.S_2Way.value:
                    neighbor.eventAdjOk()

        logger.debug(f"\033[1;36mselectDR_BDR new_DR {self.dr} new_BDR {self.bdr}\033[0m")
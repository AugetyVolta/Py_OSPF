import threading
from config import NetworkType,NeighborState,logger
from ospf_packet.packetManager import sendEmptyDDPackets

class Neighbor():
    def __init__(self,ip,hostInter):
        self.state = NeighborState.S_Down
        # 主从master/slave
        self.is_master = False
        
        # 当前被发往邻居的 DD 包序号
        self.dd_sequence_number = 0
        # 最近接收到的数据库描述包，
        # 从邻居最近接收到的 DD 包中的 DD 序号，以及初始（I）、更多（M）和主从（MS）位。用于判断从邻居接收到的下一个 DD 包是否重复
        self.last_dd_equence_number = 0 
        self.last_dd_flags = 0x00

        # 邻居信息
        self.id = ""
        self.priority = 1
        self.ip = ip
        self.ndr = "0.0.0.0" # 邻居认为的DR,里面是路由器的接口ip,不是router_id
        self.nbdr = "0.0.0.0" # 邻居认为的BDR,里面是路由器的接口ip,不是router_id

        # 邻居对面的interface,即本机的interface,两端的网络状况肯定是一样的
        self.hostInter = hostInter

        self.send_empty_dd_thread = None

        # 连接状态重传列表
        # TODO

    # 从邻居接收到一个 Hello 包
    def eventHelloReceived(self):
        if self.state == NeighborState.S_Down:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event HelloReceived State {self.state.name} --> {NeighborState.S_Init.name}\033[0m")
            self.state = NeighborState.S_Init
        # 这个只和Numba网络相关，因此忽略，也不会有状态转移到Attempt
        elif self.state == NeighborState.S_Attempt:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event HelloReceived State {self.state.name} --> {NeighborState.S_Init.name}\033[0m")
            self.state = NeighborState.S_Init
        elif self.state.value >= NeighborState.S_Init.value:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event HelloReceived Update timer\033[0m")
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event HelloReceived Pass\033[0m")

    # 两台邻居路由器之间达到双向通讯。这表明在邻居的 Hello 包中包含了路由器自身。
    def event2WayReceived(self):
        if self.state == NeighborState.S_Init:
            # 由点对点网络、点对多点网络和虚拟通道连接的路由器始终形成邻接。在广播网络和 NBMA 网络上，所有的路由器与 DR 和 BDR 形成邻接。
            # 这里需要根据情况判断是否邻接、路由器自身为指定路由器、路由器自身为备份指定路由器、邻居路由器为指定路由器、邻居路由器为备份指定路由器
            if self.hostInter.type == NetworkType.T_BROADCAST or self.hostInter.type == NetworkType.T_NBMA:
                # 注意这里的dr和bdr都是ip,一定要注意！
                if self.hostInter.ip != self.ndr and \
                self.hostInter.ip != self.nbdr and \
                self.ip != self.ndr and \
                self.ip != self.nbdr:
                    logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 2WayReceived State {self.state.name} --> {NeighborState.S_2Way.name}\033[0m")
                    self.state = NeighborState.S_2Way
                    return
                
            # 其他的默认
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 2WayReceived State {self.state.name} --> {NeighborState.S_Exstart.name}\033[0m")
            self.state = NeighborState.S_Exstart
            self.dd_sequence_number = 0
            self.is_master = True
            
            # 开始发空DD报文
            self.send_empty_dd_thread = threading.Thread(target=sendEmptyDDPackets,args=(self,))
            self.send_empty_dd_thread.start()
            # self.send_empty_dd_thread.join() 不能有这个, 否则主进程被阻塞了

        elif self.state.value >= NeighborState.S_2Way.value:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 2WayReceived Pass\033[0m")

    def event1WayReceived(self):
        if self.state.value >= NeighborState.S_2Way.value:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 1WayReceived State {self.state.name} --> {NeighborState.S_Init.name}\033[0m")
            self.state = NeighborState.S_Init
            # TODO 清除连接状态重传列表、数据库汇总列表和连接状态请求列表中的 LSA

        elif self.state == NeighborState.S_Init:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 1WayReceived Pass\033[0m")
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event 1WayReceived Pass\033[0m")
    
    # 决定是否需要与邻居建立/维持邻接关系。这将导致一些邻接的形成和拆除
    def eventAdjOk(self):
        if self.state == NeighborState.S_2Way:
            # 决定是否需要与邻居路由器形成邻接.如果不需要，邻居状态就保持在 2-Way.
            # 否则，邻居状态变为 ExStart, 并执行上面 Init 状态下.收到 2-WayReceived 事件时所执行的操作
            if self.hostInter.type == NetworkType.T_BROADCAST or self.hostInter.type == NetworkType.T_NBMA:
                if self.hostInter.ip != self.ndr and \
                self.hostInter.ip != self.nbdr and \
                self.ip != self.ndr and \
                self.ip != self.nbdr:
                    logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventAdjOk Keep 2Way\033[0m")
                    return
            
            # 可以建立连接
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventAdjOk State {self.state.name} --> {NeighborState.S_Exstart.name}\033[0m")
            self.state = NeighborState.S_Exstart
            self.dd_sequence_number = 0
            self.is_master = True
            
            # 开始发空DD报文
            self.send_empty_dd_thread = threading.Thread(target=sendEmptyDDPackets,args=(self,))
            self.send_empty_dd_thread.start()
        elif self.state.value >= NeighborState.S_Exstart.value:
            # 决定是否需要与邻居路由器继续保持邻接,如果是，就无须改变状态，且无须更多操作
            # 否则，邻接（可能仅部分建立）必须被拆除。邻居状态变为 2-Way,清除连接状态重传列表、数据库汇总列表和连接状态请求列表中的 LSA
            if self.hostInter.type == NetworkType.T_BROADCAST or self.hostInter.type == NetworkType.T_NBMA:
                if self.hostInter.ip != self.ndr and \
                self.hostInter.ip != self.nbdr and \
                self.ip != self.ndr and \
                self.ip != self.nbdr:
                    logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventAdjOk State {self.state.name} --> {NeighborState.S_2Way.name}\033[0m")
                    self.state = NeighborState.S_2Way
                    # TODO:清除连接状态重传列表、数据库汇总列表和连接状态请求列表中的 LSA
                    return
            # 保持连接
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventAdjOk Keep connected\033[0m")
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventAdjOk Pass\033[0m")
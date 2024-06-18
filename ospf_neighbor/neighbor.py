import threading
from config import MaxAge, NetworkType,NeighborState,logger
from ospf_packet.packet import OSPF_LSAHeader
from ospf_packet.packetManager import sendEmptyDDPackets

class Neighbor():
    def __init__(self,ip,hostInter):
        self.state = NeighborState.S_Down
        # 主从master/slave
        self.is_master = False
        # 强制接收标志
        self.recvAnyWay = False
        
        # 当前被发往邻居的 DD 包序号
        self.dd_sequence_number = 0
        # 最近接收到的数据库描述包，
        # 从邻居最近接收到的 DD 包中的 DD 序号，以及初始（I）、更多（M）和主从（MS）位。用于判断从邻居接收到的下一个 DD 包是否重复,以及包的选项域
        self.last_dd_sequence_number = 0 
        self.last_dd_flags = 0x00
        self.last_dd_options = 0x00
        # 发给neifgbor的上一个DD报文
        self.last_send_dd_packet = None

        # 邻居信息
        self.id = ""
        self.priority = 1
        self.ip = ip
        self.ndr = "0.0.0.0" # 邻居认为的DR,里面是路由器的接口ip,不是router_id
        self.nbdr = "0.0.0.0" # 邻居认为的BDR,里面是路由器的接口ip,不是router_id

        # 邻居对面的interface,即本机的interface,两端的网络状况肯定是一样的
        self.hostInter = hostInter

        self.send_dd_timers = {} # seq,send_dd_timer 邻居发送DD报文定时器

        # 连接状态重传列表，已经被洪泛，但还没有从邻接得到确认的 LSA 列表。将按间隔重发直至确认，或邻接消失
        self.link_state_retransmission_list = []
        # 数据库汇总列表，区域连接状态数据库中 LSA 的完整列表。在邻居进入数据库交换状态时，以 DD 包的形式向邻居发送此列表
        self.database_summary_list = []
        # 连接状态请求列表，需要从邻居接收，以同步两者之间连接状态数据库的 LSA 列表
        self.link_state_request_list = []
    
    # 初始化neighbor的数据库汇总列表
    def initDateBaseSummaryList(self):
        lock = self.hostInter.lsdb.lsa_lock
        lock.acquire()
        for lsa in self.hostInter.lsdb.LSAs:
            lsa_header = OSPF_LSAHeader(
                age = lsa.age,
                options = lsa.options,
                type = lsa.type,
                lsa_id = lsa.lsa_id,
                adv_router = lsa.adv_router,
                seq = lsa.seq,
                checksum = lsa.checksum,
                len = lsa.len 
            )
            # 时限等于MaxAge的LSA被改为加入邻居连接状态重传列表
            if lsa_header.age == MaxAge:
                pass
                # TODO:加入重传列表,还没想好如何处理
                self.link_state_retransmission_list.append(lsa_header)
            else:
                self.database_summary_list.append(lsa_header)
        lock.release()
        logger.debug(f"\033[1;32mNeighbor {self.id} Ip {self.ip} initDateBaseSummaryList\033[0m")
    
    # 处理LSAck中的确认
    def handleLsaAck(self,type,lsa_id,adv_router,Implicit = False):
        for lsa_header in self.link_state_retransmission_list:
            if lsa_header.type == type and lsa_header.lsa_id == lsa_id and \
            lsa_header.adv_router == adv_router:
                self.link_state_retransmission_list.remove(lsa_header)
                if Implicit:
                    logger.debug(f"\033[1;32mImplicit Ack for LSA Type {lsa_header.type} Lsa_id {lsa_header.lsa_id} Adv_router {lsa_header.router_id}\033[0m")
                else:
                    logger.debug(f"\033[1;32mRecieve Ack for LSA Type {lsa_header.type} Lsa_id {lsa_header.lsa_id} Adv_router {lsa_header.router_id}\033[0m")
                return
    
    # 查找重传表中是否有LSA
    def findLSAInRetransList(self,type,lsa_id,adv_router):
        for lsa_header in self.link_state_retransmission_list:
            if lsa_header.type == type and lsa_header.lsa_id == lsa_id and \
            lsa_header.adv_router == adv_router:
                return True
        return False
        
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
            # 设置邻居的序号
            self.dd_sequence_number = 114514
            self.is_master = False
            
            # 开始发空DD报文
            sendEmptyDDPackets(self)
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
            # 设置邻居的序号
            self.dd_sequence_number = 114514
            self.is_master = False
            
            # 开始发空DD报文
            sendEmptyDDPackets(self)
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
    
    # 已经协商好主从关系，并交换了DD序号。这一信号表示开始收发DD包
    def eventNegotiationDone(self):
        if self.state == NeighborState.S_Exstart:
            # 路由器必须列出在邻居数据库汇总列表中，所包含的的全部区域连接状态数据库。
            self.initDateBaseSummaryList()
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event NegotiationDone State {self.state.name} --> {NeighborState.S_Exchange.name}\033[0m")
            self.state = NeighborState.S_Exchange
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event NegotiationDone Pass\033[0m")

    def eventSeqNumberMismatch(self):
        if self.state.value >= NeighborState.S_Exchange.value:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event SeqNumberMismatch State {self.state.name} --> {NeighborState.S_Exstart.name}\033[0m")
            self.state = NeighborState.S_Exstart
            # TODO:清除连接状态重传列表、数据库汇总列表和连接状态请求列表中的 LSA

            # 设置邻居的序号
            self.dd_sequence_number = 114514
            self.is_master = False
            
            # 开始发空DD报文
            sendEmptyDDPackets(self)
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event SeqNumberMismatch Pass\033[0m")
    
    def evnetExchangeDone(self):
        if self.state == NeighborState.S_Exchange:
            # 如果邻居连接状态请求列表为空，则新的邻居状态为 Full
            if len(self.link_state_request_list) == 0:
                logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event evnetExchangeDone State {self.state.name} --> {NeighborState.S_Full.name}\033[0m")
                self.state = NeighborState.S_Full

                # 邻居路由器的状态达到 FULL 状态、或不再是FULL状态,生成Router_LSA
                self.hostInter.router.genRouterLSAs()
                # 此外，如果路由器是该网络的 DR 的话，还需要生成一个新的 Network-LSA
                if self.hostInter.ip == self.hostInter.dr:
                    self.hostInter.router.genNetworkLSAs(self.hostInter)
            # 开始发送LSR请求
            else:
                logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event evnetExchangeDone State {self.state.name} --> {NeighborState.S_Loading.name}\033[0m")
                self.state = NeighborState.S_Loading
                # TODO:发送LSR请求
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event evnetExchangeDone Pass\033[0m")

    def eventLoadingDone(self):
        if self.state == NeighborState.S_Loading:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventLoadingDone State {self.state.name} --> {NeighborState.S_Full.name}\033[0m")
            self.state = NeighborState.S_Full

            # 邻居路由器的状态达到 FULL 状态、或不再是FULL状态,生成Router_LSA
            self.hostInter.router.genRouterLSAs()
            # 此外，如果路由器是该网络的 DR 的话，还需要生成一个新的 Network-LSA
            if self.hostInter.ip == self.hostInter.dr:
                self.hostInter.router.genNetworkLSAs(self.hostInter)
        else:
            logger.debug(f"\033[1;36mNeighbor {self.id} Ip {self.ip} Event eventLoadingDone Pass\033[0m")

    def eventBadLSReq(self):
        pass
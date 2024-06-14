import ipaddress
from scapy.all import *
# from ospf_interface.interface import Interface
# from ospf_neighbor.neighbor import Neighbor
# from ospf_router.router import MyRouter
from config import Config,NeighborState,InterfaceState,logger
from ospf_packet.packet import OSPF_Header,OSPF_Hello,OSPF_DD,OSPF_LSR,OSPF_LSU,OSPF_LSAck

def sendHelloPackets(router, interface):
    timer = 0 # 使用这个可以快一点终止线程
    while True and not Config.is_stop:
        if timer == 0:
            ospf_header = OSPF_Header(
                version = 2,
                type = 1,  # Hello 包
                router_id = router.router_id,
                area_id = interface.area_id,
                autype = 0,
                auth = 0
            )
            hello_packet = OSPF_Hello(
                network_mask = interface.mask,
                hello_interval = interface.hello_interval,
                options = 0x02,
                router_priority = interface.router_priority,
                router_dead_interval = interface.router_dead_interval,
                designated_router = interface.dr,
                backup_designated_router = interface.bdr,
                neighbors = list(interface.neighbors.keys())
            )

            hello_packet = IP(src=interface.ip, dst="224.0.0.5", ttl=1) / ospf_header / hello_packet
            send(hello_packet, verbose=False)

            logger.debug("\033[1;32mSendHelloPacket: send success!\033[0m")

        timer = (timer + 1) % interface.hello_interval
        time.sleep(1)

def sendEmptyDDPackets(neighbor):
    if neighbor.state != NeighborState.S_Exstart:
        return
    interface = neighbor.hostInter
    ospf_header = OSPF_Header(
        version = 2,
        type = 2,  # DD 包
        router_id = interface.router.router_id,
        area_id = interface.area_id,
        autype = 0,
        auth = 0
    )
    dd_packet = OSPF_DD(
        mtu=interface.mtu,
        options=0x02,
        flags=0x07, # I,M,MS
        dd_sequence=neighbor.dd_sequence_number,
        lsa_headers=[]
    )      
    dd_packet = IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / dd_packet
    # 保存上一次发送的DD报文
    neighbor.last_send_dd_packet = dd_packet
    send(dd_packet, verbose=False)
    logger.debug(f"\033[1;32mSendEmptyDDPacket Seq {neighbor.dd_sequence_number}: send success!\033[0m")

    # 检查定时器是否存在，如果存在则取消
    if dd_packet.dd_sequence in neighbor.send_dd_timers:
        neighbor.send_dd_timers[dd_packet.dd_sequence].cancel()
    
    # 创建新的定时器
    timer = threading.Timer(interface.rxmt_interval,sendEmptyDDPackets,(neighbor,))
    neighbor.send_dd_timers[dd_packet.dd_sequence] = timer
    timer.start()

def sendDDPackets(interface,neighbor,dd_packet):
    send(dd_packet, verbose=False)
    logger.debug(f"\033[1;32mSendDDPacket Seq {dd_packet.dd_sequence}\033[0m")
    if Config.is_debug:
        dd_packet.show()

    # 检查定时器是否存在，如果存在则取消
    if dd_packet.dd_sequence in neighbor.send_dd_timers:
        neighbor.send_dd_timers[dd_packet.dd_sequence].cancel()
    
    # 创建新的定时器
    timer = threading.Timer(interface.rxmt_interval,sendDDPackets,(interface,neighbor,dd_packet))
    neighbor.send_dd_timers[dd_packet.dd_sequence] = timer
    timer.start()

    
def handleRecvDDPackets(neighbor,dd_packet):
    # 处理DD报文
    pass
    # 回复收到的DD报文
    # Master
    if neighbor.is_master == False:
        # 将邻居数据结构中的DD序号加一
        neighbor.dd_sequence_number += 1

    # Slaver
    elif neighbor.is_master == True:
        # 将接收包中的 DD 序号设定为邻居数据结构中的 DD 序列号
        neighbor.dd_sequence_number = dd_packet.dd_sequence


def handle_ospf_packets(packet, router, interface):
    ip_packet = packet[IP]
    src_ip, dst_ip = ip_packet.src, ip_packet.dst

    # 不处理自己发出的,不处理目标不是自己也不是广播的包
    if src_ip == interface.ip or dst_ip != interface.ip and dst_ip != '224.0.0.5':
        return
    logger.debug("\033[1;32mRecvPackets: recv one packet\033[0m")
    logger.debug(f'src : {src_ip}, dst : {dst_ip}')
    # Hello
    if OSPF_Header in packet and packet[OSPF_Header].type == 1:
        ospf_header = packet[OSPF_Header]
        hello_packet = packet[OSPF_Hello] 

        logger.debug("\033[1;36mReceived OSPF Hello Packet:\033[0m")
        logger.debug(f"Network Mask: {hello_packet.network_mask}")
        logger.debug(f"Hello Interval: {hello_packet.hello_interval}")
        logger.debug(f"Options: {hello_packet.options}")
        logger.debug(f"Router Priority: {hello_packet.router_priority}")
        logger.debug(f"Router Dead Interval: {hello_packet.router_dead_interval}")
        logger.debug(f"Designated Router: {hello_packet.designated_router}")
        logger.debug(f"Backup Designated Router: {hello_packet.backup_designated_router}")
        logger.debug(f"Neighbors: {hello_packet.neighbors}")

        neighbor = interface.getNeighbor(src_ip)    
        if neighbor == None:
            neighbor = interface.addNeighbor(src_ip)
        # 邻居之前的DR, BDR, priority
        prev_dr = neighbor.ndr
        prev_bdr = neighbor.nbdr
        prev_priority = neighbor.priority

        # 设置新的参数
        neighbor.id = ospf_header.router_id
        neighbor.priority = hello_packet.router_priority
        neighbor.ndr = hello_packet.designated_router
        neighbor.nbdr = hello_packet.backup_designated_router

        # neighbor执行helloRecieved
        neighbor.eventHelloReceived()
        # 检查 Hello 包中的邻居列表。如果路由器自身出现在列表中，邻居状态机执行事件 2-WayReceived。否则，邻居状态机执行事件 1-WayReceived，并终止包处理过程
        if router.router_id in hello_packet.neighbors:
            neighbor.event2WayReceived()
        else:
            neighbor.event1WayReceived()
            return # 终止包处理过程
        
        # priority change
        if prev_priority != neighbor.priority:
            interface.eventNeighborChange()

        # DR
        if neighbor.ndr == neighbor.ip and \
        neighbor.nbdr == "0.0.0.0" and \
        interface.state == InterfaceState.S_Waiting:
            interface.eventBackupSeen()
        elif (prev_dr == neighbor.ip) != (neighbor.ndr == neighbor.ip): 
            interface.eventNeighborChange()

        # BDR
        if neighbor.nbdr == neighbor.ip and \
        interface.state == InterfaceState.S_Waiting:
            interface.eventBackupSeen()
        elif (prev_bdr == neighbor.ip) != (neighbor.nbdr == neighbor.ip):
            interface.eventNeighborChange()
    # DD
    elif OSPF_Header in packet and packet[OSPF_Header].type == 2:
        ospf_header = packet[OSPF_Header]
        dd_packet = packet[OSPF_DD]
        neighbor = interface.getNeighbor(src_ip)
        is_dup = False # 是否是重复的DD

        logger.debug("\033[1;36mReceived OSPF DD Packet:\033[0m")
        logger.debug(f"MTU: {dd_packet.mtu}")
        logger.debug(f"Options: {dd_packet.options}")
        logger.debug(f"Flags: {dd_packet.flags}")
        logger.debug(f"DD Sequence: {dd_packet.dd_sequence}")
        logger.debug(f"LSA Headers Num: {len(dd_packet.lsa_headers)}")
        if Config.is_debug:
            for lsa_header in dd_packet.lsa_headers:
                lsa_header.show()
        
        if neighbor.last_dd_sequence_number == dd_packet.dd_sequence and \
            neighbor.last_dd_flags == dd_packet.flags:
            logger.debug("\033[1;31mDuplicated OSPF DD Packet\033[0m")
            is_dup = True
        else:
            neighbor.last_dd_sequence_number = dd_packet.dd_sequence
            neighbor.last_dd_flags = dd_packet.flags
        
        while True:
            # DD包中表示IP包大小的接口MTU域,大于该路由器接口所能接收的不分片大小,拒绝该DD包
            if dd_packet.mtu > interface.mtu:
                logger.debug("\033[1;31mOSPF DD Mtu bigger than interface\033[0m")
                return
            # Down,Attempt
            if neighbor.state == NeighborState.S_Down or neighbor.state == NeighborState.S_Attempt:
                logger.debug("\033[1;31mOSPF DD Packet Rejected\033[0m")
                return
            # Init
            elif neighbor.state == NeighborState.S_Init:
                neighbor.event2WayReceived()
                # 回到开始继续处理包
                continue
            # 2Way
            elif neighbor.state == NeighborState.S_2Way:
                logger.debug("\033[1;31mOSPF DD Packet Ignored\033[0m")
                return
            # Exstart
            elif neighbor.state == NeighborState.S_Exstart:
                # 记录包的选项域
                neighbor.last_dd_options = dd_packet.options

                # # 序号正确，不管它了
                # if neighbor.is_master == False and dd_packet.dd_sequence == neighbor.dd_sequence_number or \
                #         neighbor.is_master == True and dd_packet.dd_sequence == neighbor.dd_sequence_number+1:
                    
                # 设定了初始（I）、更多（M）和主从（MS）选项位，包的其他部分为空，且邻居路由器标识比自身路由器标识要大
                if dd_packet.flags == 0x07 and ipaddress.IPv4Address(neighbor.id) > ipaddress.IPv4Address(router.router_id):
                    # 处理EmptyDD报文的发送Timer, 删除最初的DD报文的seq num对应关系
                    neighbor.send_dd_timers[dd_packet.dd_sequence] = neighbor.send_dd_timers[neighbor.dd_sequence_number]
                    neighbor.send_dd_timers.pop(neighbor.dd_sequence_number,None)
                    # 设置对面为master,需要根据对面设置seq num
                    neighbor.is_master = True
                    neighbor.dd_sequence_number = dd_packet.dd_sequence
                    # 需要特殊处理,保证continue之后处理正确,进入正确接收的地方
                    dd_packet.dd_sequence += 1
                    dd_packet.flags = 0x03 # 设置为More, Master
                    logger.debug(f"\033[1;36mNeighbor {neighbor.id} is Master\033[0m")
                    # 满足条件,邻居状态机执行 NegotiationDone
                    neighbor.eventNegotiationDone()
                    # 开始处理发送DD报文,即将对方设置为Master后自己发,对应RT1的exchange
                    continue
                # 清除了初始（I）和主从（MS）选项位，且包中的 DD 序号等于邻居数据结构中的 DD 序号（标明为确认），而且邻居路由器标识比自身路由器标识要小
                elif (dd_packet.flags&0x05) == 0x00 and dd_packet.dd_sequence == neighbor.dd_sequence_number and ipaddress.IPv4Address(neighbor.id) < ipaddress.IPv4Address(router.router_id):
                    # 设置自己为master
                    neighbor.is_master = False
                    logger.debug(f"\033[1;36mNeighbor {neighbor.id} is Slaver\033[0m")
                    # 满足条件,邻居状态机执行 NegotiationDone
                    neighbor.eventNegotiationDone()
                    continue # 此时无论LSA_Headers里面有无东西,都需要处理,对应RT2的exchange,可能还要接着发
                else:        
                    logger.debug("\033[1;31mOSPF DD Packet Ignored\033[0m")
                    return
            # Exchange
            elif neighbor.state == NeighborState.S_Exchange:
                # 从机收到重复的 DD 包时，则应当重发前一个 DD 包
                if is_dup:
                    if neighbor.is_master:
                        if neighbor.last_send_dd_packet != None:
                            send(neighbor.last_send_dd_packet, verbose=False)
                            logger.debug("\033[1;32mRetransmit Last DD Packet\033[0m")
                        return
                else:
                    # 如果主从（MS）位的状态与当前的主从关系不匹配
                    # 如果意外设定了初始（I）位
                    # 如果包的选项域与以前接收到的 OSPF 可选项不同
                    if neighbor.is_master == True and (dd_packet.flags & 0x01) != 0x01 or \
                        neighbor.is_master == False and (dd_packet.flags & 0x01) == 0x01 or\
                        (dd_packet.flags & 0x04) == 0x04 or \
                        neighbor.last_dd_options != dd_packet.options:
                        neighbor.eventSeqNumberMismatch()
                        return
                    
                    # 包序号正常,正常处理
                    if neighbor.is_master == False and dd_packet.dd_sequence == neighbor.dd_sequence_number or \
                        neighbor.is_master == True and dd_packet.dd_sequence == neighbor.dd_sequence_number+1:
                        # 设置发送的DD报文状态为接收,Master和Slave的处理是一致的
                        neighbor.send_dd_timers[neighbor.dd_sequence_number].cancel()
                        logger.debug(f"\033[1;32mRecieve Reply for DD Packet Seq {neighbor.dd_sequence_number}\033[0m")    
                        # 处理dd报文并回复
                        handleRecvDDPackets(neighbor,dd_packet)
                        logger.debug(f"\033[1;32mRecieve handlable DD Packet Seq {dd_packet.dd_sequence}\033[0m")
                    else:
                        neighbor.eventSeqNumberMismatch()
                        return

            # Loading,Full
            elif neighbor.state == NeighborState.S_Loading or neighbor.state == NeighborState.S_Full:
                if (dd_packet.flags & 0x04) == 0x04 or neighbor.last_dd_options != dd_packet.options:
                    neighbor.eventSeqNumberMismatch()
                    return
                # 从机重发前一个DD包
                if is_dup and neighbor.is_master:
                    if neighbor.last_send_dd_packet != None:
                        send(neighbor.last_send_dd_packet, verbose=False)
                        logger.debug("\033[1;32mRetransmit Last DD Packet\033[0m")
            # 跳出循环
            break
    # LSR
    elif OSPF_Header in packet and packet[OSPF_Header].type == 3:
        pass
        


def recvPackets(router, interface):
    while not Config.is_stop:
        sniff(filter="ip proto 89", prn=lambda packet: handle_ospf_packets(packet, router, interface), timeout=1)

# 绑定 IP 层和 OSPF 层
bind_layers(IP, OSPF_Header, proto=89)
# 绑定 OSPF 层和 OSPF Hello 层
bind_layers(OSPF_Header, OSPF_Hello, type=1)
# 绑定 OSPF 层和 OSPF DD 描述符层
bind_layers(OSPF_Header, OSPF_DD, type=2)
# 绑定 OSPF 层和 OSPF LSR 描述符层
bind_layers(OSPF_Header, OSPF_LSR, type=3)
# 绑定 OSPF 层和 OSPF LSR 描述符层
bind_layers(OSPF_Header, OSPF_LSU, type=4)
# 绑定 OSPF 层和 OSPF LSR 描述符层
bind_layers(OSPF_Header, OSPF_LSAck, type=5)


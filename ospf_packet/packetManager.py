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
    timer = 0
    interface = neighbor.hostInter
    while True and not Config.is_stop:
        if neighbor.state != NeighborState.S_Exstart:
            break 
        if timer == 0:
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
            send(dd_packet, verbose=False)
            
            logger.debug("\033[1;32mSendEmptyDDPacket: send success!\033[0m")

        timer = (timer + 1) % interface.rxmt_interval
        time.sleep(1)


def handle_ospf_packets(packet, router, interface):
    ip_packet = packet[IP]
    src_ip, dst_ip = ip_packet.src, ip_packet.dst

    # 不处理自己发出的,不处理目标不是自己也不是广播的包
    if src_ip == interface.ip or dst_ip != interface.ip and dst_ip != '224.0.0.5':
        return
    logger.debug("\033[1;32mrecvPackets: recv one packet\033[0m")
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


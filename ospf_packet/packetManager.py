import ipaddress
from scapy.all import *
# from ospf_interface.interface import Interface
# from ospf_neighbor.neighbor import Neighbor
# from ospf_router.router import MyRouter
from config import Config, MaxAge,NeighborState,InterfaceState,logger
from ospf_packet.packet import OSPF_Header,OSPF_Hello,OSPF_DD,OSPF_LSR,OSPF_LSU, OSPF_LSAHeader,OSPF_LSAck, OSPF_LSR_Item

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
                neighbors = [neighbor.id for neighbor in interface.neighbors.values()] # 注意，是邻居的router id # list(interface.neighbors.keys())
            )
            eth = Ether()
            hello_packet = eth / IP(src=interface.ip, dst="224.0.0.5", ttl=1) / ospf_header / hello_packet
            sendp(hello_packet, verbose=False, iface=interface.ethname)

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
    eth = Ether()      
    dd_packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / dd_packet
    # 保存上一次发送的DD报文
    neighbor.last_send_dd_packet = dd_packet
    sendp(dd_packet, verbose=False, iface=interface.ethname)
    logger.debug(f"\033[1;32mSendEmptyDDPacket Seq {neighbor.dd_sequence_number}: send success!\033[0m")

    # 检查定时器是否存在，如果存在则取消
    if dd_packet.dd_sequence in neighbor.send_dd_timers:
        neighbor.send_dd_timers[dd_packet.dd_sequence].cancel()
    
    # 创建新的定时器
    timer = threading.Timer(interface.rxmt_interval,sendEmptyDDPackets,(neighbor,))
    neighbor.send_dd_timers[dd_packet.dd_sequence] = timer
    timer.start()

def sendLSRPackets(neighbor):
    if neighbor.state == NeighborState.S_Exchange or \
        neighbor.state == NeighborState.S_Loading:
        interface = neighbor.hostInter
        # 在exchange和loading状态才发LSR
        if len(neighbor.link_state_request_list) != 0: 
            ospf_header = OSPF_Header(
                version = 2,
                type = 3,  # LSR 包
                router_id = interface.router.router_id,
                area_id = interface.area_id,
                autype = 0,
                auth = 0
            )
            lsr_packet = OSPF_LSR()
            for req in neighbor.link_state_request_list:
                lsr_packet.lsa_requests.append(
                    OSPF_LSR_Item(
                        type = req.type,
                        lsa_id = req.lsa_id,
                        adv_router = req.adv_router
                    )
                )
            eth = Ether()
            lsr_packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / lsr_packet
            sendp(lsr_packet, verbose=False, iface=interface.ethname)
            logger.debug(f"\033[1;32mSendLSRPackets : send success!\033[0m")
            if Config.is_debug:
                lsr_packet.show()

        # 当邻居状态为 Loading 而连接状态请求列表为空时,生成LoadingDone事件
        elif neighbor.state == NeighborState.S_Loading:
            neighbor.eventLoadingDone()
            return
        
        # 检查定时器是否存在，如果存在则取消
        if neighbor.send_lsr_timer != None:
            neighbor.send_lsr_timer.cancel()

        # 创建新的定时器
        timer = threading.Timer(interface.rxmt_interval,sendLSRPackets,(neighbor,))
        neighbor.send_lsr_timer = timer
        timer.start()    


def sendDDPackets(interface,neighbor,dd_packet,need_retrans=True):
    # 保存发送的DD packet
    neighbor.last_send_dd_packet = dd_packet
    sendp(dd_packet, verbose=False, iface=interface.ethname)
    logger.debug(f"\033[1;32mSendDDPacket Seq {dd_packet.dd_sequence}\033[0m")
    if Config.is_debug:
        dd_packet.show()
    
    # 如果需要重传,默认是需要的
    if need_retrans:
        # 检查定时器是否存在，如果存在则取消
        if dd_packet.dd_sequence in neighbor.send_dd_timers:
            neighbor.send_dd_timers[dd_packet.dd_sequence].cancel()
        
        # 创建新的定时器
        timer = threading.Timer(interface.rxmt_interval,sendDDPackets,(interface,neighbor,dd_packet))
        neighbor.send_dd_timers[dd_packet.dd_sequence] = timer
        timer.start()

def sendDirectLSAck(interface,neighbor,lsa):
    ospf_header = OSPF_Header(
        version = 2,
        type = 5,  # LSAck 包
        router_id = interface.router.router_id,
        area_id = interface.area_id,
        autype = 0,
        auth = 0
    )
    direct_ack = OSPF_LSAck() 
    direct_ack.lsa_headers.append(
        OSPF_LSAHeader(
            age = lsa.age,
            options = lsa.options,
            type = lsa.type,
            lsa_id = lsa.lsa_id,
            adv_router = lsa.adv_router,
            seq = lsa.seq,
            checksum = lsa.checksum,
            len = lsa.len 
        )
    )
    eth = Ether() 
    packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / direct_ack
    sendp(packet, verbose=False, iface=interface.ethname)
    logger.debug(f"\033[1;32mSend Direct LSAck for LSA Type {lsa.type} LSA_id {lsa.lsa_id} Adv_router {lsa.adv_router}\033[0m")

def handleRecvDDPackets(neighbor,dd_packet):
    interface = neighbor.hostInter
    # 处理DD报文
    lsa_headers = dd_packet.lsa_headers
    for header in lsa_headers:
        # 如果 LS 类型为未知（即不是本规范所定义的 LS 类型 1-5）
        # 或者是一个AS-external-LSA（LS 类型 = 5）而邻居关联到一个存根区域，就生成 SeqNumberMismatch，并终止处理
        if not 1<=header.type<=5:
            neighbor.eventSeqNumberMismatch()
            return
        # 数据库中没有，或者数据库中的数据较旧
        lsa = interface.lsdb.getLSA(header.type,header.lsa_id,header.adv_router)
        if lsa == None:
            neighbor.link_state_request_list.append(header)
            logger.debug(f"\033[1;32mLSA Need Req Type {header.type} LSA_id {header.lsa_id} Adv_router {header.adv_router}\033[0m")
        elif header.is_newer(lsa):
            neighbor.link_state_request_list.append(header)
            logger.debug(f"\033[1;32mLSA Need update Type {header.type} LSA_id {header.lsa_id} Adv_router {header.adv_router}\033[0m")

    # 回复收到的DD报文
    # Master
    if neighbor.is_master == False:
        # 将邻居数据结构中的DD序号加一
        neighbor.dd_sequence_number += 1
        # 发送了全部的DD,并且收到了清除M位的包
        # 这个和作为Slaver的不同,但是但是可以正确处理交换结束后从机发来的最后一个DD报文
        # 此时所有的DD报文都被接收了
        if len(neighbor.database_summary_list) == 0 and (dd_packet.flags & 0x02) == 0x00:
            neighbor.evnetExchangeDone()
            return
        if Config.is_debug:
            print(f"\033[1;32mCurrent Database Summary List\033[0m")
            print(neighbor.database_summary_list)
        # 否则发送DD报文
        # 每次最多发送5个LSA Header报文
        ospf_header = OSPF_Header(
            version = 2,
            type = 2,  # DD 包
            router_id = interface.router.router_id,
            area_id = interface.area_id,
            autype = 0,
            auth = 0
        )
        dd = OSPF_DD(
            mtu=interface.mtu,
            options=0x02,
            flags=0x03, # I,M,MS,默认是M,MS
            dd_sequence=neighbor.dd_sequence_number,
            lsa_headers=[]
        )
        # DD报文最多携带5 LSA_Header
        lsa_cnt = 0
        while len(neighbor.database_summary_list) > 0 and lsa_cnt < 5:
            dd.lsa_headers.append(neighbor.database_summary_list.pop())
            lsa_cnt += 1
        # 取消M标志位
        if len(neighbor.database_summary_list) == 0:
            dd.flags = 0x01
        # 发送DD报文,并保存,需要重传
        eth = Ether()
        packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / dd
        neighbor.last_send_dd_packet = packet
        sendDDPackets(interface,neighbor,packet)

    # Slaver,不需要设置重传,只需在收到重复DD包时重新传送上一个DD包
    elif neighbor.is_master == True:
        # 将接收包中的 DD 序号设定为邻居数据结构中的 DD 序列号
        neighbor.dd_sequence_number = dd_packet.dd_sequence
        # 每次最多发送5个LSA Header报文
        ospf_header = OSPF_Header(
            version = 2,
            type = 2,  # DD 包
            router_id = interface.router.router_id,
            area_id = interface.area_id,
            autype = 0,
            auth = 0
        )
        dd = OSPF_DD(
            mtu=interface.mtu,
            options=0x02,
            flags=0x02, # I,M,MS,默认是M
            dd_sequence=neighbor.dd_sequence_number,
            lsa_headers=[]
        )
        # DD报文最多携带5 LSA_Header
        lsa_cnt = 0
        while len(neighbor.database_summary_list) > 0 and lsa_cnt < 5:
            dd.lsa_headers.append(neighbor.database_summary_list.pop())
            lsa_cnt += 1
        # 取消M标志位
        if len(neighbor.database_summary_list) == 0:
            dd.flags = 0x00
        # 发送DD报文,并保存,不设置重传
        eth = Ether()
        packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / dd
        neighbor.last_send_dd_packet = packet
        sendDDPackets(interface,neighbor,packet,need_retrans=False)
        # 发送了全部的DD,并且收到了清除M位的包,这个顺序和主机不同,因为主机需要处理最后一个DD从机DD报文的接收
        # 从机始终比主机早生成这一事件
        if len(neighbor.database_summary_list) == 0 and (dd_packet.flags & 0x02) == 0x00:
            neighbor.evnetExchangeDone()

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
                logger.debug("\033[1;31mOSPF DD Packet Ignored 2Way\033[0m")
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
                    neighbor.recvAnyWay = True
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
                    logger.debug("\033[1;31mOSPF DD Packet Ignored ExStart\033[0m")
                    return
            # Exchange
            elif neighbor.state == NeighborState.S_Exchange:
                # 从机收到重复的 DD 包时，则应当重发前一个 DD 包
                if is_dup and not neighbor.recvAnyWay: # 必须加这个,不能因为重复导致了问题,Dup是在所有的包处理之前判断的,因此不知道是否包被有效处理
                    if neighbor.is_master:
                        if neighbor.last_send_dd_packet != None:
                            sendp(neighbor.last_send_dd_packet, verbose=False, iface=interface.ethname)
                            logger.debug("\033[1;32mRetransmit Last DD Packet\033[0m")
                        return
                else:
                    if neighbor.recvAnyWay:
                        # 设置发送的DD报文状态为接收,Master和Slave的处理是一致的
                        neighbor.send_dd_timers[neighbor.dd_sequence_number].cancel()
                        logger.debug(f"\033[1;32mRecieve Reply for DD Packet Seq {neighbor.dd_sequence_number}\033[0m")
                        # 处理dd报文并回复
                        handleRecvDDPackets(neighbor,dd_packet)
                        return
                    
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
                        logger.debug(f"\033[1;32mRecieve handlable DD Packet Seq {dd_packet.dd_sequence}\033[0m")
                        handleRecvDDPackets(neighbor,dd_packet)
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
                        sendp(neighbor.last_send_dd_packet, verbose=False, iface=interface.ethname)
                        logger.debug("\033[1;32mRetransmit Last DD Packet\033[0m")
            # 跳出循环
            break
    # LSR
    elif OSPF_Header in packet and packet[OSPF_Header].type == 3:
        ospf_header = packet[OSPF_Header]
        lsr_packet = packet[OSPF_LSR]
        neighbor = interface.getNeighbor(src_ip)

        logger.debug("\033[1;36mReceived OSPF LSR Packet:\033[0m")
        logger.debug(f"Num of LSA Requests: {len(lsr_packet.lsa_requests)}")
        if Config.is_debug:
            for lsr_item in lsr_packet.lsa_requests:
                lsr_item.show()
        # 在邻居状态为Exchange、Loading 或 Full时，应当接收 LSR 包
        if neighbor.state.value >= NeighborState.S_Exchange.value:
            lsdb = interface.lsdb
            ospf_header = OSPF_Header(
                version = 2,
                type = 4,  # LSU 包
                router_id = interface.router.router_id,
                area_id = interface.area_id,
                autype = 0,
                auth = 0
            )
            lsu_packet = OSPF_LSU(
                num_lsa = 0,
                lsa_list = []  
            )
            for lsr_item in lsr_packet.lsa_requests:
                lsa = lsdb.getLSA(lsr_item.type,lsr_item.lsa_id,lsr_item.adv_router)
                # 如果某个LSA没有在数据库中被找到, 生成BadLSReq
                if lsa == None:
                    neighbor.eventBadLSReq()
                else:
                    lsu_packet.lsa_list.append(lsa)
                    lsu_packet.num_lsa += 1
            eth = Ether()
            packet = eth / IP(src=interface.ip, dst=neighbor.ip, ttl=1) / ospf_header / lsu_packet
            logger.debug(f"\033[1;32mReply to LSR, Send LSU Packet\033[0m")
            if Config.is_debug:
                packet.show()
            sendp(packet, verbose=False, iface=interface.ethname)
        else:
            logger.debug("\033[1;36OSPF LSR Packet Ignored\033[0m")

    # LSU
    elif OSPF_Header in packet and packet[OSPF_Header].type == 4:
        ospf_header = packet[OSPF_Header]
        lsu_packet = packet[OSPF_LSU]
        neighbor = interface.getNeighbor(src_ip)

        logger.debug("\033[1;36mReceived OSPF LSU Packet:\033[0m")
        logger.debug(f"Num of LSA: {lsu_packet.num_lsa}")
        if Config.is_debug:
            for lsa in lsu_packet.lsa_list:
                lsa.show()
        # 连接状态数据库
        lsdb = interface.lsdb
        # 洪泛LSU
        lsu_header = OSPF_Header(
            version = 2,
            type = 4,  # LSU 包
            router_id = interface.router.router_id,
            area_id = interface.area_id,
            autype = 0,
            auth = 0
        )
        send_lsu_packet = OSPF_LSU(
            num_lsa = 0,
            lsa_list = []  
        )
        # LSAck包
        eth = Ether() 
        lsack_header = OSPF_Header(
            version = 2,
            type = 5,  # LSAck 包
            router_id = interface.router.router_id,
            area_id = interface.area_id,
            autype = 0,
            auth = 0
        )
        # 延迟LSAck回复
        ls_ack = OSPF_LSAck()
        for lsa in lsu_packet.lsa_list:
            # 错误判断
            # (1) 确认LSA的LS校验和,错误丢弃
            if calculate_Fletcher_checksum(raw(lsa)[2:],15) != 0:
                logger.debug("\033[1;31mLSA CheckSum Error\033[0m")
                if Config.is_debug:
                    lsa.show()
                continue
            # (2) 检查 LSA 的 LS 类型。如果 LS 类型为未知，丢弃该 LSA
            if not 1<= lsa.type <= 5:
                logger.debug("\033[1;31mLSA Unknown Type\033[0m")
                if Config.is_debug:
                    lsa.show()
                continue
            # (3)AS-external-LSA,暂时不管
            pass
            # (4) TODO 如果 LSA 的 LS 时限等于 MaxAge，而且路由器的连接状态数据库中没有该LSA的实例，而且路由器的邻居都不处于Exchange或Loading状态
            if lsa.age == MaxAge and lsdb.getLSA(lsa.type,lsa.lsa_id,lsa.adv_router) == None and\
                neighbor.state != NeighborState.S_Exchange and neighbor.state != NeighborState.S_Loading:
                # (a) 通过发送一个 LSAck 包到发送的邻居（见第 13.5 节）来确认收到该 LSA
                sendDirectLSAck(interface,neighbor,lsa)
                # (b) 丢弃该 LSA
                continue
            # 处理LSU中的LSA
            # 将收到的LSA从邻居请求列表中删除
            neighbor.delLSAInReqList(lsa.type,lsa.lsa_id,lsa.adv_router)
            # 将lsa加入到LSU中
            send_lsu_packet.lsa_list.append(lsa)
            send_lsu_packet.num_lsa += 1
            # (5) 在路由器当前的连接状态数据库中查找该 LSA 的实例。如果没有找到数据库中的副本，或所接收的 LSA 比数据库副本新
            old_lsa = lsdb.getLSA(lsa.type,lsa.lsa_id,lsa.adv_router)
            if old_lsa == None or lsa.is_newer(old_lsa):
                # (a)
                # (b)
                # (c)将当前数据库中的副本，从所有的邻居连接状态重传列表中删除
                if old_lsa != None:
                    lsdb.delLSA(old_lsa)
                for n in interface.neighbors.values():
                    n.delLSAInInRetransList(lsa.type,lsa.lsa_id,lsa.adv_router)
                # (d)删除旧的LSA,添加新的LSA
                lsdb.addLSA(lsa)
                # (e) TODO 发送LSAck回复 
                ls_ack.lsa_headers.append(
                    OSPF_LSAHeader(
                        age = lsa.age,
                        options = lsa.options,
                        type = lsa.type,
                        lsa_id = lsa.lsa_id,
                        adv_router = lsa.adv_router,
                        seq = lsa.seq,
                        checksum = lsa.checksum,
                        len = lsa.len 
                    )
                )
                # (f) TODO 接收自生成的LSA 
                continue
            # (6) 如果该 LSA 的实例正在邻居的连接状态请求列表上，产生数据库交换过程的错误,感觉有问题
            pass
            # (7) 接收的 LSA 与数据库副本为同一实例（没有哪个较新）
            if not lsa.is_newer(old_lsa):
                # 如果 LSA 在所接收邻居的连接状态重传列表上，表示路由器自身正期待着这一LSA的确认。路由器可以将这一LSA作为确认，并将其从连接状态重传列表中去除
                if neighbor.findLSAInRetransList(lsa.type,lsa.lsa_id,lsa.adv_router):
                    # 作为确认, 从连接状态重传列表中去除, 隐式确认
                    neighbor.handleLsaAck(lsa.type,lsa.lsa_id,lsa.adv_router,Implicit = True)
                    # 发送延迟确认
                    ls_ack.lsa_headers.append(
                        OSPF_LSAHeader(
                            age = lsa.age,
                            options = lsa.options,
                            type = lsa.type,
                            lsa_id = lsa.lsa_id,
                            adv_router = lsa.adv_router,
                            seq = lsa.seq,
                            checksum = lsa.checksum,
                            len = lsa.len 
                        )
                    )
                # LSA 重复，但不被作为隐含确认, 发送直接确认
                else:
                    sendDirectLSAck(interface,neighbor,lsa)
                continue
            # (8)
        packet = eth / IP(src=interface.ip, dst="224.0.0.5", ttl=1) / lsack_header / ls_ack
        if Config.is_debug:
            packet.show2()
        sendp(packet, verbose=False, iface=interface.ethname)
        logger.debug(f"\033[1;32mSend LSAck\033[0m")
        # 洪泛转发,全部都转,有来的就转
        if lsu_packet.num_lsa != 0:
            for iface in router.interfaces.values():
                if iface.area_id == interface.area_id and iface != interface and iface.state.value > InterfaceState.S_Waiting.value:
                    # iface.state == InterfaceState.S_Backup or iface.state == InterfaceState.S_DROther : # or iface.state.value > InterfaceState.S_Waiting.value:
                    packet = eth / IP(src=iface.ip, dst="224.0.0.5", ttl=1) / lsu_header / send_lsu_packet
                    sendp(packet, verbose=False, iface=iface.ethname)

    # LSAck
    elif OSPF_Header in packet and packet[OSPF_Header].type == 5:
        ospf_header = packet[OSPF_Header]
        ls_ack = packet[OSPF_LSAck]
        neighbor = interface.getNeighbor(src_ip)

        logger.debug("\033[1;36mReceived OSPF LSAck Packet:\033[0m")
        logger.debug(f"Num of LSA Headers: {len(ls_ack.lsa_headers)}")
        if Config.is_debug:
            for lsa_header in ls_ack.lsa_headers:
                lsa_header.show()

        # 如果所关联的邻居状态小于 Exchange，则丢弃该 LSAck 包
        if neighbor.state.value < NeighborState.S_Exchange.value:
            logger.debug("\033[1;32mOSPF LSAck Packet Ignored\033[0m")
            return
        else:
            # 对于LSAck包中的每个确认, 检查是否在重传列表中, 如果在就删除
            for lsa_header in ls_ack.lsa_headers:
                neighbor.handleLsaAck(lsa_header.type,lsa_header.lsa_id,lsa_header.adv_router)

def recvPackets(router, interface):
    while not Config.is_stop:
        sniff(filter="ip proto 89", prn=lambda packet: handle_ospf_packets(packet, router, interface), timeout=1, iface=interface.ethname)

def calculate_Fletcher_checksum(bytes,n):
    C0 = 0
    C1 = 0
    L = len(bytes)
    # 处理每个八位字节
    for i in range(L):
        C0 = (C0 + bytes[i]) % 255
        C1 = (C1 + C0) % 255
        if C0 < 0:
            C0 += 255
        if C1 < 0:
            C1 += 255
    
    X = (-C1 + (L - n) * C0) % 255
    Y = (C1 - (L - n + 1) * C0) % 255

    # 如果 X 或 Y 为负数，调整为正数
    if X < 0:
        X += 255
    if Y < 0:
        Y += 255

    return (X << 8) | Y

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


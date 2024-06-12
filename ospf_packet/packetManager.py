from scapy.all import *
from ospf_interface.interface import Interface
from config import Config
from ospf_router.router import MyRouter
from ospf_packet.packet import OSPF_Header,OSPF_Hello,OSPF_DD,OSPF_LSR,OSPF_LSU,OSPF_LSAck

def sendHelloPackets(router : MyRouter, interface: Interface):
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

            hello_packet = IP(src=interface.ip, dst="224.0.0.5", ttl=1 ) / ospf_header / hello_packet
            send(hello_packet, verbose=False)

            if Config.is_debug:
                print("\033[1;32mSendHelloPacket: send success!\033[0m")

        timer = (timer + 1) % interface.hello_interval
        time.sleep(1)

def sendEmptyDDPackets():
    pass

def  recvPackets():
    pass


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


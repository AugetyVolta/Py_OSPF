from scapy.all import *
from scapy.compat import Any, Optional, Union
from scapy.fields import *
from scapy.packet import Packet
from packet import OSPF_Header,OSPF_Hello,OSPF_DD,OSPF_LSR,OSPF_LSU,OSPF_LSAck

def handle_ospf(packet):
    if OSPF_Header in packet and packet[OSPF_Header].type == 1:
        hello_packet = packet[OSPF_Hello]
        print("\033[1;36mReceived OSPF Hello Packet:\033[0m")
        print(f"Network Mask: {hello_packet.network_mask}")
        print(f"Hello Interval: {hello_packet.hello_interval}")
        print(f"Options: {hello_packet.options}")
        print(f"Router Priority: {hello_packet.router_priority}")
        print(f"Router Dead Interval: {hello_packet.router_dead_interval}")
        print(f"Designated Router: {hello_packet.designated_router}")
        print(f"Backup Designated Router: {hello_packet.backup_designated_router}")
        print(f"Neighbors: {hello_packet.neighbors}")

    elif OSPF_Header in packet and packet[OSPF_Header].type == 2:
        dd_packet = packet[OSPF_DD]
        print("\033[1;36mReceived OSPF DD Packet:\033[0m")
        print(f"MTU: {dd_packet.mtu}")
        print(f"Options: {dd_packet.options}")
        print(f"Flags: {dd_packet.flags}")
        print(f"DD Sequence: {dd_packet.dd_sequence}")
        print(f"LSA Headers: {dd_packet.lsa_headers}")
        for lsa_header in dd_packet.lsa_headers:
            lsa_header.show()

    elif OSPF_Header in packet and packet[OSPF_Header].type == 3:
        dd_packet = packet[OSPF_LSR]
        print("\033[1;36mReceived OSPF LSR Packet:\033[0m")
        print(f"LSA Requests: {dd_packet.lsa_requests}")
        for lsr_item in dd_packet.lsa_requests:
            lsr_item.show()

    elif OSPF_Header in packet and packet[OSPF_Header].type == 4:
        dd_packet = packet[OSPF_LSU]
        print("\033[1;36mReceived OSPF LSU Packet:\033[0m")

    elif OSPF_Header in packet and packet[OSPF_Header].type == 5:
        dd_packet = packet[OSPF_LSAck]
        print("\033[1;36mReceived OSPF LSAck Packet:\033[0m")
        print(f"LSA Headers: {dd_packet.lsa_headers}")
        for lsa_header in dd_packet.lsa_headers:
            lsa_header.show()


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


sniff(filter="ip proto 89", prn=handle_ospf)
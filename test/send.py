from scapy.all import *
from scapy.compat import Any, Optional, Union
from scapy.fields import *
from scapy.packet import Packet
from packet import OSPF_Header,OSPF_Hello,OSPF_LSAHeader,OSPF_DD

# 创建并发送 OSPF Hello 包
def create_ospf_hello():
    hello = OSPF_Hello(
        network_mask="255.255.255.0",
        hello_interval=10,
        options=0x02,
        router_priority=1,
        router_dead_interval=40,
        designated_router="192.168.60.3",
        backup_designated_router="0.0.0.0",
        neighbors=["9.9.9.9"]
    )
    
    ospf = OSPF_Header(
        version=2,
        type=1,  # Hello 包
        router_id="1.1.1.1",
        area_id="0.0.0.0",
        autype=0,
        auth=0
    )
    
    packet = IP(dst="224.0.0.5", src="192.168.60.3",ttl=1) / ospf / hello
    return packet

def create_ospf_dd():
    dd_packet = OSPF_DD(
        mtu=1500,
        options=0x02,
        flags=0x07,
        dd_sequence=0,
        lsa_headers=[
            OSPF_LSAHeader(
                age=10,
                options=0x02,
                type=1,
                lsa_id="192.168.1.1",
                adv_router="192.168.1.1",
                seq=100,
                checksum=0,
                length=24
            ),
            OSPF_LSAHeader(
                age=20,
                options=0x02,
                type=2,
                lsa_id="192.168.1.2",
                adv_router="192.168.1.2",
                seq=200,
                checksum=0,
                length=28
            )
        ]
    )
    
    ospf = OSPF_Header(
        version=2,
        type=2,  # DD 报文
        router_id="1.1.1.1",
        area_id="0.0.0.0",
        autype=0,
        auth=0
    )
    
    # 打印报文内容
    print("OSPF_DD 报文内容：")
    dd_packet.show()

    # 打印每个 LSAHeader 的字段值
    print("\n每个 LSAHeader 的字段值：")
    for lsa_header in dd_packet.lsa_headers:
        lsa_header.show()
    
    packet = IP(src="192.168.60.3", dst="192.168.60.4") / ospf / dd_packet
    return packet

# 绑定 IP 层和 OSPF 层
bind_layers(IP, OSPF_Header, proto=89)
# 绑定 OSPF 层和 OSPF Hello 层
bind_layers(OSPF_Header, OSPF_Hello, type=1)
# 绑定 OSPF 层和 OSPF DD 描述符层
bind_layers(OSPF_Header, OSPF_DD, type=2)

if __name__ == "__main__":
    functions = {
        "hello":create_ospf_hello,
        "dd":create_ospf_dd
    }

    fun = functions["hello"]
    packet = fun()
    send(packet)
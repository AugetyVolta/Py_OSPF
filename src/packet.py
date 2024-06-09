from scapy.all import *
from scapy.compat import Any, Optional, Union
from scapy.fields import *
from scapy.packet import Packet

class OSPF_Header(Packet):
    name = 'OSPF_Header'
    fields_desc = [
        ByteField("version", 2),
        ByteEnumField("type", 1, {1: "Hello", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Ack"}),
        ShortField("len", None),
        IPField("router_id", "0.0.0.0"),
        IPField("area_id", "0.0.0.0"),
        XShortField("checksum", None),
        ShortField("autype", 0),
        LongField("auth", 0),
    ]
    
    def post_build(self, p, pay):
        # 报文构建后添加负载
        p += pay
        # 计算并设置包的总长度
        if self.len is None:
            l = len(p)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        # 计算并设置校验和
        if self.checksum is None:
            ck = checksum(p)
            p = p[:12] + struct.pack("!H", ck) + p[14:]
        return p

class OSPF_Hello(Packet):
    name = "OSPF_Hello"
    fields_desc = [
        IPField("network_mask", "255.255.255.0"),
        ShortField("hello_interval", 10),
        ByteField("options", 0x02),
        ByteField("router_priority", 1),
        IntField("router_dead_interval", 40),
        IPField("designated_router", "0.0.0.0"),
        IPField("backup_designated_router", "0.0.0.0"),
        FieldListField("neighbors", [], IPField("", "0.0.0.0"), length_from=lambda pkt: (pkt.underlayer.len - 20))
    ]

class OSPF_LSAHeader(Packet):
    name = "OSPF_LSAHeader"
    fields_desc = [
        ShortField("age", 0),
        ByteField("options", 0x02),
        ByteField("type", 1),
        IPField("lsa_id", "0.0.0.0"),
        IPField("adv_router", "0.0.0.0"),
        IntField("seq", 0),
        XShortField("checksum", 0),
        ShortField("length", 0)
    ]

    # 需要重写函数, important!!!
    def extract_padding(self, s):
        return "", s
    
    def post_build(self, p, pay):
        pass
        # TODO 计算checksum

class OSPF_DD(Packet):
    name = 'OSPF_DD'
    fields_desc = [
        ShortField("mtu", 1500),
        ByteField("options", 0x02),
        ByteField("flags", 0x00),
        IntField("dd_sequence", 0),
        PacketListField("lsa_headers", [], OSPF_LSAHeader, length_from=lambda pkt: (pkt.underlayer.len - 8))
    ]

class OSPF_LSR_Item(Packet):
    name = 'OSPF_LSR_Item'
    fields_desc = [
        IntField("type", 1),
        IPField("lsa_id", "0.0.0.0"),
        IPField("adv_router", "0.0.0.0"),
    ]

    # 需要重写函数, important!!!
    def extract_padding(self, s):
        return "", s

class OSPF_LSR(Packet):
    name = 'OSPF_LSR'
    fields_desc = [
        PacketListField("lsa_requests", [], OSPF_LSR_Item)
    ]

class OSPF_LSU(Packet):
    name = 'OSPF_LSU'
    fields_desc = [
        
    ]

class OSPF_LSAck(Packet):
    name = 'OSPF_LSAck'
    fields_desc = [
        PacketListField("lsa_headers", [], OSPF_LSAHeader)
    ]

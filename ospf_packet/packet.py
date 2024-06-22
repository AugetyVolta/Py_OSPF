from scapy.all import *
from scapy.compat import Any, Optional, Union
from scapy.fields import *
from scapy.packet import Packet

from config import MaxAge, MaxAgeDiff

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
        XIntField("seq", 0),
        XShortField("checksum", 0),
        ShortField("len", 0)
    ]

    # 就默认type,lsa_id,adv_router一样了,在调用前判断了
    def is_newer(self,header):
        # 较大 LS 序号的 LSA 较新
        if self.seq > header.seq:
            return True
        # 否则, LS 校验和不同，具有较大校验和（按 16 位无符号整数）的实例较新
        if self.checksum > header.checksum:
            return True
        # 否则，如果其中一个实例的 LS 时限为 MaxAge
        if self.age == MaxAge:
            return True
        # 否则，如果两个实例 LS 时限的差异大于 MaxAgeDiff，较小时限（较近生成）的实例为较新
        if abs(self.age - header.age) > MaxAgeDiff and self.age < header.age:
            return True
        # 否则,认为相同,可以不用管
        return False

    # 需要重写函数, important!!!
    def extract_padding(self, s):
        return "", s
    
    # 不能写空的post_build

class OSPF_RouterLSA_Item(Packet):
    name = "OSPF_RouterLSA_Item"
    fields_desc = [
        IPField("link_id", "255.255.255.0"),
        IPField("link_data", "0.0.0.0"),
        ByteField("type",0),
        ByteField("tos",0),
        ShortField("metric", 0)
        # TODO: 还有一部分没有遇到先不实现
    ]

    def extract_padding(self, s):
        return "", s

class OSPF_RouterLSA(OSPF_LSAHeader):
    name = "OSPF_RouterLSA"
    fields_desc = OSPF_LSAHeader.fields_desc + [
        XByteField("flags", 0),
        ByteField("pad", 0),
        ShortField("links", 0),
        PacketListField("lsa_routers", [], OSPF_RouterLSA_Item, count_from=lambda pkt: pkt.links)
    ]

    def extract_padding(self, s):
        return "", s

class OSPF_NetworkLSA_Item(Packet):
    name = "OSPF_NetworkLSA_Item"
    fields_desc = [
        IPField("attached_router", "0.0.0.0")
    ]
    
    def extract_padding(self, s):
        return "", s

class OSPF_NetworkLSA(OSPF_LSAHeader):
    name = "OSPF_NetworkLSA"
    fields_desc = OSPF_LSAHeader.fields_desc + [
        IPField("network_mask", "255.255.255.0"),
        PacketListField("attached_routers", [], OSPF_NetworkLSA_Item, length_from=lambda pkt: (pkt.len - 24))
    ]

    def extract_padding(self, s):
        return "", s

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

def lsa_parser(pkt, lst, cur, s):
        lsa_type = s[3]
        if lsa_type == 1:
            return OSPF_RouterLSA
        elif lsa_type == 2:
            return OSPF_NetworkLSA
        else:
            return OSPF_LSAHeader
        
class OSPF_LSU(Packet):
    name = 'OSPF_LSU'
    fields_desc = [
        IntField("num_lsa", 0),
        PacketListField("lsa_list", [], OSPF_LSAHeader, count_from=lambda pkt: pkt.num_lsa, next_cls_cb=lsa_parser)
    ]

class OSPF_LSAck(Packet):
    name = 'OSPF_LSAck'
    fields_desc = [
        PacketListField("lsa_headers", [], OSPF_LSAHeader)
    ]

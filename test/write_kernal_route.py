from pyroute2 import IPRoute
import socket
import struct
import os

def num_to_mask(n):
    """将一个数字转换为网络掩码的点分十进制表示形式"""
    mask = (0xffffffff >> (32 - n)) << (32 - n)
    return socket.inet_ntoa(struct.pack(">I", mask))

class RouteItem:
    def __init__(self, dest, prefix_length, gateway):
        self.dest = dest
        self.mask = prefix_length
        self.gateway = gateway

class RouteTable:
    def __init__(self):
        self.routings = {}  # This should be a dictionary of RouteItem objects
        self.rtentries_written = []

    def resetRoute(self):
        for rtitem in self.rtentries_written:
            self.del_ipv4_route(rtitem)
        self.rtentries_written.clear()
        
    def add_ipv4_route(self, rtitem, interface_name = "ens33"):
        ip = IPRoute()
        try:
            ip.route("add",
                    dst=f"{rtitem.dest}/{rtitem.mask}",
                    gateway=rtitem.gateway,
                    oif=ip.link_lookup(ifname=interface_name)[0])
            self.rtentries_written.append(rtitem)
            print("IPv4 route added successfully")
        except Exception as e:
            print(f"Failed to add IPv4 route: {e}")
        finally:
            ip.close()

    def del_ipv4_route(self, rtitem, interface_name = "ens33"):
        ip = IPRoute()
        try:
            ip.route("del",
                    dst=f"{rtitem.dest}/{rtitem.mask}",
                    gateway=rtitem.gateway,
                    oif=ip.link_lookup(ifname=interface_name)[0])
            print("IPv4 route deleted successfully")
        except Exception as e:
            print(f"Failed to del IPv4 route: {e}")
        finally:
            ip.close()
    
    def writeKernelRoute(self):
        self.resetRoute()  # Remove the last OSPF writing to kernel route
        
        for rtitem in self.routings.values():
            self.add_ipv4_route(rtitem)

        print("Write kernel route successfully.")


if __name__ == '__main__':
    route_table = RouteTable()
    route_table.routings = {
        1: RouteItem("10.0.2.0", 24, "192.168.60.4"),
        2: RouteItem("10.0.1.0", 24, "192.168.60.4"),
        3: RouteItem("10.0.0.0", 24, "192.168.60.4")
    }
    route_table.writeKernelRoute()
    os.system("route")
    route_table.resetRoute()

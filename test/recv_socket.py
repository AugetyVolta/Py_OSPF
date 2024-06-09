import socket
import struct
"""
B unsigned char 1byte
H unsigned short 2byte
s char[]
"""

def cal_checksum(ip_header):
    ip_header_upacked =  struct.unpack("!10H", ip_header) #解析为10个2byte(16bit)
    checksum = 0
    for data in ip_header_upacked:
        checksum += data
        checksum = (checksum>>16) + (checksum & 0xFFFF)
    checksum = (~checksum) & 0xFFFF    
    print(f"calculate checkSum {checksum}")
    return checksum

def create_socket_and_receive():
    # 创建一个原始套接字
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # 绑定到特定的接口（替换为你自己的接口名称）
    interface_name = "ens33"
    sock.bind((interface_name, 0))

    while True:
        # 接收数据包
        packet = sock.recv(65535)  # 65535 是接收缓冲区大小
        print(f"Received packet: {len(packet)} bytes")

        # 解析以太网帧头部,14字节
        eth_header = packet[:14]
        # 6 char 6 char unsigned short(2 byte)
        eth_header_unpacked = struct.unpack("!6s6sH", eth_header)
        '''
        将网络字节序转换为主机字节序
        Network byte order: 0x0800
        Host byte order: 0x8
        '''
        eth_protocol = socket.ntohs(eth_header_unpacked[2])
        eth_protocol = eth_header_unpacked[2]
        
        print(f"Ethernet Protocol: {eth_protocol}")

        if eth_protocol == 0x0800:  # IPv4
            ip_header = packet[14:34]  # IP头部在以太网帧后，20字节
            ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)  
            protocol = ip_header_unpacked[6]
            # print(f"IP Protocol: {protocol}")
            
            # ip header中的checksum是发送方算的
            checksum = cal_checksum(ip_header)
            if checksum == 0:
                print("package is valid")
            else:
                print("package is invalid")

            if protocol == 89:  # OSPF
                print("Received an OSPF packet")
                break


if __name__ == "__main__":
    create_socket_and_receive()

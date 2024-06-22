import threading
from scapy.all import *
import signal
from test.recv import handle_ospf
from config import Config
from ospf_router.router import MyRouter
from ospf_packet.packetManager import sendHelloPackets,recvPackets 

global router

def signal_handler(sig, frame):
    Config.is_stop = True
    router.routing_table.resetRoute()
    print("Signal received, stopping threads...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    # 路由器
    router = MyRouter()

    # 每一个接口一个线程
    send_hello_threads = []
    recv_packet_threads = []

    # 生成并开启线程
    for _,interface in router.interfaces.items():
        send_hello = threading.Thread(target=sendHelloPackets,args=(router,interface))
        recv_packet = threading.Thread(target=recvPackets,args=(router,interface))

        send_hello_threads.append(send_hello)
        recv_packet_threads.append(recv_packet)
        
        send_hello.start()
        recv_packet.start()

    command_dicts = {
        "peer": "display ospf peer",
        "routing": "display ospf routing",
        "lsdb": "dis ospf lsdb",
        "exit": "terminal OSPF threads",
        "help": "help list"
    }

    while True:
        command = input()
        if command == 'peer':
            router.disConfig()
        elif command == 'routing':
            router.disRoutingTable()
        elif command == 'lsdb':
            router.disLsdb()
        elif command == 'exit':
            Config.is_stop = True
            router.routing_table.resetRoute()
            print("Signal received, stopping threads...")
            break
        elif command == 'help':
            for key in command_dicts.keys():
                print(f"{key} : {command_dicts[key]}")
        else:
            print("unknown command, please try command \033[33mhelp\033[0m for details")
        print()
import threading
from scapy.all import *
import signal
from test.recv import handle_ospf
from config import Config
from ospf_router.router import MyRouter
from ospf_packet.packetManager import sendHelloPackets 

def recvPackets():
    while not Config.is_stop:
        sniff(filter="ip proto 89", prn=handle_ospf, timeout=1)

def signal_handler(sig, frame):
    Config.is_stop = True
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
        recv_packet = threading.Thread(target=recvPackets)

        send_hello_threads.append(send_hello)
        recv_packet_threads.append(recv_packet)
        
        send_hello.start()
        recv_packet.start()

    command_dicts = {
        "dis ": "display this router config",
        "exit": "terminal OSPF threads",
        "help": "help list"
    }

    while True:
        command = input()
        if command == 'dis':
            router.disConfig()
        elif command == 'exit':
            Config.is_stop = True
            print("Signal received, stopping threads...")
            break
        elif command == 'help':
            for key in command_dicts.keys():
                print(f"{key} : {command_dicts[key]}")
        else:
            print("unknown command, please try command \033[33mhelp\033[0m for details")
        print()

    for thread in send_hello_threads:
        thread.join()
    for thread in recv_packet_threads:
        thread.join()
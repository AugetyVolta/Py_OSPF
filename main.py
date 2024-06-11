import threading
from scapy.all import *
import signal
from test.recv import handle_ospf
from test.send import create_ospf_hello
from ospf_router.router import MyRouter

stop_flag = False

def sendHello():
    timer = 0
    while not stop_flag:
        if timer%10 == 0:
            packet = create_ospf_hello()
            send(packet)
        timer += 1
        time.sleep(1)

def recvPackets():
    while not stop_flag:
        sniff(filter="ip proto 89", prn=handle_ospf, timeout=1)

def signal_handler(sig, frame):
    global stop_flag
    stop_flag = True
    print("Signal received, stopping threads...")
    sys.exit(0)

if __name__ == "__main__":
    router = MyRouter()

    recv_thread = threading.Thread(target=recvPackets)
    send_thread = threading.Thread(target=sendHello)

    recv_thread.start()
    send_thread.start()

    signal.signal(signal.SIGINT, signal_handler)
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
            stop_flag = True
            print("Signal received, stopping threads...")
            break
        elif command == 'help':
            for key in command_dicts.keys():
                print(f"{key} : {command_dicts[key]}")
        else:
            print("unknown command, please try command \033[33mhelp\033[0m for details")
        print()

    recv_thread.join()
    send_thread.join()
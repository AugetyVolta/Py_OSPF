import threading
from scapy.all import *
from recv import handle_ospf
from send import create_ospf_hello

def sendHello():
    while True:
        packet = create_ospf_hello()
        send(packet)
        time.sleep(10)

def recvPackets():
    sniff(filter="ip proto 89", prn=handle_ospf)

if __name__ == "__main__":
    
    recv_thread = threading.Thread(target=recvPackets)
    send_thread = threading.Thread(target=sendHello)

    recv_thread.start()
    send_thread.start()
    
    recv_thread.join()
    send_thread.join()
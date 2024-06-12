from enum import Enum, auto

"neighbor states"
class NeighborState(Enum):
    S_Down = 0,
    S_Attempt = 1
    S_Init = 2,
    S_2Way = 3,
    S_Exstart = 4
    S_Exchange = 5,
    S_Loading = 6,
    S_Full = 7

"neighbor events"
class NeighborEvent(Enum):
    E_HelloReceived = 0,
    E_Start = 1,
    E_2WayReceived = 2,
    E_NegotiationDone = 3,
    E_ExchangeDone = 4,
    E_BadLSReq = 5,
    E_LoadingDone = 6,
    E_AdjOK = 7,
    E_SeqNumberMismatch = 8,
    E_1Way = 9,
    E_KillNbr = 10,
    E_InactivityTimer = 11,
    E_LLDown = 12 

class Neighbor():
    def __init__(self):
        self.state = NeighborState.S_Down
        # 主从master/slave
        self.is_master = False
        
        # 当前被发往邻居的 DD 包序号
        self.dd_sequence_number = 0
        # 最近接收到的数据库描述包，
        # 从邻居最近接收到的 DD 包中的 DD 序号，以及初始（I）、更多（M）和主从（MS）位。用于判断从邻居接收到的下一个 DD 包是否重复
        self.last_dd_equence_number
        self.last_dd_flags

        # 邻居信息
        self.id
        self.priority
        self.ip 
        self.ndr # 邻居认为的DR
        self.nbdr# 邻居认为的BDR

        # 连接状态重传列表
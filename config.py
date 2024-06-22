# 全局配置
import logging
from enum import Enum

InitialSequenceNumber = 0x80000001 # 32位有符号数,TODO:这个值有待商榷
MaxSequenceNumber = 0x7fffffff # 32位有符号数
MaxAge = 3600 # 单位是s
MaxAgeDiff = 900 # 单位是s
LSRefreshTime = 1800

"network type"
class NetworkType(Enum):
    T_P2P = 0
    T_BROADCAST = 1
    T_NBMA = 2
    T_P2MP = 3
    T_VIRTUAL = 4

"neighbor states"
class NeighborState(Enum):
    S_Down = 0
    S_Attempt = 1
    S_Init = 2
    S_2Way = 3
    S_Exstart = 4
    S_Exchange = 5
    S_Loading = 6
    S_Full = 7

"neighbor events"
class NeighborEvent(Enum):
    E_HelloReceived = 0
    E_Start = 1
    E_2WayReceived = 2
    E_NegotiationDone = 3
    E_ExchangeDone = 4
    E_BadLSReq = 5
    E_LoadingDone = 6
    E_AdjOK = 7
    E_SeqNumberMismatch = 8
    E_1Way = 9
    E_KillNbr = 10
    E_InactivityTimer = 11
    E_LLDown = 12

"interface states"
class InterfaceState(Enum):
    S_Down = 0
    S_Loopback = 1
    S_Waiting = 2
    S_PointToPoint = 3
    S_DROther = 4
    S_Backup = 5
    S_DR = 6

"interface events"
class InterfaceEvent(Enum):
    E_InterfaceUp = 0
    E_WaitTimer = 1
    E_BackupSeen = 2
    E_NeighborChange = 3
    E_LoopInd = 4
    E_UnloopInd = 5
    E_InterfaceDown = 6 

"routing item types"
class RoutingType(Enum):
    Network = 1
    Router = 2

class Config():
    is_stop = False
    is_debug = True

logger = logging.getLogger('my_thread_logger')
logger.setLevel(logging.DEBUG)
# 创建控制台处理器并设置级别为 DEBUG
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
if Config.is_debug:
    logger.addHandler(console_handler)
else:
    logger.addHandler(logging.NullHandler())
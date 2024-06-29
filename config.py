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

"interface states"
class InterfaceState(Enum):
    S_Down = 0
    S_Loopback = 1
    S_Waiting = 2
    S_PointToPoint = 3
    S_DROther = 4
    S_Backup = 5
    S_DR = 6

"routing item types"
class RoutingType(Enum):
    Network = 1
    Router = 2

class Config():
    is_stop = False
    is_debug = True # 是否是debug状态,输出日志

logger = logging.getLogger('my_thread_logger')
logger.setLevel(logging.DEBUG)
# 创建控制台处理器并设置级别为 DEBUG
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)

if Config.is_debug:
    logger.addHandler(console_handler)
else:
    logger.addHandler(logging.NullHandler())
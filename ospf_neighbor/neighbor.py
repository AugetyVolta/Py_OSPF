from enum import Enum, auto
"neighbor states"

class NeighborState(Enum):
    S_DOWN = 0,
    S_ATTEMPT = 1
    S_INIT = 2,
    S_2WAY = 3,
    S_EXSTART = 4
    S_EXCHANGE = 5,
    S_LOADING = 6,
    S_FULL = 7
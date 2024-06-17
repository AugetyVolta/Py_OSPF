from threading import Lock

class LSADataBase():
    def __init__(self,area_id = "0.0.0.0"):
        # 每一个区域拥有独立的lsdb
        self.area_id = area_id
        # LSA列表
        self.LSAs = []
        # 对于LSA访问的锁
        self.lsa_lock = Lock()
        
    # 基于 LS 类型、LS 标识以及宣告路由器的 LSA 查找函数
    def getLSA(self,ls_type,lsa_id,adv_router):
        self.lsa_lock.acquire()
        for lsa in self.LSAs:
            if lsa.type == ls_type and lsa.lsa_id == lsa_id and lsa.adv_router == adv_router:
                return lsa
        self.lsa_lock.release()
        return None
    
    # 添加lsa，a）在洪泛过程中接收（见第 13 章）；b）路由器自己生成（见第 12.4 节）
    def addLSA(self,lsa):
        self.lsa_lock.acquire()

        self.lsa_lock.release()
        pass

    # 删除LSA
    def delLSA(self):
        self.lsa_lock.acquire()

        self.lsa_lock.release()
        pass
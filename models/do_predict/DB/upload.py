from pymongo import MongoClient

class vaiscanDB():
    def __init__(self):
        self.client= MongoClient("mongodb://13.125.230.113:27017")
        self.db = self.client['vaiscan']
        self.col = self.db['results']
        #self.hash=hash
    
    def selectall(self):
        
        return self.col.find()
    
    def select(self,hash):
        
        return self.col.find({"hash":hash})
    
    def set(self,filename,filesize,hash,type):
        where={"hash":hash}
        # "type" : type,
        newvalue={"$set":{"file_name":filename,"size":filesize,"type" : type}}
        try:
            self.col.update_one(where,newvalue)
        except Exception as e:
             
            return e
        else:
            return self.col.find()
    
    def settype(self,hash,type):
        where={"hash":hash}
        # "type" : type,
        newvalue={"$set":{"type" : type}}
        try:
            self.col.update_one(where,newvalue)
        except Exception as e:
             
            return e
        else:
            return self.col.find()
        
    def setrisk(self,hash,risk):
        where={"hash":hash}
        # "type" : type,
        newvalue={"$set":{"risk" : risk}}
        try:
            self.col.update_one(where,newvalue)
        except Exception as e:
             
            return e
        else:
            return self.col.find()
        
    
    def setprogress(self,hash,progress):
        
        where={"hash":hash}
        # "type" : type,
        newvalue={"$set":{ "progress" : progress}}
        try:
            self.col.update_one(where,newvalue)
        except Exception as e:
             
            return e
        else:
            return self.col.find()
    
    def setall(self,filename,filesize,hash,progress,risk,type):
    
        where={"hash":hash}
        # "type" : type,
        newvalue={"$set":{ "file_name":filename,"size":filesize,"progress" : progress,"risk":risk,"type":type}}
        
        try:
            self.col.update_one(where,newvalue)
        except Exception as e:
                
            return e
        else:
            return self.col.find()
        
    
    

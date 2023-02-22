# -*- coding: utf-8 -*-

from itertools import chain
from capstone import *
from capstone.x86 import *
import tensorflow as tf
import numpy as np
import pandas as pd
import time
import array
import dis
import operator
import binascii
import csv
import os
import pefile
import yara
import math
import hashlib
import asyncio;
import DB.upload as upload
import percent

np.set_printoptions(suppress=True, threshold=np.inf, linewidth=np.inf)

class do_predict():

    global prograss_n
    IMAGE_DOS_HEADER = [
                        "e_cblp",\
                        "e_cp", \
                        "e_cparhdr",\
                        "e_maxalloc",\
                        "e_sp",\
                        "e_lfanew"]

    FILE_HEADER= ["NumberOfSections","CreationYear"] + [ "FH_char" + str(i) for i in range(15)]
                

    OPTIONAL_HEADER1 = [
                        "MajorLinkerVersion",\
                        "MinorLinkerVersion",\
                        "SizeOfCode",\
                        "SizeOfInitializedData",\
                        "SizeOfUninitializedData",\
                        "AddressOfEntryPoint",\
                        "BaseOfCode",\
                        "BaseOfData",\
                        "ImageBase",\
                        "SectionAlignment",\
                        "FileAlignment",\
                        "MajorOperatingSystemVersion",\
                        "MinorOperatingSystemVersion",\
                        "MajorImageVersion",\
                        "MinorImageVersion",\
                        "MajorSubsystemVersion",\
                        "MinorSubsystemVersion",\
                        "SizeOfImage",\
                        "SizeOfHeaders",\
                        "CheckSum",\
                        "Subsystem"] 
    OPTIONAL_HEADER_DLL_char = [ "OH_DLLchar" + str(i) for i in range(11)]                   
                            
    OPTIONAL_HEADER2 = [
                        "SizeOfStackReserve",\
                        "SizeOfStackCommit",\
                        "SizeOfHeapReserve",\
                        "SizeOfHeapCommit",\
                        "LoaderFlags"]  # boolean check for zero or not
    OPTIONAL_HEADER = OPTIONAL_HEADER1 + OPTIONAL_HEADER_DLL_char + OPTIONAL_HEADER2
    Derived_header = ["sus_sections","non_sus_sections", "packer","packer_type","E_text","E_data","filesize","E_file","fileinfo"]
    
    def __init__(self,path):
        
        self.source = path
        self.hashnum = ''
        self.rules = yara.compile(filepath='./peid.yara')
        self.db = upload.vaiscanDB()
        self.num = 1

    @property
    def hash(self):
        return self.hashnum
    @hash.setter
    def hash(self, hash):
        self.source += hash
        self.hashnum = hash
    
    def dbprogress(self,increase):
        self.num+=increase
        self.db.setprogress(self.hash,self.num)
    
    def file_creation_year(self,seconds):
        tmp = 1970 + ((int(seconds) / 86400) / 365)
        return int(tmp in range (1980,2016)) 

    def FILE_HEADER_Char_boolean_set(self,pe):
        tmp = [pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE,\
            pe.FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM,\
            pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE,\
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO,\
            pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE,\
            pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,\
            pe.FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP,\
            pe.FILE_HEADER.IMAGE_FILE_SYSTEM,\
            pe.FILE_HEADER.IMAGE_FILE_DLL,\
            pe.FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY,\
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI
            ]
        return [int(s) for s in tmp]

    def OPTIONAL_HEADER_DLLChar(self,pe):
        tmp = [
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT ,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
            ]
        return [int(s) for s in tmp]

    def Optional_header_ImageBase(self,ImageBase):
        result= 0
        if ImageBase % (64 * 1024) == 0 and ImageBase in [268435456,65536,4194304]:
            result = 1
        return result

    def Optional_header_SectionAlignment(self,SectionAlignment,FileAlignment):
        """This is boolean function and will return 0 or 1 based on condidtions
        that it SectionAlignment must be greater than or equal to FileAlignment
        """
        return int(SectionAlignment >= FileAlignment)

    def Optional_header_FileAlignment(self,SectionAlignment,FileAlignment):
        result =0
        if SectionAlignment >= 512:
            if FileAlignment % 2 == 0 and FileAlignment in range(512,65537):
                result =1
        else: 
            if FileAlignment == SectionAlignment:
                result = 1
        return result

    def Optional_header_SizeOfImage(self,SizeOfImage,SectionAlignment):

        return int(SizeOfImage % SectionAlignment == 0)

    def Optional_header_SizeOfHeaders(self,SizeOfHeaders,FileAlignment):

        return int(SizeOfHeaders % FileAlignment == 0 )

    def extract_dos_header(self,pe):
        IMAGE_DOS_HEADER_data = [ 0 for i in range(6)]
        try:
            IMAGE_DOS_HEADER_data = [
                                pe.DOS_HEADER.e_cblp,\
                                pe.DOS_HEADER.e_cp, \
                                pe.DOS_HEADER.e_cparhdr,\
                                pe.DOS_HEADER.e_maxalloc,\
                                pe.DOS_HEADER.e_sp,\
                                pe.DOS_HEADER.e_lfanew]
        except Exception as e:
            print(e)
        return IMAGE_DOS_HEADER_data

    def extract_file_header(self,pe):   
        FILE_HEADER_data = [ 0 for i in range(3)]
        FILE_HEADER_char =  []
        try:
            FILE_HEADER_data = [ 
                    pe.FILE_HEADER.NumberOfSections, \
                    self.file_creation_year(pe.FILE_HEADER.TimeDateStamp)]
            FILE_HEADER_char = self.FILE_HEADER_Char_boolean_set(pe)
        except Exception as e:
            print(e)
        return FILE_HEADER_data + FILE_HEADER_char

    def extract_optional_header(self,pe):
        OPTIONAL_HEADER_data = [ 0 for i in range(21)]
        DLL_char =[]
        OPTIONAL_HEADER_data2 = [ 0 for i in range(6)]

        try:
            OPTIONAL_HEADER_data = [
                pe.OPTIONAL_HEADER.MajorLinkerVersion,\
                pe.OPTIONAL_HEADER.MinorLinkerVersion,\
                pe.OPTIONAL_HEADER.SizeOfCode,\
                pe.OPTIONAL_HEADER.SizeOfInitializedData,\
                pe.OPTIONAL_HEADER.SizeOfUninitializedData,\
                pe.OPTIONAL_HEADER.AddressOfEntryPoint,\
                pe.OPTIONAL_HEADER.BaseOfCode,\
                pe.OPTIONAL_HEADER.BaseOfData,\
                #Check the ImageBase for the condition
                self.Optional_header_ImageBase(pe.OPTIONAL_HEADER.ImageBase),\
                # Checking for SectionAlignment condition
                self.Optional_header_SectionAlignment(pe.OPTIONAL_HEADER.SectionAlignment,pe.OPTIONAL_HEADER.FileAlignment),\
                #Checking for FileAlignment condition
                self.Optional_header_FileAlignment(pe.OPTIONAL_HEADER.SectionAlignment,pe.OPTIONAL_HEADER.FileAlignment),\
                pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MajorImageVersion,\
                pe.OPTIONAL_HEADER.MinorImageVersion,\
                pe.OPTIONAL_HEADER.MajorSubsystemVersion,\
                pe.OPTIONAL_HEADER.MinorSubsystemVersion,\
                #Checking size of Image
                self.Optional_header_SizeOfImage(pe.OPTIONAL_HEADER.SizeOfImage,pe.OPTIONAL_HEADER.SectionAlignment),\
                #Checking for size of headers
                self.Optional_header_SizeOfHeaders(pe.OPTIONAL_HEADER.SizeOfHeaders,pe.OPTIONAL_HEADER.FileAlignment),\
                pe.OPTIONAL_HEADER.CheckSum,\
                pe.OPTIONAL_HEADER.Subsystem]

            DLL_char = self.OPTIONAL_HEADER_DLLChar(pe)

            OPTIONAL_HEADER_data2= [                
                pe.OPTIONAL_HEADER.SizeOfStackReserve,\
                pe.OPTIONAL_HEADER.SizeOfStackCommit,\
                pe.OPTIONAL_HEADER.SizeOfHeapReserve,\
                pe.OPTIONAL_HEADER.SizeOfHeapCommit,\
                int(pe.OPTIONAL_HEADER.LoaderFlags == 0) ]
        except Exception as e:
            print(e)
        return OPTIONAL_HEADER_data + DLL_char + OPTIONAL_HEADER_data2

    def get_count_suspicious_sections(self,pe):
        result=[]
        tmp =[]
        benign_sections = set(['.text','.data','.rdata','.idata','.edata','.rsrc','.bss','.crt','.tls'])
        for section in pe.sections:
            tmp.append(section.Name.decode().split('\0')[0])
        non_sus_sections = len(set(tmp).intersection(benign_sections))
        result=[len(tmp) - non_sus_sections, non_sus_sections]
        return result

    def check_packer(self,filepath):

        result=[]
        matches = self.rules.match(filepath)

        try:
            if matches == [] or matches == {}:
                result.append([0,"NoPacker"])
            else:
                result.append([1,matches['main'][0]['rule']])
        except:
            result.append([1,matches[0]])

        return result

    def get_text_data_entropy(self,pe):
        result=[0.0,0.0]
        for section in pe.sections:
            s_name = section.Name.decode().split('\0')[0]
            if s_name == ".text":
                result[0]= section.get_entropy()
            elif s_name == ".data":
                result[1]= section.get_entropy()
            else:
                pass
        return result  
    
    def get_file_bytes_size(self,filepath):
        with open(filepath, "rb") as f:
            byteArr = list(f.read())
        fileSize = len(byteArr)
        return byteArr, fileSize

    def cal_byteFrequency(self,byteArr,fileSize):
        freqList = []
        for b in range(256):
            ctr = 0
            for byte in byteArr:
                if byte == b:
                    ctr += 1
            freqList.append(float(ctr) / fileSize)
        return freqList
    
    def get_file_entropy(self,filepath):
        byteArr, fileSize = self.get_file_bytes_size(filepath)
        freqList = self.cal_byteFrequency(byteArr, fileSize)

        ent = 0.0
        for freq in freqList:
            if freq > 0:
                ent += -freq * math.log(freq, 2)

        return [fileSize, ent]

    def get_fileinfo(self,pe):
        result=[]
        try:
            FileVersion    = pe.FileInfo[0].StringTable[0].entries['FileVersion']
            ProductVersion = pe.FileInfo[0].StringTable[0].entries['ProductVersion']
            ProductName =    pe.FileInfo[0].StringTable[0].entries['ProductName']
            CompanyName = pe.FileInfo[0].StringTable[0].entries['CompanyName']
        #getting Lower and 
            FileVersionLS    = pe.VS_FIXEDFILEINFO.FileVersionLS
            FileVersionMS    = pe.VS_FIXEDFILEINFO.FileVersionMS
            ProductVersionLS = pe.VS_FIXEDFILEINFO.ProductVersionLS
            ProductVersionMS = pe.VS_FIXEDFILEINFO.ProductVersionMS
        except Exception as e:
            result=["error"]

        else:
        #shifting byte
            FileVersion = (FileVersionMS >> 16, FileVersionMS & 0xFFFF, FileVersionLS >> 16, FileVersionLS & 0xFFFF)
            ProductVersion = (ProductVersionMS >> 16, ProductVersionMS & 0xFFFF, ProductVersionLS >> 16, ProductVersionLS & 0xFFFF)
            result = [FileVersion,ProductVersion,ProductName,CompanyName]
        return int ( result[0] != 'error')


    def extract_pe(self):
        data =[]
        filepath = self.source
        try:
            pe = pefile.PE(filepath)
            self.dbprogress(3)
        except Exception as e:
            print("{} while opening {}".format(e,filepath))
        else:
            
            magic = pe.OPTIONAL_HEADER.Magic
            if magic != 267:
                print("64-bit File. cannot process")
                return 0
            self.dbprogress(3)
            data += self.extract_dos_header(pe)
            self.dbprogress(3)
            data += self.extract_file_header(pe)
            self.dbprogress(3)
            data += self.extract_optional_header(pe)
            self.dbprogress(3)
            num_ss_nss = self.get_count_suspicious_sections(pe)
            self.dbprogress(3)
            data += num_ss_nss
            self.dbprogress(3)
            packer = self.check_packer(filepath)
            self.dbprogress(3)
            data += packer[0]
            self.dbprogress(3)
            entropy_sections = self.get_text_data_entropy(pe)
            self.dbprogress(3)
            print("entropy text data",entropy_sections)
            data += entropy_sections
            self.dbprogress(3)
            f_size_entropy = self.get_file_entropy(filepath)
            self.dbprogress(3)
            print("f_entropy text data",f_size_entropy)
            data += f_size_entropy
            self.dbprogress(3)
            fileinfo = self.get_fileinfo(pe)
            self.dbprogress(3)
            data.append(fileinfo)

        
        return data 
    
    
################################ ngram

    def gen_list_n_gram(self, num, asm_list):

        for i in range(0, len(asm_list), num):
            yield asm_list[i:i+num]

    def n_grams(self, num, asm_list):
        gram = dict()
        gen_list = self.gen_list_n_gram(num, asm_list)
        self.dbprogress(3)
        for lis in gen_list:
            lis = " ".join(lis)
            try:
                gram[lis] += 1
            except:
                gram[lis] = 1    
            
        return gram


    def get_ngram_count(self, headers, grams):

        patterns = list()
        self.dbprogress(3)
        for pat in headers:
            try:
                
                patterns.append(grams[pat])

            except:
                patterns.append(0)

        return patterns

    def get_opcodes(self, mode, file):

        asm = []
        pe = pefile.PE(file)
        self.dbprogress(3)

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        end = pe.OPTIONAL_HEADER.SizeOfCode
        self.dbprogress(3)
        for section in pe.sections:
            addr = section.VirtualAddress
            size = section.Misc_VirtualSize
            
            if ep > addr and ep < (addr+size):
                ep = addr
                end = size
        self.dbprogress(3)
        data = pe.get_memory_mapped_image()[ep:ep+end]
        self.dbprogress(3)
        temp = binascii.hexlify(data).decode('ascii')
        self.dbprogress(3)
        temp = [temp[i:i+2] for i in range(0,len(temp), 2)]
        self.dbprogress(3)
        if(mode):
            return temp

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = False
        self.dbprogress(3)
        
        for insn in md.disasm(data, 0x401000):
            asm.append(insn.mnemonic) 

        return asm

    def extract_ngram(self):
        
        # ngram column을 불러옴
        ngram_col=pd.read_csv("./ngram_col.csv")
        self.dbprogress(3)
        header=list(ngram_col.columns)
        self.dbprogress(3)
        
        # asm코드 추출
        byte_code = self.get_opcodes(0, self.source)
        self.dbprogress(3)
        # 상위 4개의 코드 추출
        grams = self.n_grams(4, byte_code)
        self.dbprogress(3)
        # 헤더에 맞춰 저장
        gram_count = self.get_ngram_count(header, grams)
        self.dbprogress(3) 
        print("grams ty",type(gram_count))
        print("grams",len(gram_count))
        print("gram :",gram_count)
        return gram_count
        

    def extract_all(self):
        
        data=self.extract_pe()
        print(len(data))
        print(data)
        # 64bit 알림

        if len(data) != 69:
            print("File corrupted")
            return 0
        self.dbprogress(3)
        
        ngram=self.extract_ngram()
        print(len(ngram))
        print(data[63])
        del data[63]
        self.dbprogress(3)
        # extend() 는 리스트 자체를 변환시킴. 반환은 none이 됨. 주의!
        data.extend(ngram)
        self.dbprogress(3)

        return data
    
    def predict_file(self):
        
        data=self.extract_all()
        
        if data!=0:

            print(len(data))
            print(type(data))
            data = np.asarray(data).reshape((1, -1)) # 자료형 변환 
            self.dbprogress(3)
            
            model = tf.keras.models.load_model('../saved_models/last_model.h5')
            self.dbprogress(3)
            
            print("data : \n",data)
            print("data[0] : ",data[0])
            print("len:",len(data[0]))
            
            y_prednum = model.predict(data)
            y_prednum = y_prednum.flatten() # 차원 펴주기
            
            y_pred = np.where(y_prednum > 0.80, 1 , 0) #0.5보다크면 1, 작으면 0
            pred = 1
            pred=percent.p(y_pred[0])
            self.db.setrisk(self.hash,pred)
              
            print("\n 2 : ",y_pred[0])
            print("risk : ",pred)    
        else:
            os.system("rm -rf "+self.source)
            self.db.setprogress(self.hash,-1)
            

        
        
        

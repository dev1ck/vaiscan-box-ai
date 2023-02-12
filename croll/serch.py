import os

# 파일경로
pwd = "/mnt/hgfs/portableapps/PortableApps"
failelist = []

def movefile(file_list):
    fail=[]
    for program in file_list:
            if ".exe" in program:
                try:
                    os.system("cp "+pwd+"/"+folder_name+"/"+program+" /home/sai/mal_sha256/normalfile/"+program)
                except:
                    print(program+" move fail")
                    fail.append(program)
                    pass
                print("moved exe filename : "+program)
    
    return fail


# 파일경로의　프로그램이　파일이　담긴　폴더들을 가져옴
folder_list = os.listdir(pwd)


# 폴더들을 순서대로 반복 
for folder_name in folder_list:
    try:
 
        print("\nfolder name : "+folder_name)
        # 프로그램들이　담긴　폴더들을 순서대로 반복
        file_list = os.listdir(pwd+"/"+folder_name)

        failelist=movefile(file_list)
        
                
    except:
        pass

# 실패목록 재시도
print("\n\n retry move faile files ----- ")

# 재시도 실패한 목록
print("\n\n------------ move fail list ------------")
for fail in movefile(failelist):
    print(fail)


    

            

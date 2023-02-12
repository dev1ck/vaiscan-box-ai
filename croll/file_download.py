#from zipfile import ZipFile
import pyzipper
import os
import time
import get_html
import re

malwares=0
downloadfale=0
numoffiles=10000

_link = '(?<=a href=\")(.*)(\">20.*.zip)'
link_pattern = re.compile(_link)


url='https://datalake.abuse.ch/malware-bazaar/daily/'

list1=get_html.get_html(url,'table',0,'html5lib')

# list1=["< a href='A1?=a2'><img>","< a href='B1?=b2'><img>","< a href='C1?=c2'><img>","< a href='D1?=d2'><img>","< a href='E1?=e2'><img>"]
i=0
#for l1 in list1:
print('\nfor ---')
    
down_link = link_pattern.findall(str(list1))
						
		# 골라낸 값이 존재할 경우
if(down_link):
    
    print("start")
    # with open("/home/sai/mal_sha256/full_sha256.txt","r") as f:
        
    for f_sha256 in down_link:
        i+=1
        if(i>=45):
            try:    
                
                cmd='wget '+url+'/'+f_sha256[0]+' -P /home/sai/mal_sha256/newmalware'
                    
                try:
                    os.system(cmd)
                except:
                    try:
                        print("wget error!!")
                        time.sleep(15)
                        os.system(cmd)
                    except:
                        print("wget restart fale....")
                        downloadfale+=1
                        pass
                            #input("Keep Download? Y<Enter>/ N<ctrl+c>")
                            


                with pyzipper.AESZipFile('/home/sai/mal_sha256/newmalware/'+f_sha256[0]) as zf:
                    zf.pwd=b'infected'
                    filename=zf.namelist()
                    zf.extractall('/home/sai/mal_sha256/newmalware')
                        
                with open("/home/sai/mal_sha256/newmalware/"+filename[0],'rb') as binmal:
                        
                    data=binmal.read()
                    if(hex(data[0])=='0x4d')and(hex(data[1])=='0x5a'):
                        print("PE file")
                        print("\n\n ============"+filename[0]+" Download succeed =============\n\n ")
                        malwares+=1
                    else:
                        print("not PE file")
                        os.system("rm -rf /home/sai/mal_sha256/newmalware/"+filename[0])


                #os.system("rm -rf /home/sai/mal_sha256/newmalware/"+f_sha256[0])

                if(numoffiles==malwares):
                    print("Malware Download is End")
                    break

                print("\nnumber of Downloaded PEmalware : "+str(malwares)+"\nnumber of Download fale : "+str(downloadfale)+"\n===========================================\n\n")
                time.sleep(15)

            except KeyboardInterrupt:
                print("\n===== download is stoped .. ====== \n\n  cleaning..")
                path='/home/sai/mal_sha256/newmalware'
                cleanlist=os.listdir(path)
                
                try:
                    for cfile in cleanlist:
                        if ".exe" not in cfile:
                            os.system("rm -rf "+path+"/"+cfile)
                    
                    print("==== clean succeed!! ====")
                    break
                except:
                    print("cleanning error")
                    break

                

            except:
                print("open fale")
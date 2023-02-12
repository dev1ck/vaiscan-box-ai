import pyzipper
import os

path="/home/sai/mal_sha256/newmalware"
filename=os.listdir(path)
succeednum=0
failednum=0

print("... start unzip ... \n")

for file in filename:
    if ".zip" in file:
        try:
            with pyzipper.AESZipFile(path+"/"+file) as zf:
                zf.pwd=b'infected'
                filename=zf.namelist()
                zf.extractall(path)
            succeednum+=1
            os.system("rm -rf "+path+"/"+file)

            print("unzip succeed! number : "+succeednum)

        except KeyboardInterrupt:
            print("unzipping stoped !!")
            break

        except:
            print("unzip fail!!")
            failednum+=1

print("\n==== End unzip ==== \n\n succeed : "+str(succeednum)+"\n failed : "+str(failednum)+"\n")
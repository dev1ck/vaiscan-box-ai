import os 

path='/home/sai/mal_sha256/newmalware'
list1=os.listdir(path)

for file in list1:
    if ".exe" not in file:
        os.system("rm -rf "+path+"/"+file)


from zipfile import ZipFile 

filename="/home/sai/test4.zip"
try:
    with ZipFile(filename) as zf:
        print("zip")
        zf.extractall(pwd=b'test4')
        print("succeed")
except:            
    print(filename+" Download f")
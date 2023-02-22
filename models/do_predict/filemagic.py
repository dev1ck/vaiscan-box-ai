
# https://github.com/ahupp/python-magic
import magic

def f_magic(file):
    path="/home/jodaegeun/vaiscan-box-static-ai/received_files/"+file
    f=magic.from_file(path,mime=True)
    print(f)
    num=False
    a,b=f.split('/')
    if b=='vnd.openxmlformats-officedocument.wordprocessingml.document':
        ftype='docx'
    elif b=='x-dosexec':
        ftype='exe'
        num=True
    elif b=='pdf':
        ftype='pdf'
    elif b=='jpeg':
        ftype='jpeg'
    elif b=='png':
        ftype='png'
    elif a=='text' and b=='plain':
        ftype='text'
    elif b=='vnd.ms-powerpoint':
        ftype='ppt'
    elif b=='vnd.openxmlformats-officedocument.spreadsheetml.sheet':
        ftype='xlsx'
    elif b=='zip':
        ftype='zip'
    elif b=='x-empty' and a=='inode':
        ftype='mp4'
    elif b=='x-python' and a=='text':
        ftype='python'
    elif b=='vnd.openxmlformats-officedocument.presentationml.presentation':
        ftype='pptx'
    else:
        ftype='unknown'
    return ftype, num
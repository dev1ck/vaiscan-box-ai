import urllib.request
from bs4 import BeautifulSoup

# tag : 긁어올 태그 ,att : 긁어올 속성 , parser : 파서의 종류
def get_html(url,tag,att,parser):
    try:
        # url open & decoding 방식 설정 
        html = urllib.request.urlopen(url).read().decode('utf-8')
    
    except:

        # url open 실패시 none 반환
        return None
    
    # url 주소에서 받아온 값이 없을 경우
    if(html==None): 
        print("url get error") 
    
    # 받아온 값이 존재할 때 
    else:
        
        #BS 라이브러리를 이용해 파싱
        bsobj=BeautifulSoup(html, parser)

        # 태그 설정 값이 없을 경우
        if(tag==0):

            # 모든 html 값을 출력
            return bsobj 
        
        # 태그 설정 값이 있을 경우
        else:

            # 속성 설정값이 없을 경우
            if(att==0):

                # 특정 태그의 값을 리턴
                return bsobj.find(tag)
            
            #속성 설정값이 있을 경우
            else:
                
                # 특정 태그 중 특정 속성을 포함하는 값을 리턴
                return bsobj.find(tag,att)
         
               



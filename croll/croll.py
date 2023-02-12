import get_html
import re
_link = '(?<=a href=\")(.*)(\">20.*.zip)'
link_pattern = re.compile(_link)


url='https://datalake.abuse.ch/malware-bazaar/daily/'

list1=get_html.get_html(url,'table',0,'html5lib')

# list1=["< a href='A1?=a2'><img>","< a href='B1?=b2'><img>","< a href='C1?=c2'><img>","< a href='D1?=d2'><img>","< a href='E1?=e2'><img>"]
j=0

#for l1 in list1:
print('\nfor ---')
    
down_link = link_pattern.findall(str(list1))
						
		# 골라낸 값이 존재할 경우
if(down_link):
    print(down_link)
    print('list----')
		# down_link에 담긴 값은 
		# ( http://malwaredb.malekal.com/index.php?hash=86927f...0675 , "><img )
		# 이중 하나로.. down_link[i][0] == http://malwaredb.malekal.com/index.php?hash=86927f...0675
    i =0
    for l1 in down_link:
      if i==3000:
        break
      print(i)
      i+=1

    print("total : "+str(i))
        
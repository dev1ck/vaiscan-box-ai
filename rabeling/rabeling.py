import json
import urllib.request
from urllib import parse
import sys
import os
import time
import re
import hashlib

# sha256 의 패턴
_sha256 = '[a-z0-9]{64}'

# 바이러스 샘플 파일의 위치
path_dir = '/home/sai/mal_sha256/malware'

# 샘플디렉토리의 파일들을 리스트 형태로 가져옴
file_list = os.listdir(path_dir)

# sha256 패턴을 python 코드화
sha256_pattern = re.compile(_sha256)

# 주요 기능을 담고있는 클래스 선언 
class vtAPI():
	
	# vtAPI 생성시 실행됨
	def __init__(self):
        
	# virustotal 사이트에서 받은 api 키 입력 
		self.api = '902b3b664ba89b8861c30fe7a0267ef7825c370e297907a97b1daea4596ce0e2'
	# virustotal 의 v2 api.
	# https://developers.virustotal.com/v2.0/reference/getting-started 에서 확인이 가능
		self.base = 'https://www.virustotal.com/vtapi/v2/'
	
	# virustotal 에 제출하는 함수 
	def getReport(self,md5,sha256):
        
		# md5 값과 apikey 값, api 정보를 딕셔너리 형식으로 저장
		# https://developers.virustotal.com/v2.0/reference/file-report 의 예시를 확인
		param = {'resource':md5,'apikey':self.api, 'allinfo':'1'}
		url = self.base + "file/report"

		# url에서 사용하는 형태로 문자 인코딩
		data = urllib.parse.urlencode(param).encode('utf-8')

		# url 과 서버에 보낼 부분이 인코딩 된 문자열 폼. open 후 결과를 저장. 
		result = urllib.request.urlopen(url,data)

		# 받은 결과( json 형태 )를 읽어서 python 객체로 저장. 
		jdata = json.loads(result.read())
		# virustotal 에서 보낸 응답이 0 일 경우 (서버의 데이터 세트에 값이 없음)
		if jdata['response_code'] == 0:
			print(sha256 + " -- Not Found in VT")
			return "no"
		
		# virustotal 에 값이 존재할 경우
		else:
			# 받은 값중 일부를 출력하고 양성, 음성인지 결과를 출력함 
			print("=== Results for sha256: ", jdata['sha256'], "\tDetected by: ", jdata['positives'])
			return jdata['positives']

	# 파일을 virustotal 에 업로드하여 분석하는 함수
	def reqScan(self,filepath):
		print("- Requesting a new scan")
		param = {'file':filepath,'apikey':self.api}
		url = self.base + "file/scan"
		data = urllib.urlencode(param)
		result = urllib.urlopen(url,data)
		
		# 결과 (json) 을 받아서 python 객체로 저장
		jdata = json.loads(result.read())
		# 반환
		return jdata

# 파일의 해시값을 구하는 함수
# 버퍼의 기본 크기 8192
	def getsha256(self, filepath, blocksize=8192):
		
		# sha256 으로 해시
		sha256 = hashlib.sha256()
		
		try:
			# 파일을 읽어온다.
			f = open(filepath, "rb")
		
		# 파일 읽기 실패시.
		except IOError as e:
			print("file open error", e)
			return
		
		while True:
			
			# 파일에서 blocksize 크기만큼 문자를 읽어옴
			buf = f.read(blocksize)

			# buf 에 값이 없을 경우 멈춤
			if not buf:
				break
			
			# 읽어온 값을 sha256 형식으로 해시함.
			sha256.update(buf)
		
		# 해시값을 리턴
		return sha256.hexdigest()

	def getmd5(self, filepath, blocksize=8192):
		
		# sha256 으로 해시
		md5 = hashlib.md5()
		
		try:
			# 파일을 읽어온다.
			f = open(filepath, "rb")
		
		# 파일 읽기 실패시.
		except IOError as e:
			print("file open error", e)
			return
		
		while True:
			
			# 파일에서 blocksize 크기만큼 문자를 읽어옴
			buf = f.read(blocksize)

			# buf 에 값이 없을 경우 멈춤
			if not buf:
				break
			
			# 읽어온 값을 sha256 형식으로 해시함.
			md5.update(buf)
		
		# 해시값을 리턴
		return md5.hexdigest()        


# 메인
def main():

	vt = vtAPI()
	i = 0
	
	# 파일리스트의 크기만큼 반복
	for file in file_list:

		before = path_dir + "/" + file
		
		# 파일의 이름이 .exe , .xml 이런식이기 때문에 나눠줌
		filename=file.split('.')[0]
		f_extension=file.split('.')[1]
		tmp=0
		if "#" in filename:
			tmp=1
			o_file=filename.split('#')
			o_file=o_file[(len(o_file)-1)]

		# 파일 리스트의 이름이 sha256 패턴인지 확인
		name_check = re.search(sha256_pattern, filename)
		
		# 해시값이 아닐경우 해시값을 구해 file 에 저장
		if name_check == None:
			print("hash")
			filename = vt.getsha256(before)

		try:

			i += 1
            
			filemd5 = vt.getmd5(before)
			# 파일 이름값으로 virustotal 에 검색

			rns = vt.getReport(filemd5,filename)

			# 결과가 없을 경우 
			if(rns == "no"):
				
				# 결과가 없는 파일을 virustotal 에 전송하여 분석 
				file_path = os.getcwd() + "/" + file
				rns = vt.reqScan(file_path)
				
				# 분석 결과중 sha256 부분을 뽑아 저장
				filename = rns['sha256']

				while True:
					
					# virustotal 결과 반영을 위해 20초 대기 후 다시 검색
					time.sleep(20)
					rns = vt.getReport(filename)

					# 그래도 결과가 없을 경우 멈춤
					if(rns != "no"):
						break
			
			# 파일이름을 ( 결과#해시값 ) 바꾸기 위해 합쳐서 저장.
			if tmp==0:
				after = path_dir + "/" + str(rns) + "#" + filename+"."+f_extension
			else:
				after = path_dir + "/" + str(rns) + "#" + o_file+"."+f_extension
			# 결과를 저장
			print("Processed " + str(i) + " files - "+ after)
			# 이름을 라벨링한 결과로 다시 저장.
			os.rename(before, after)
			os.system("mv "+after+" "+"/home/sai/mal_sha256/rabeled")

			time.sleep(15)
		except:
			print("pass")
			pass

	

if __name__ == '__main__':
	main()
    
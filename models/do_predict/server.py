#비동기 프로그래밍을 위한 모듈 
import asyncio
# 웹 소켓 모듈
import nest_asyncio
import websockets
import os
# base64를 binary로 변환하는 모듈
import base64
import predict
import filemagic
import DB.upload as up

# 업로드 할 때 데이터 정보에 관한 클래스
nest_asyncio.apply()

class Node():
  # 생성자
  def __init__(self,path):
    # 파일 이름
    self.__hash = ''
    # 파일 사이즈
    self.__filesize = 0
    # base64로 된 파일 데이터
    self.__data = bytearray()
    # 파일 저장위치
    self.path=path
    
  # 파일 이름 프로퍼티
  @property
  def hash(self):
    return self.__hash
  @hash.setter
  def hash(self, hash):
    self.__hash = hash
  # 파일 사이즈 프로퍼티
  @property
  def filesize(self):
    return self.__filesize
  @filesize.setter
  def filesize(self, filesize):
    # websocket에서는 string type으로 데이터가 오기 때문에 int형으로 변환
    self.__filesize = int(filesize)
  # 파일 데이터 프로퍼티
  @property
  def data(self):
    return self.__data
  @data.setter
  def data(self, data):
    self.__data = data
  # 파일 데이터를 연속적으로 추가하는 함수
  def add_data(self, data):
    self.__data += (data)
  # 파일 전송이 끝났는지 확인하는 함수
  def is_complate(self):
    # 다운 받은 파일 크기와 요청된 파일 크기가 같으면 종료
    return self.__filesize == len(self.__data)
  # base64로 된 데이터를 파일로 저장하는 함수
  def save(self):
    # string을 byte로 변환(base64는 ascii코드로 구성되어 있음)
    #byte = self.__data.encode("ASCII")
    # byte64를 binary로 디코딩
    #byte = base64.b64decode(byte)
    # 파일 IO 오픈
    with open(self.path+self.__hash, "wb") as handle:
      
      # 파일 작성
      handle.write(self.__data)
    
    # 콘솔 출력
    print("craete file - "+self.path+self.__hash)
    
 
# 웹 소켓 클라이언트가 접속이 되면 호출된다.
async def accept(websocket):
  # 데이터 정보에 관한 클래스 할당
  path="../received_files/"
  node = Node(path)
  do_predict = predict.do_predict(path)
  num=0
  # 무한 루프, 파일 전송이 끝나면 종료한다.
  while True:
    # cmd를 받는다.
    cmd = await websocket.recv()
    print(cmd)
    # 처음 접속시 웹소켓에서 START 명령어가 온다.
    if cmd == 'START':
      # 파일 이름을 요청한다.
      await websocket.send("FILENAME")
    elif cmd=='FILENAME':
      filename=await websocket.recv()
      print(filename)
      await websocket.send("HASH")
    # 파일 이름에 대한 명령어가 오면,
    elif cmd == 'HASH':
      # 파일 이름을 받는다.
      node.hash= await websocket.recv()
      do_predict.hash=node.hash
      print("\n\n"+node.hash)
      # 파일 사이즈를 요청한다.
      await websocket.send("FILESIZE")
    # 파일 사이즈에 대한 명령어가 오면
    elif cmd == 'FILESIZE':
      # 파일 사이즈를 설정한다.
      node.filesize = await websocket.recv()
      print(node.filesize)
      # 파일 데이터를 요청한다.
      await websocket.send("DATA")
    # 파일 데이터에 대한 명령어가 오면
    elif cmd == 'DATA':
      # 파일을 받아서 데이터를 추가한다.
      node.add_data(await websocket.recv())
      # 파일 전송이 끝나지 않으면
      if node.is_complate() == False:
        # 파일 데이터를 요청한다.
        await websocket.send("DATA")
      else:
        # 파일 전송이 끝나면 저장한다.
        node.save()
        # 웹 소켓을 닫는다.
        await websocket.close()
        
        # 파일 시그니처 검사
        try:
          f, num=filemagic.f_magic(node.hash)
        except:
          print("file magic errer!!")
          up.vaiscanDB().setprogress(node.hash,-1)
          break
        up.vaiscanDB().set(filename,node.filesize,node.hash,f)
        
        # 파일이 실제로 실행파일일 경우
        if num==True:
          # 예측함수 실행
          do_predict.predict_file()
        else:
          up.vaiscanDB().setrisk(node.hash,0)
          up.vaiscanDB().setprogress(node.hash,100)
          
        # 종료!
        break

start_server = websockets.serve(accept, "172.20.10.5", 8282,  max_size=104857600)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()

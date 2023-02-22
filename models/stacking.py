# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score, cross_validate
import warnings
np.set_printoptions(suppress=True)
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
warnings.simplefilter(action='ignore', category=FutureWarning)
#tf.enable_eager_execution()
#np.set_printoptions(precision=8, suppress=True)

class Classifiers():
    
    def __init__(self, X, Y):
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(X,Y, test_size=0.2, random_state=0)
        
    def do_DNN(self):

        # datafram 은 .index[] 형태로 호출
        dataset = tf.data.Dataset.from_tensor_slices((self.x_train.values,self.y_train.values))

        model = tf.keras.models.Sequential()    
        model.add(tf.keras.layers.Input(shape=(168,))) # Input tensor
        model.add(tf.keras.layers.Dense(units=256, activation='sigmoid')) # hidden layer 1
        model.add(tf.keras.layers.Dropout(0.5))
        model.add(tf.keras.layers.Dense(units=1024, activation='relu')) #hidden layer 2
        model.add(tf.keras.layers.Dropout(0.5))
        model.add(tf.keras.layers.Dense(units=1024, activation='relu')) #hidden layer 3
        model.add(tf.keras.layers.Dropout(0.5))
        model.add(tf.keras.layers.Dense(units=256, activation='relu')) #hidden layer 4
        model.add(tf.keras.layers.Dropout(0.5))
        model.add(tf.keras.layers.Dense(units=128, activation='relu')) #hidden layer 4
        model.add(tf.keras.layers.Dropout(0.5))
        model.add(tf.keras.layers.Dense(units=1, activation='sigmoid')) #output layer 

        adam = tf.keras.optimizers.Adam(learning_rate=0.001)
        model.compile(optimizer=adam,
            loss='binary_crossentropy',
            metrics=['accuracy'])
        
        #print(model.summary())
        
        train_dataset=dataset.shuffle(len(self.x_train)).batch(64)

        model.fit(train_dataset,epochs=13)

        test_loss, test_accuracy = model.evaluate(self.x_test,self.y_test)
        print('\n\nTest Loss {}, Test Accuracy {}'.format(test_loss, test_accuracy))

        print("\n\n predict!!!\n")
        test=self.x_test.values.tolist()
        print("test:",test[0])
        y_pred=model.predict(test)
        y_pred = y_pred.flatten() # 차원 펴주기
        
        y_pred = np.where(y_pred > 0.4, 1 , 0) #0.5보다크면 1, 작으면 0
        
        print("\n DNN Models :")
        print("accuracy_score : ",accuracy_score(self.y_test, y_pred))
        j=0
        for i in range(50):
            print("test num %d real y : %d"%(i, self.y_test.iloc[i]))
            print("test num %d pred y : %f"%(i, y_pred[i]))
            print("")
        
        model.save('/home/jodaegeun/vaiscan-box-static-ai/models/saved_models/rlast_model.h5', overwrite=True, save_format="h5")


    def do_SVC(self):
        print("svc in")
        nfolds=10
        svm_parameters = [{'kernel' : ['rbf'],'C':[0.1,1,10, 100, 1000], 'gamma':[1, 0.1, 0.01, 0.001, 0.0001]}]

        #사이킷런에서 제공하는 GridSearchCV를 사용해 최적의 파라미터를 구함
        clf = GridSearchCV(SVC(verbose=True), svm_parameters, cv=nfolds, scoring='accuracy') # estimator, param_grid, cross-validation
        print("end gridsearchcv")
        clf.fit(self.x_train, self.y_train.values.ravel())
        print(clf.best_params_) #최고 점수를 낸 파라미터 출력
        #model=SVC(C=10,gamma=1e-06, kernel='rbf',verbose=True)
#         model = SVC(C=10, cache_size=200, class_weight=None, coef0=0.0,
#   decision_function_shape='ovr', degree=3, gamma=5, kernel='rbf',
#   max_iter=-1, probability=True, random_state=None, shrinking=True,
#   tol=0.001, verbose=True) 
        
#         model.fit(self.x_train, self.y_train)
#         y_pred = model.predict(self.x_test)
#         # y_pred = y_pred.flatten() # 차원 펴주기
#         # y_pred = np.where(y_pred > 0.5, 1 , 0) #0.5보다크면 1, 작으면 0
#         # 성능 평가
#         #print("dd: ",model.oob_score_) ## Out-of-bag 성능 평가 점수
#         #print('정확도 : ', model.score(self.x_test,self.y_test)) ## 테스트 성능 평가 점수(Accuracy)
#         print("\n SVC Models :")
#         print("accuracy_score : ",accuracy_score(self.y_test, y_pred))
#         for i in range(10):
#             print("test num %d real y : %d"%(i, self.y_test.iloc[i]))
#             print("test num %d pred y : %d"%(i, y_pred[i]))
#             print("")
            
    def do_all(self):
        self.do_DNN()
        #self.do_SVC()
    

# PE 특징 데이터 로드
pe_nor = pd.read_csv('./normal_pe.csv')
#pe_mal = pd.read_csv('./malware_pe.csv')
pe_mal = pd.read_csv('./tmpmalware.csv')
pe_all = pd.concat([pe_nor, pe_mal])  # 10004 x 72 -> 각종 데이터 지우고 68
ngram = pd.read_csv('./tmpngram.csv')   # 10004 x 103 -> 각종 데이터 지우고 100   
#print("pe_all : ",pe_all.shape)
#print("ngram : ",ngram.shape)

# SHA256을 기준으로 정렬 
pe_all=pe_all.sort_values(by=['SHA256'])
ngram=ngram.sort_values(by=['SHA256'])

pe_all = pe_all.drop(['filename', 'SHA256', 'packer_type','class'], 1) # 파일이름, SHA256, packer_type 열 제거
ngram = ngram.drop(['filename', 'SHA256'], 1) # 파일이름, SHA256, packer_type 열 제거

# 인덱스 초기화
pe_all = pe_all.reset_index(drop=True)
ngram = ngram.reset_index(drop=True)

# pe_all 과 ngram 을 열기준 병합 -> 10004 X 169
X=pd.concat([pe_all, ngram], axis=1)
#X_tmp=pe_all
print("all : ",X.shape)
# class( 결과값 ) 을 따로 분리
Y=X.pop('class')

# # 혹시 영향을 미칠지 모를 속성이름 제거
# Y = Y_tmp[1:]
# X = X_tmp[1:]

models=Classifiers(X,Y)

# 학습모델 실행
models.do_all()


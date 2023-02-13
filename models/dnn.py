# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import tensorflow as tf
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import warnings
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
warnings.simplefilter(action='ignore', category=FutureWarning)
#tf.enable_eager_execution()
#np.set_printoptions(precision=8, suppress=True)

def DNN(X,Y,innum):

    if innum==68:
        print("pe_header dnn")
    if innum==100:
        print("ngram dnn")

    x_train, x_test, y_train, y_test = train_test_split(X,Y, test_size=0.3, random_state=0)

    # datafram 은 .index[] 형태로 호출
    dataset = tf.data.Dataset.from_tensor_slices((x_train.values,y_train.values))
    
    model = tf.keras.models.Sequential()    
    model.add(tf.keras.layers.Input(shape=(innum,))) # Input tensor
    model.add(tf.keras.layers.Dense(units=128, activation='sigmoid')) # hidden layer 1
    model.add(tf.keras.layers.Dense(units=1024, activation='relu')) #hidden layer 2
    model.add(tf.keras.layers.Dropout(0.5))
    model.add(tf.keras.layers.Dense(units=1024, activation='relu')) #hidden layer 3
    model.add(tf.keras.layers.Dropout(0.5))
    model.add(tf.keras.layers.Dense(units=128, activation='relu')) #hidden layer 4
    model.add(tf.keras.layers.Dense(units=1, activation='sigmoid')) #output layer 

    adam = tf.keras.optimizers.Adam(learning_rate=0.0001)
    model.compile(optimizer=adam,
        loss='binary_crossentropy',
        metrics=['accuracy'])
    
    train_dataset=dataset.shuffle(len(x_train)).batch(128)

    model.fit(train_dataset,epochs=20)

    test_loss, test_accuracy = model.evaluate(x_test,y_test)
    print('\n\nTest Loss {}, Test Accuracy {}'.format(test_loss, test_accuracy))

    print("\n\n predict!!!\n")
    pred=model.predict(x_test)

    for i in range(40):
        print("test num %d real y : %d"%(i, y_test.iloc[i]))
        print("test num %d pred y : %f"%(i, pred[i]))
        print("")


# PE 특징 데이터 로드
pe_nor = pd.read_csv('./normal_pe.csv')
pe_mal = pd.read_csv('./malware_pe.csv')
pe_all = pd.concat([pe_nor, pe_mal])  # 10004 x 72 -> 각종 데이터 지우고 68
#print("pe_all : ",pe_all.shape)

X_tmp = pe_all.drop(['filename', 'SHA256', 'packer_type'], 1) # 파일이름, SHA256, packer_type 열 제거
Y_tmp=X_tmp.pop('class')

Y = Y_tmp[1:]
X = X_tmp[1:]
# pe_header : 68
DNN(X,Y,68)

# ngram 특징 데이터 로드

ngram = pd.read_csv('./ngram.csv')   # 10004 x 103 -> 각종 데이터 지우고 100
ngram=sklearn.utils.shuffle(ngram)
#print("ngram : ",ngram.shape)
X_tmp = ngram.drop(['filename', 'SHA256'], 1) # 파일이름, SHA256, packer_type 열 제거
Y_tmp=X_tmp.pop('class')

Y = Y_tmp[1:]
X = X_tmp[1:]
# ngram = 100
DNN(X,Y,100)
# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
import seaborn as sns

import matplotlib.pyplot as plt
import model
import operator
import cnn_model

from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder


def hot_encoding(df):

    enc = OneHotEncoder(handle_unknown='ignore', sparse=False)
    lab = LabelEncoder()    

    dat = df['packer_type']
    lab.fit(dat)
    lab_dat = lab.transform(dat)

    df = df.drop('packer_type', 1)
    lab_dat = lab_dat.reshape(len(lab_dat), 1)
    enc_dat = enc.fit_transform(lab_dat)
    enc_dat = pd.DataFrame(enc_dat, columns=lab.classes_)

    df = df.reset_index(drop=True)
    enc_dat = enc_dat.reset_index(drop=True)
    
    df = pd.concat([df, enc_dat], axis=1)

    return df, lab.classes_

cols = ["svm", "randomforest", "naivebayes", "dnn"]
df = pd.DataFrame(columns=cols)

# PE 특징 데이터 로드
pe_nor = pd.read_csv('./normal_pe.csv')
pe_mal = pd.read_csv('./malware_pe.csv')
pe_all = pd.concat([pe_nor, pe_mal]) # 10004 x 72

# ngram 특징 데이터 로드
gram_all = pd.read_csv('./ngram.csv')   # 10004 x 103

print (pe_all.shape, gram_all.shape)

pe_all_tmp = pe_all  # 데이터 백업
pe_all = pe_all.drop(['filename', 'SHA256', 'packer_type'], 1) # 파일이름, SHA256, packer_type 열 제거

Y = pe_all['class'] # 카테고리 열을 별도로 추출
X = pe_all.drop('class', 1) # 카테고리 열 제거
Y_bak = Y # 뒤에서 진행할 특징 선택 작업을 위해 데이터 백업
#print "Y : ",Y
# print "X : ",X

#Y = Y_tmp[1:]
#X = X_tmp[1:]
#print "Y2 : ",Y2
# print "X : ",X

md_pe = model.Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
df.loc['pe'] = md_pe.do_all()  # 분류 모델 학습

print (X.shape, Y.shape)  # X: 10004 x 68   / Y: 10004 x 1

pe_all = pe_all_tmp
pe_all = pe_all.drop(['filename', 'SHA256'], 1)  # 파일이름, SHA256 열 제거

pe_all, classes_ = hot_encoding(pe_all)  # One-Hot 인코딩 변환

print ("Found %d Categories in packer-type") % len(classes_)
# dataset for modeling
pe_all = pd.DataFrame(pe_all)
pe_all.to_csv('pe_packer.csv', index=False)

Y = pe_all['class']  # 카테고리 열을 별도로 추출
X = pe_all.drop('class', axis=1)


md_pe_packer = model.Classifiers(X, Y) # 학습 모듈 인스턴스 초기화
df.loc['pe_packer'] = md_pe_packer.do_all() # 분류 모델 학습
 
print (X.shape, Y.shape) # X: 937 x 87 / Y: 937 x 1

gram_all = gram_all.drop(['filename', 'SHA256'], 1) # 파일이름, SHA256 열 제거

Y = gram_all['class'] # 카테고리 열을 별도로 추출
X = gram_all.drop('class', 1) # 카테고리 열 제거
Y_bak = Y # 뒤에서 진행할 특징 선택 작업을 위해 데이터 백업

md_gram = model.Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
df.loc['ngram'] = md_gram.do_all()  # 분류 모델 학습

print (X.shape, Y.shape)  # X: / Y: 

# cnn image 

cn = cnn_model.CNN_tensor() 
cn.load_images()
cnn_acc = cn.do_cnn()

avg_pe = df.loc['pe'].mean(axis=0)
avg_pe_packer = df.loc['pe_packer'].mean(axis=0)
avg_ngram = df.loc['ngram'].mean(axis=0)

df['cnn'] = [0,0,0,cnn_acc]
df['avg'] = [avg_pe,avg_pe_packer, avg_ngram, cnn_acc]

print 'df :',df
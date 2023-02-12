# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
import seaborn as sns
import tensorflow as tf

import matplotlib.pyplot as plt
import model
import operator
import one_hotincode
import cnn_model

cols = ["svm", "randomforest", "naivebayes", "dnn"]
df = pd.DataFrame(columns=cols)

# PE 특징 데이터 로드
pe_nor = pd.read_csv('normal_pe.csv')
pe_mal = pd.read_csv('malware_pe.csv')
pe_all = pd.concat([pe_nor, pe_mal])  # 10004 x 72

# ngram 특징 데이터 로드
gram_all = pd.read_csv('ngram.csv')   # 10004 x 103

print pe_all.shape, gram_all.shape

print "[*] Before Filtering NA values: ", pe_all.shape
NA_values = pe_all.isnull().values.sum()
print "[*] Missing Values: ", NA_values
pe_all = pe_all.dropna()
print "[*] After Filtering NA values: ", pe_all.shape

pe_all_tmp = pe_all  # 데이터 백업
pe_all = pe_all.drop(['filename', 'SHA256', 'packer_type'], 1) # 파일이름, SHA256, packer_type 열 제거
target=pe_all.pop('class')
print"df : ",pe_all.values," class : ",target.values
dataset = tf.data.Dataset.from_tensor_slices((pe_all.values, target.values))
for feat, targ in dataset.take(1):
  print ('Features: {}, Target: {}'.format(feat, targ))

train_dataset=dataset.shuffle(len(pe_all)).batch(128)

"""

pe_all = pd.DataFrame(pe_all)
Y = pe_all['class'] # 카테고리 열을 별도로 추출
X = pe_all.drop('class', 1) # 카테고리 열 제거
Y_bak = Y # 뒤에서 진행할 특징 선택 작업을 위해 데이터 백업
md_pe = model.Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
print 'hello'
df.loc['pe'] = md_pe.do_all()  # 분류 모델 학습
print 'hello2'
print X.shape, Y.shape  # X: 10004 x 68 / Y: 10004 x 1
"""
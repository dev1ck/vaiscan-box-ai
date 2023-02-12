# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import seaborn as sns

import matplotlib.pyplot as plt
import model
import operator
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
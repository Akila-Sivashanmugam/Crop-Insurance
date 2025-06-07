import json
import csv
import pandas as pd
import numpy as np
import shutil

shutil.copy("static/weather.csv","static/weather_data.csv")
responsetext="https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/10.783537,78.775118/2023-12-01/2023-12-05?unitGroup=metric&include=days&key=8STCAMRSRTEZ77JA2XRP7FMNC&contentType=csv"

cdata=[]
data1 = pd.read_csv(responsetext, header=0)
for ss in data1.values:
    dt=[]
    print(ss[0])
    '''dt.append(ss[0])
    dt.append(ss[1])
    dt.append(ss[2])
    dt.append(ss[3])
    dt.append(ss[4])
    dt.append(ss[5])
    dt.append(ss[6])
    dt.append(ss[7])
    dt.append(ss[8])
    dt.append(ss[9])
    dt.append(ss[10])
    dt.append(ss[11])
    dt.append(ss[12])
    dt.append(ss[13])
    dt.append(ss[14])
    dt.append(ss[15])
    dt.append(ss[16])
    dt.append(ss[17])
    dt.append(ss[18])
    dt.append(ss[19])
    dt.append(ss[20])
    dt.append(ss[21])
    dt.append(ss[22])
    dt.append(ss[23])
    dt.append(ss[24])
    dt.append(ss[25])
    dt.append(ss[26])
    dt.append(ss[27])
    dt.append(ss[28])
    dt.append(ss[29])
    dt.append(ss[30])
    dt.append(ss[31])
    dt.append(ss[32])'''
    with open("static/weather_data.csv",'a',newline='') as outfile:
        writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(ss)

    cdata.append(dt)


#with open("static/weather_data.csv",'a',newline='') as outfile:
#        writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
#        writer.writerow(cdata)

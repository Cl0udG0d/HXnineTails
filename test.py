import shutil,os
from config import Root_Path
from subDomainsBrute import subDomainsBruteMain
from Subfinder.subfinderMain import subfinderScan
import config
import re
# def delModel():
#     saveFolderList=['saveCplus','saveJS','saveSub','saveXray']
#     for tempFolder in saveFolderList:
#         shutil.rmtree("{}\\save\\{}".format(Root_Path,tempFolder))
#         os.mkdir("{}\\save\\{}".format(Root_Path,tempFolder))
#     return

def test(target,filename):
    try:
        subfinderScan(target,filename)
    except Exception as e:
        print(e)
        pass
'''
mergeReport()函数
    功能：合并报告
    传入参数：目标保存文件名 filename
'''
def mergeReport(filename):
    reportList=os.listdir(config.Xray_temp_report_path)
    resultList=[]
    pattern = re.compile(r'<script class=\'web-vulns\'>(.*?)</script>')

    for report in reportList:
        tempReport="{}\\{}".format(config.Xray_temp_report_path,report)
        with open(tempReport,'r',encoding='utf-8') as f:
            temp=f.read()
            result=pattern.findall(temp)
            resultList+=result
    print(resultList)
    return

def main():
    mergeReport('aa')
    return

if __name__ == '__main__':
    main()
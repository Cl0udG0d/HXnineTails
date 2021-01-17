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

def cleanTempXrayReport():

    shutil.rmtree("{}".format(config.Xray_temp_report_path))
    os.mkdir("{}".format(config.Xray_temp_report_path))
    return

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

    context=""
    with open("{}\\modelFile.html".format(config.Root_Path),'r',encoding='utf-8') as f:
        context+=f.read()
    for result in resultList:
        result="<script class=\'web-vulns\'>{}</script>".format(result)
        context+=result
    with open("{}\\{}.html".format(config.Xray_report_path,filename),'w',encoding='utf-8') as f:
        f.write(context)
    cleanTempXrayReport()
    return

def main():
    mergeReport('aa')
    return

if __name__ == '__main__':
    main()
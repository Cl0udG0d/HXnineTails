import re
import shutil

import requests
from subDomainsBrute import subDomainsBruteMain
from Sublist3r import Sublist3rMain
from Subfinder import subfinderMain
from OneForAll import oneforallMain
from CScan import CScan
from JSmessage.jsfinder import JSFinder
import config
from ServerJiang.jiangMain import SendNotice
import os
import hashlib
'''
init() 扫描初始化函数
功能：
    初始化保存文件目录
'''
def init():
    try:
        if not os.path.exists(config.Save_path):
            os.makedirs(config.Save_path)
            os.makedirs(config.Xray_report_path)
            os.makedirs(config.Xray_temp_report_path)
            os.makedirs(config.CScan_report_path)
            os.makedirs(config.Sub_report_path)
            os.makedirs(config.Temp_path)
            os.makedirs(config.JS_report_path)
    except Exception as e:
        print(e)
        exit(0)
    print("初始化完成")
    return

'''
cleanTempXrayReport()函数
    功能：删除xray临时报告目录下的全部文件
'''
def cleanTempXrayReport():
    shutil.rmtree("{}".format(config.Xray_temp_report_path))
    os.mkdir("{}".format(config.Xray_temp_report_path))
    return

'''
函数 checkXrayVersion()
功能:
    检测xray为社区版还是专业版
    专业版返回 true
    社区版返回 false
'''
def checkXrayVersion(content):
    if "snapshot" in content:
        return False
    return True

'''
函数 advancedMergeReport(resultList)
功能:
    xray 专业版报告合并函数
'''
def advancedMergeReport(resultList):
    context = ""
    requestMd5Set = set()
    with open("{}\\advancedModelFile.html".format(config.Root_Path), 'r', encoding='utf-8') as f:
        context += f.read()
    for result in resultList:
        tempResultDict = eval(result)
        tempDetailRequest = tempResultDict["detail"]["request"]
        tempRequestMd5 = hashlib.md5(tempDetailRequest.encode('utf-8')).hexdigest()
        if tempRequestMd5 not in requestMd5Set:
            requestMd5Set.add(tempRequestMd5)

            result = "<script class=\'web-vulns\'>webVulns.push({})</script>".format(result)
            context += result
    return context

'''
函数 communityMergeReport(resultList)
功能:
    xray 社区版报告合并函数
'''
def communityMergeReport(resultList):
    context = ""
    requestMd5Set=set()
    with open("{}\\communityModelFile.html".format(config.Root_Path), 'r', encoding='utf-8') as f:
        context += f.read()
    for result in resultList:
        tempResultDict = eval(result)
        tempDetailRequest = tempResultDict["detail"]["snapshot"][0][0]
        tempRequestMd5 = hashlib.md5(tempDetailRequest.encode('utf-8')).hexdigest()
        if tempRequestMd5 not in requestMd5Set:
            requestMd5Set.add(tempRequestMd5)

            result = "<script class=\'web-vulns\'>webVulns.push({})</script>".format(result)
            context += result
    return context


'''
mergeReport()函数
    功能：合并报告
    传入参数：目标保存文件名 filename
    其中需要使用集合这种数据结构去除重复漏洞,其判断依据为：xray Request md5值
'''
def mergeReport(filename):
    reportList=os.listdir(config.Xray_temp_report_path)
    print(reportList)
    if len(reportList)==0:
        return

    resultList=[]

    pattern = re.compile(r'<script class=\'web-vulns\'>webVulns.push\((.*?)\)</script>')

    for report in reportList:
        tempReport="{}\\{}".format(config.Xray_temp_report_path,report)
        with open(tempReport,'r',encoding='utf-8') as f:
            temp=f.read()
            result=pattern.findall(temp)
            resultList+=result
    tempResult=eval(resultList[0])
    if 'snapshot' in tempResult["detail"]:
        context = communityMergeReport(resultList)
    else:
        context=advancedMergeReport(resultList)
    with open("{}\\{}.html".format(config.Xray_report_path,filename),'w',encoding='utf-8') as f:
        f.write(context)
        cleanTempXrayReport()

    return


'''
transferJSFinder(url,filename)函数
参数：
    url 待扫描的URL
    filename 实际上为待扫描URL的MD5值，作为输出文件名的一部分

作用：
    调用并魔改JSFinder代码
输出：
    从JS中获取到的URL和subdomain
    输出文件名为：
        output_url_filename="url_"+outputfilename
        output_subdomain_filename="subdomain"+outputfilename
'''
def transferJSFinder(url ,filename):
    try:
        urls =JSFinder.find_by_url(url)
        JSFinder.giveresult(urls ,url ,filename)
    except Exception as e:
        print("JSFinder ERROR!")
        print(e)
        pass

'''
transferCScan(url,filename) 函数
'''
def transferCScan(url ,filename):
    try:
        CScan.CScanConsole(url, filename)
    except Exception as e:
        print("C段扫描出错!")
        print(e)
        pass


'''
subScan(target) 函数
参数：
    target 待扫描的URL
    filename 扫描目标 target 的对应md5之后的十六进制
作用：
    对输入的target进行子域名的收集，并将结果存储到队列sub_queue里
输出：
    结果保存在队列sub_queue里面，传递给队列去重函数
子域名收集整合模块：
    OneForAll
    ARL
    Knock
    subDomainsBrute
    Subfinder
    Sublist3r
    ...(可根据自己需要自行添加
'''
def subScan(target ,filename):
    '''
    调用四个子域名搜集模块，并将结果保存在 sub_queue 里面
    使用 queueDeduplication 进行子域名 -> 网址的转换 ，同时检测存活
    :param target:
    :param filename:
    :return:
    '''
    try:
        oneforallMain.OneForAllScan(target)
    except Exception as e:
        print(e)
        pass
    try:
        subDomainsBruteMain.subDomainsBruteScan(target,filename)
    except Exception as e:
        print(e)
        pass
    try:
        Sublist3rMain.Sublist3rScan(target)
    except Exception as e:
        print(e)
        pass
    try:
        subfinderMain.subfinderScan(target,filename)
    except Exception as e:
        print(e)
        pass
    try:
        queueDeduplication(filename)
    except Exception as e:
        print(e)
        pass


'''
urlCheck(url) 函数
参数：
    url 需要检测存活性的URL
作用：
    url存活性检测
输出：
    返回是否的布尔值
'''
def urlCheck(target):
    try:
        print("now url live check: {}".format(target))
        rep = requests.get(target, headers=config.GetHeaders(), timeout=2, verify=False)
        if rep.status_code != 404:
            return True
    except Exception as e:
        # print(e)
        return False
    return False


'''
queueDeduplication(filename) 队列去重函数
参数：
    filename 扫描目标 target 的对应md5之后的十六进制
作用：
    对子域名队列sub_queue里面的元素进行去重处理
输出：
    结果保存在target_queue队列里面，存储到saveSub文件夹下对应filename.txt中并且成为待扫描的目标
'''
def queueDeduplication(filename):
    Sub_report_path =config.Sub_report_path +filename +".txt"
    sub_set =set()
    while not config.sub_queue.empty():
        target =config.sub_queue.get()
        target=addHttpHeader(target)
        sub_set.add(target)
    length=len(sub_set)
    with open(Sub_report_path, 'a+') as f:
        while len(sub_set) != 0:
            target = sub_set.pop()
            if urlCheck(target):
                config.target_queue.put(target) # 存活的url
                print("now save :{}".format(target))
                f.write("{}\n".format(target))
    print("queueDeduplication End~")
    SendNotice("子域名搜集完毕，数量:{}，保存文件名:{}".format(length,filename))
    return


'''
对没有添加http的url添加http
'''
def addHttpHeader(target):
    pattern = re.compile(r'^http')
    if not pattern.match(target.strip()):
        target = "https://" + target.strip()
    else:
        target = target.strip()
    return target


'''
checkBlackList(url)
检测目标URL是否在黑名单列表中
'''
def checkBlackList(url):
    for i in config.blacklist:
        if i in url:
            return False
    return True



def main():
    a=set()
    a.add(1)
    a.add(2)
    print(list(a))
    return

if __name__ == '__main__':
    main()
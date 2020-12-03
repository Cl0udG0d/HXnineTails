from JSmessage.jsfinder import JSFinder
import hashlib
from CScan import CScan
import re
from crawlergo import crawlergoMain
from Xray import pppXray
from OneForAll import oneforallMain
import config
import requests
from subDomainsBrute import subDomainsBruteMain
from Sublist3r import Sublist3rMain
from Subfinder import subfinderMain
'''
扫描控制主函数
参数：
    url
    格式如：https://www.baidu.com

扫描联动工具：
    JS方面：
        JSfinder
    漏洞扫描：
        360 0Kee-Team 的 crawlergo动态爬虫 -> Xray高级版
    C段：
        自写C段扫描函数
'''


'''
transferJSFinder(url,filename,path)函数
参数：
    url 待扫描的URL
    filename 实际上为待扫描URL的MD5值，作为输出文件名的一部分
    传入的path为保存文件项目的绝对路径，方便保存到指定的文件夹下
    
作用：
    调用并魔改JSFinder代码
输出：
    从JS中获取到的URL和subdomain
    输出文件名为：
        output_url_filename="url_"+outputfilename
        output_subdomain_filename="subdomain"+outputfilename
'''
def transferJSFinder(url,filename,path):
    try:
        urls=JSFinder.find_by_url(url)
        JSFinder.giveresult(urls,url,filename,path)
    except Exception as e:
        print("JSFinder ERROR!")
        print(e)
        pass

'''
transferCScan(url,filename,path) 函数
'''
def transferCScan(url,filename,path):
    try:
        CScan.CScanConsole(url, filename, path)
    except Exception as e:
        print("C段扫描出错!")
        print(e)
        pass

'''
vulScan(target) 函数
参数：
    target 待扫描的URL 
作用：
    联动 crawlergo对页面爬取 + 去重 + Xray扫描
输出：
    输出Xray扫描报告至 save文件夹下的saveXray文件夹
'''
def vulScan(target):
    pattern = re.compile(r'^http')
    #进行URL参数补充
    if not pattern.match(target.strip()):
        target = "https://" + target.strip()
    else:
        target = target.strip()

    req_list=crawlergoMain.crawlergoGet(target)
    req_queue=crawlergoMain.removeDuplicates(req_list)
    pppXray.pppGet(req_queue)
    print("vulScan End~")

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
def subScan(target,filename):
    try:
        oneforallMain.OneForAllScan(target)
    except Exception as e:
        print(e)
        pass
    try:
        subDomainsBruteMain.subDomainsBruteScan(target)
    except Exception as e:
        print(e)
        pass
    try:
        Sublist3rMain.Sublist3rScan(target)
    except Exception as e:
        print(e)
        pass
    try:
        subfinderMain.subfinderScan(target)
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
def urlCheck(url):
    try:
        print("https://{}".format(url))
        rep = requests.get("https://" + url, headers=config.GetHeaders(), timeout=2, verify=False)
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
    结果保存在target_queue队列里面，存储到saveSub文件夹下对应filenamed.txt中并且成为待扫描的目标
'''
def queueDeduplication(filename):
    Sub_report_path=config.Sub_report_path+filename+".txt"
    sub_set=set()
    while not config.sub_queue.empty():
        target=config.sub_queue.get()
        sub_set.add(target)
    with open(Sub_report_path, 'a') as f:
        while len(sub_set) != 0:
            target = sub_set.pop()
            if urlCheck(target):
                config.target_queue.put(target)
                f.write("{}\n".format(target))
    print("queueDeduplication End~")
    return


'''
花溪九尾主函数
foxScan(target) 函数
参数：
    target 待扫描的URL 示例：baidu.com 
作用：

                                          -> JS敏感信息提取 
    对输入的目标进行子域名收集 -> 存储去重  -> crawlergo动态爬虫 -> Xray高级版漏洞扫描
                                          -> C段信息收集
    
输出：
    对应阶段性结果都会保存在save 文件夹下对应的目录里面
'''
def foxScan(target):
    filename=hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start foxScan {}\nfilename : {}\n".format(target,filename))
    subScan(target,filename)
    while not config.target_queue.empty():
        current_target=config.target_queue.get()
        crawlergoMain.crawlergoGet(current_target)
    while not config.xray_queue.empty():
        current_target=config.xray_queue.get()
        pppXray.xrayScan(current_target,filename)
    print("InPuT T4rGet {} Sc3n EnD#".format(target))
    return

'''
单元测试代码
进行子域名收集和动态爬虫+xray扫描的测试
'''
def main():
    target='baidu.com'
    foxScan(target)
    # subDomainsBruteMain.subDomainsBruteScan('baidu.com')
    return


if __name__ == '__main__':
    main()
from JSmessage.jsfinder import JSFinder
import os
import hashlib
from CScan import CScan
import re
from crawlergo import crawlergoMain
from Xray import pppXray

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

def foxScan(url):
    filename=hashlib.md5(url).hexdigest()
    return

'''
单元测试代码
'''
def main():
    target="https://xueshu.baidu.com"
    vulScan(target)
    return


if __name__ == '__main__':
    main()
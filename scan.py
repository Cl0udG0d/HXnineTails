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
import sys
import getopt
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
def transferJSFinder(url,filename):
    try:
        urls=JSFinder.find_by_url(url)
        JSFinder.giveresult(urls,url,filename)
    except Exception as e:
        print("JSFinder ERROR!")
        print(e)
        pass

'''
transferCScan(url,filename) 函数
'''
def transferCScan(url,filename):
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
def subScan(target,filename):
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
    结果保存在target_queue队列里面，存储到saveSub文件夹下对应filenamed.txt中并且成为待扫描的目标
'''
def queueDeduplication(filename):
    Sub_report_path=config.Sub_report_path+filename+".txt"
    sub_set=set()
    while not config.sub_queue.empty():
        target=config.sub_queue.get()
        pattern = re.compile(r'^http')
        # 进行URL参数补充 子域名 -> 网址
        if not pattern.match(target.strip()):
            target = "https://" + target.strip()
        else:
            target = target.strip()
        sub_set.add(target)
    with open(Sub_report_path, 'a') as f:
        while len(sub_set) != 0:
            target = sub_set.pop()
            if "baiduspider" not in target and urlCheck(target):
                config.target_queue.put(target)
                print("now save :{}".format(target))
                f.write("{}\n".format(target))
    print("queueDeduplication End~")
    return

'''
oneFoxScan(target)函数
    针对某一目标网址进行扫描而非对某一资产下的网址进行扫描，输入案例： www.baidu.com
    扫描流程: 输入URL正确性检查+crawlergo+xray
'''
def oneFoxScan(target):
    pattern = re.compile(r'^http')
    if not pattern.match(target.strip()):
        target = "https://" + target.strip()
    else:
        target = target.strip()
    filename = hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start foxScan {}\nfilename : {}\n".format(target, filename))
    try:
        req_pool = crawlergoMain.crawlergoGet(target)
    except Exception as e:
        print(e)
        print("crawlergo error!")
        req_pool=set()
        pass
    # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
    while len(req_pool) != 0:
        # 将 req_pool 里的URL依次弹出并扫描
        try:
            temp_url = req_pool.pop()
            current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
            # 调用 xray 进行扫描并保存
            pppXray.xrayScan(temp_url, current_filename)
        except Exception as e:
            print(e)
            pass
    print("InPuT T4rGet {} Sc3n EnD#".format(target))
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
    print("Start attsrc foxScan {}\nfilename : {}\n".format(target,filename))
    subScan(target,filename)
    #进行子域名搜集
    while not config.target_queue.empty():
        current_target=config.target_queue.get()
        # 对搜集到的目标挨个进行扫描
        req_pool=crawlergoMain.crawlergoGet(current_target)
        #对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
        while len(req_pool)!=0:
            #将 req_pool 里的URL依次弹出并扫描
            temp_url=req_pool.pop()
            current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
            #调用 xray 进行扫描并保存
            pppXray.xrayScan(temp_url, current_filename)
    print("InPuT T4rGet {} Sc3n EnD#".format(target))
    return

'''
foxScanDetail(target)
对于输入SRC进行详细的信息搜集+扫描
耗时很长+为防止遗漏搜集了部分重复信息（不建议使用
作用：
                                                            -> JS敏感信息提取 
    对输入的目标进行子域名收集 -> 存储去重  -> crawlergo动态爬虫 -> Xray高级版漏洞扫描
                                                            -> C段信息收集
输出：
    对应阶段性结果都会保存在save 文件夹下对应的目录里面
'''
def foxScanDetail(target):
    filename=hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start attsrc foxScan {}\nfilename : {}\n".format(target,filename))
    subScan(target,filename)
    #进行子域名搜集
    while not config.target_queue.empty():
        current_target=config.target_queue.get()
        # 对搜集到的目标挨个进行扫描
        req_pool=crawlergoMain.crawlergoGet(current_target)
        #对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
        while len(req_pool)!=0:
            #将 req_pool 里的URL依次弹出并扫描
            try:
                temp_url=req_pool.pop()
                current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
                #调用 xray 进行扫描并保存
                pppXray.xrayScan(temp_url, current_filename)
                transferJSFinder(temp_url,current_filename)
                transferCScan(temp_url,current_filename)
            except Exception as e:
                print(e)
                pass
    print("InPuT T4rGet {} Sc3n EnD#".format(target))
    return

def logo():
    print('''
    
 +-+-+-+-+-+-+-+-+-+-+-+
 |H|X|n|i|n|e|T|a|i|l|s|
 +-+-+-+-+-+-+-+-+-+-+-+
                        v1.0
                        author:春告鳥
                        blog:https://www.cnblogs.com/Cl0ud/
    ''')

'''
单元测试代码
支持三个攻击参数：
    1,-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 输入 https://www.baidu.com
    2,-s --attsrc 对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC  输入 baidu.com
    3,-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 baidu.com
'''
def main(argv):
    logo()
    try:
        opts, args = getopt.getopt(argv, "ha:s:d:", ["attone=", "attsrc=","attdetail="])
    except getopt.GetoptError:
        print('scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:'
              'scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(
                'scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:'
                'scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n')
            sys.exit()
        elif opt in ("-a", "--attone"):
            target = arg
            oneFoxScan(target)
        elif opt in ("-s", "--attsrc"):
            target = arg
            foxScan(target)
        elif opt in ("-d", "--attdetail"):
            target=arg
            foxScanDetail(target)
        else:
            print(
                'scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:'
                'scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n')
            sys.exit()
    return


if __name__ == '__main__':
    main(sys.argv[1:])
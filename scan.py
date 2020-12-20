import hashlib
from crawlergo import crawlergoMain
from Xray import pppXray
import config
import sys
import getopt
import base

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

import threadpool

task_pool=threadpool.ThreadPool(8)

def thpool(temp_url,current_filename):
    requests = threadpool.makeRequests(sayhello, name_list)


def pppFoxScan(filename):
    print("Start pppFoxScan,filename is {}".format(filename))
    try:
        with open(filename, 'r') as f:
            lines=f.readlines()
            for line in lines:
                target=line.strip()
                target=base.addHttpHeader(target)
                config.ppp_queue.put(target)
    except Exception as e:
        print(e)
        pass
    while not config.ppp_queue.empty():
        current_target = config.ppp_queue.get()
        # 对搜集到的目标挨个进行扫描
        req_pool = crawlergoMain.crawlergoGet(current_target)
        req_pool.add(current_target)
        # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
        while len(req_pool) != 0:
            # 将 req_pool 里的URL依次弹出并扫描
            temp_url = req_pool.pop()
            current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
            # 调用 xray 进行扫描并保存
            pppXray.xrayScan(temp_url, current_filename)
    return

'''
oneFoxScan(target)函数
    针对某一目标网址进行扫描而非对某一资产下的网址进行扫描，输入案例： www.baidu.com
    扫描流程: 输入URL正确性检查+crawlergo+xray
'''
def oneFoxScan(target):
    target=base.addHttpHeader(target)
    filename = hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start foxScan {}\nfilename : {}\n".format(target, filename))
    req_pool = crawlergoMain.crawlergoGet(target)
    # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
    req_pool.add(target)
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
                                          
    对输入的目标进行子域名收集 -> 存储去重  -> crawlergo动态爬虫 -> Xray高级版漏洞扫描
                                          
输出：
    对应阶段性结果都会保存在save 文件夹下对应的目录里面
'''
def foxScan(target):
    filename=hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start attsrc foxScan {}\nfilename : {}\n".format(target,filename))
    base.subScan(target,filename)
    #进行子域名搜集
    while not config.target_queue.empty():
        current_target=config.target_queue.get()
        # 对搜集到的目标挨个进行扫描
        req_pool=crawlergoMain.crawlergoGet(current_target)
        req_pool.add(current_target)
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
    base.subScan(target,filename)
    #进行子域名搜集
    while not config.target_queue.empty():
        current_target=config.target_queue.get()
        # 对搜集到的目标挨个进行扫描
        req_pool=crawlergoMain.crawlergoGet(current_target)
        req_pool.add(current_target)
        #对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
        while len(req_pool)!=0:
            #将 req_pool 里的URL依次弹出并扫描
            try:
                temp_url=req_pool.pop()
                current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
                #调用 xray 进行扫描并保存
                pppXray.xrayScan(temp_url, current_filename)
                base.transferJSFinder(temp_url,current_filename)
                base.transferCScan(temp_url,current_filename)
            except Exception as e:
                print(e)
                pass
    print("InPuT T4rGet {} Sc3n EnD#".format(target))
    return



'''
单元测试代码
支持三个攻击参数：
    1,-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 输入 https://www.baidu.com
    2,-s --attsrc 对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC  输入 baidu.com
    3,-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 baidu.com
'''
def main(argv):
    config.logo()
    try:
        opts, args = getopt.getopt(argv, "ha:s:d:r:", ["attone=", "attsrc=","attdetail=","readppp="])
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
        elif opt in ("-r","--readppp"):
            filename=arg
            pppFoxScan(filename)
        else:
            print(
                'scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:'
                'scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n')
            sys.exit()
    return


if __name__ == '__main__':
    main(sys.argv[1:])
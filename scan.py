import click
import getopt
import hashlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

import Hx_config
import base
from ServerJiang.jiangMain import SendNotice
from Xray import pppXray
from crawlergo import crawlergoMain
from waf import WAF

'''
漏洞扫描控制主函数
参数：
    url
    格式如：https://www.baidu.com

扫描联动工具：
    JS发现：
        JSfinder
    xray扫描：
        crawlergo动态爬虫 -> Xray高级版
    C段：
        自写C段扫描函数
'''


def threadPoolDetailScan(temp_url, current_filename):
    pppXray.xrayScan(temp_url, current_filename)
    base.transferJSFinder(temp_url, current_filename)
    base.transferCScan(temp_url, current_filename)
    return


def threadPoolScan(req_pool, filename, target):
    print("req_pool num is {}".format(len(req_pool)))
    thread = ThreadPoolExecutor(max_workers=Hx_config.ThreadNum)
    i = 0
    all_task = []
    while len(req_pool) != 0:
        # 将 req_pool 里的URL依次弹出并扫描
        temp_url = req_pool.pop()
        current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
        # 调用 xray 进行扫描并保存
        # pppXray.xrayScan(temp_url, current_filename)
        i += 1
        one_t = thread.submit(pppXray.xrayScan, temp_url, current_filename)
        all_task.append(one_t)
        if i == 5 or len(req_pool) == 0:
            i = 0
            wait(all_task, return_when=ALL_COMPLETED)
            all_task = []
    base.mergeReport(filename)
    SendNotice("{} 花溪九尾扫描完毕".format(target))


'''
init() 扫描初始化函数
功能：
    初始化保存文件目录
    初始化扫描各参数
    attone=, attsrc=, attdetail=, readppp=, thread=,clean ,plugins=

'''


@click.command()
@click.option('-a', '--attone', help='对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 python3 scan.py -a https://www.baidu.com',
              type=str)
@click.option('-s', '--attsrc', help='对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC python3 scan.py -s baidu.com', type=str)
@click.option('-d', '--attdetail',
              help='对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 python3 scan.py -d baidu.com', type=str)
@click.option('-t', '--thread', default=5, help='线程数量，默认线程为5 如 python3 scan.py -t 10 -a http://testphp.vulnweb.com/ ',
              type=int)
@click.option('-r', '--readppp', help='读取待扫描txt文件，每行一个URL 对取出的每个URL进行 -a 扫描，如 python3 scan.py -t 10 -r target.txt',
              type=str)
@click.option('-c', '--clean', help='对保存的漏洞相关报告进行清理，即清理save文件夹下的文件', is_flag=True)
@click.option('-p', '--plugins', help='自定义xray插件 plugins')
def init(attone, attsrc, attdetail, thread, readppp, clean, plugins):
    """
    花溪九尾 懒狗必备\n
    https://github.com/Cl0udG0d/HXnineTails
    """
    base.init()
    Hx_config.ThreadNum = int(thread)
    if plugins:
        Hx_config.plugins = plugins
    if clean:
        Hx_config.delModel()
        sys.exit()
    if attone:
        oneFoxScan(attone)
    if attsrc:
        foxScan(attsrc)
    if attdetail:
        foxScanDetail(attdetail)
    if readppp:
        pppFoxScan(readppp)
    return


def pppFoxScan(filename):
    print(f"{Hx_config.yellow}Start pppFoxScan,filename is {filename}{Hx_config.end}")
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            for line in lines:
                target = line.strip()
                target = base.addHttpHeader(target)
                Hx_config.ppp_queue.put(target)
    except Exception as e:
        print(e)
        pass
    while not Hx_config.ppp_queue.empty():
        current_target = Hx_config.ppp_queue.get()
        # 对搜集到的目标挨个进行扫描
        currentfilename = hashlib.md5(current_target.encode("utf-8")).hexdigest()
        if base.checkBlackList(current_target):
            req_pool = crawlergoMain.crawlergoGet(current_target)
            if req_pool == 'pass':
                continue
            req_pool.add(current_target)
            # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
            threadPoolScan(req_pool, currentfilename, current_target)
        else:
            print("扫描网址在黑名单内,退出")
    print(f"{Hx_config.yellow}pppFoxScan End~{Hx_config.end}")
    return


'''
oneFoxScan(target)函数
    针对某一目标网址进行扫描而非对某一资产下的网址进行扫描，输入案例： www.baidu.com
    扫描流程: 输入URL正确性检查+crawlergo+xray
'''


def oneFoxScan(target):
    if base.checkBlackList(target):
        target = base.addHttpHeader(target)
        filename = hashlib.md5(target.encode("utf-8")).hexdigest()
        print(f"{Hx_config.yellow}Start foxScan {target}\nfilename : {filename}\n{Hx_config.end}")
        req_pool = crawlergoMain.crawlergoGet(target)
        # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
        req_pool.add(target)
        threadPoolScan(req_pool, filename, target)
    else:
        print("扫描网址在黑名单内,退出")
    print(f"{Hx_config.yellow}InPuT T4rGet {target} Sc3n EnD#{Hx_config.end}")
    return


'''
花溪九尾主函数
foxScan(target) 函数
参数：
    target 待扫描的URL 示例：baidu.com 
作用：
    对输入的目标进行子域名收集 -> 存储去重  -> crawlergo动态爬虫 -> Xray高级版漏洞扫描
                                 ↓
                         ARL资产管理+漏洞扫描
输出：
    对应阶段性结果都会保存在save 文件夹下对应的目录里面
'''


def foxScan(target):
    filename = hashlib.md5(target.encode("utf-8")).hexdigest()
    print(f"{Hx_config.yellow}{Hx_config.green}Start attsrc foxScan {target}\nfilename : {filename}\n{Hx_config.end}")
    base.subScan(target, filename)
    # 将队列列表化并进行子域名搜集
    _ = base.from_queue_to_list(Hx_config.target_queue)
    base.ArlScan(name=target, target=_)  # 启动ARL扫描,第一个参数target表示文件名
    print(f"{Hx_config.yellow}InPuT T4rGet {target} Sc3n Start!{Hx_config.end}")
    while not Hx_config.target_queue.empty():
        current_target = base.addHttpHeader(Hx_config.target_queue.get())
        try:
            if base.checkBlackList(current_target):
                # 对搜集到的目标挨个进行扫描
                req_pool = crawlergoMain.crawlergoGet(current_target)  # 返回crawlergoGet结果列表,是多个url路径
                req_pool.add(current_target)  # 添加自己本身到该列表里
                req_pool = WAF(req_pool).run_detect()
                base.save(req_pool, filepath=f"{Hx_config.Crawlergo_save_path}{target}.txt", host=current_target)
                tempFilename = hashlib.md5(current_target.encode("utf-8")).hexdigest()
                # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
                threadPoolScan(req_pool, tempFilename, target)
        except:
            pass
    print(f"{Hx_config.yellow}InPuT T4rGet {target} Sc3n EnD#{Hx_config.end}")
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
    thread = ThreadPoolExecutor(Hx_config.ThreadNum)
    filename = hashlib.md5(target.encode("utf-8")).hexdigest()
    print(f"{Hx_config.yellow}Start attsrc foxScan {target}\nfilename : {filename}\n{Hx_config.end}")
    base.subScan(target, filename)
    # 进行子域名搜集
    while not Hx_config.target_queue.empty():
        current_target = Hx_config.target_queue.get()
        # 对搜集到的目标挨个进行扫描
        if base.checkBlackList(current_target):
            req_pool = crawlergoMain.crawlergoGet(current_target)
            req_pool.add(current_target)
            i = 0
            all_task = []
            while len(req_pool) != 0:
                # 将 req_pool 里的URL依次弹出并扫描
                temp_url = req_pool.pop()
                current_filename = hashlib.md5(temp_url.encode("utf-8")).hexdigest()
                i += 1
                one_t = thread.submit(threadPoolDetailScan, temp_url, current_filename)
                all_task.append(one_t)
                if i == 5 or len(req_pool) == 0:
                    i = 0
                    wait(all_task, return_when=ALL_COMPLETED)
                    all_task = []
        else:
            print("扫描网址在黑名单内,退出")
    print(f"{Hx_config.yellow}InPuT T4rGet {target} Sc3n EnD#{Hx_config.end}")
    return


'''
单元测试代码
支持三个攻击参数：
    1,-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 输入 https://www.baidu.com
    2,-s --attsrc 对SRC资产，进行信息搜集+ARL+crawlergo+xray , 例如 百度SRC  输入 baidu.com
    3,-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 baidu.com
'''


def main():
    try:
        Hx_config.logo()
        init.main(standalone_mode=False)
    except Exception as e:
        print(e)
        pass


# def main(argv):
#     config.logo()
#     base.init()
#     try:
#         opts, args = getopt.getopt(argv, "ha:s:d:r:t:c",
#                                    ["help", "attone=", "attsrc=", "attdetail=", "readppp=", "thread=", "clean"])
#     except getopt.GetoptError:
#         config.scanHelp()
#         sys.exit(2)
#     for opt, arg in opts:
#         target = arg.strip('/') # 因为url后缀带有\会造成oneforall保存错误
#         filename = arg
#         if opt in ("-h", "--help"):
#             config.scanHelp()
#             sys.exit()
#         elif opt in ("-t", "--thread"):
#             config.ThreadNum = int(arg)
#         elif opt in ("-a", "--attone"):
#             oneFoxScan(target)
#         elif opt in ("-s", "--attsrc"):
#             foxScan(target)
#         elif opt in ("-d", "--attdetail"):
#             foxScanDetail(target)
#         elif opt in ("-r", "--readppp"):
#             pppFoxScan(filename)
#         elif opt in ("-c", "--clean"):
#             config.delModel()
#             sys.exit()
#         else:
#             config.scanHelp()
#             sys.exit()
#     return


if __name__ == '__main__':
    main()

import hashlib
from crawlergo import crawlergoMain
from Xray import pppXray
import config
import sys
import getopt
import base
from ServerJiang.jiangMain import SendNotice
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED


def threadPoolScan(req_pool, filename, target):
    print("req_pool num is {}".format(len(req_pool)))
    thread = ThreadPoolExecutor(max_workers=config.ThreadNum)
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

def foxScan():
    # 进行子域名搜集
    config.target_queue.put('127.0.0.1')
    config.target_queue.put('http://testphp.vulnweb.com/')

    while not config.target_queue.empty():
        current_target = config.target_queue.get()
        if base.checkBlackList(current_target):
            # 对搜集到的目标挨个进行扫描
            req_pool = crawlergoMain.crawlergoGet(current_target)
            req_pool.add(current_target)
            tempFilename=hashlib.md5(current_target.encode("utf-8")).hexdigest()
            # 对目标网址使用 crawlergoGet 页面URL动态爬取，保存在 req_pool 集合里
            threadPoolScan(req_pool, tempFilename, "aa")
    print("InPuT T4rGet {} Sc3n EnD#".format("aa"))
    return

def main():
    base.init()
    foxScan()
    # subDomainsBruteMain.subDomainsBruteScan('wkj.work',"aa")
    return

if __name__ == '__main__':
    main()
import fnmatch
import os
import subprocess

import simplejson
import Hx_config

ua = Hx_config.GetHeaders()

# def GetHeaders():
#     headers = {'User-Agent': ua.random}
#     return headers

'''
    使用集合去除重复的URL
    将去重后的URL存储进入queue队列
'''


def removeDuplicates(req_list):
    req_pool = set()
    try:
        for url in req_list:
            req_pool.add(url['url'].strip())
    except Exception as e:
        print(e)
        pass
    return req_pool


'''
    使用crawlergo进行目标页面URL的爬取
'''


def crawlergoGet(target):
    print(f"{Hx_config.yellow}Now crawlergoGet : {target}{Hx_config.end}")
    try:
        if jump_duplication(target) == 'pass':
            return 'pass'
        cmd = [Hx_config.crawlergo_Path, "-c", Hx_config.Chrome_Path, "-t", "10", "-f",
               "smart", "-o", "json", target]
        rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = rsp.communicate()
        #  "--[Mission Complete]--"  是任务结束的分隔字符串
        result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
        # print(result)
        req_list = result["req_list"]

    except Exception as e:
        print(e)
        req_list = []
        pass
    print(f"{Hx_config.yellow}target {target} crawlergo end~{Hx_config.end}")
    print(f"{Hx_config.green}crawlergo get url number {len(req_list)}{Hx_config.end}")
    return removeDuplicates(req_list)


# 跳过已经完成爬取的host
def jump_duplication(url):
    host = get_host(url)
    filenames = []
    for i in range(0, len(host)):
        _ = '.'.join(host[i::])
        filenames.append(_ + '.txt')

    del filenames[-2::]

    files = []
    complete_urls = []
    for root, dir, files in os.walk(r'save/saveCrawlergo'):
        pass
    for file in files:
        for filename in filenames:
            if fnmatch.fnmatch(filename, file):
                f = open(f'save//saveCrawlergo//{filename}', 'r')
                complete_urls = f.readlines()
                break

    for complete_url in complete_urls:
        if get_host(complete_url) == host:
            print(f"{Hx_config.yellow}target {url} exist, crawlergo pass~{Hx_config.end}")
            return 'pass'


# 提取url里的host
def get_host(url):
    host = url.split('.')
    end = host[-1]
    head = host[0]
    if ':' in end:
        end = end.split(':')[0]
    elif '/' in end:
        end = end.split('/')[0]
    if 'https://' in head or 'http://' in head:
        head = head.split('//')[-1]
    host[-1] = end
    host[0] = head

    return host


def main():
    return


if __name__ == '__main__':
    main()

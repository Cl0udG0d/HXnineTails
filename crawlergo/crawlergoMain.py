import simplejson
import subprocess
import json
import config
from fake_useragent import UserAgent
import queue
ua = UserAgent()


def GetHeaders():
    headers = {'User-Agent': ua.random}
    return headers

'''
    使用集合去除重复的URL
    将去重后的URL存储进入queue队列
'''
def removeDuplicates(req_list):
    req_pool=set()
    req_queue=queue.Queue()
    for url in req_list:
        req_pool.add(url['url'].strip())
    while len(req_pool)!=0:
        url=req_pool.pop()
        req_queue.put(url)
    return req_queue

'''
    使用crawlergo进行目标页面URL的爬取
'''
def crawlergoGet(target):
    cmd = [config.crawlergo_Path, "-c", config.Chrome_Path, "--custom-headers", json.dumps(GetHeaders()), "-t", "10", "-f",
           "smart", "-o", "json", target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    #  "--[Mission Complete]--"  是任务结束的分隔字符串
    result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
    # print(result)
    req_list = result["req_list"]
    print("target {} crawlergo end~".format(target))
    return req_list

def main():
    return
    # target = "http://testphp.vulnweb.com/"
    # cmd = ["./crawlergo", "-c", config.Chrome_Path, "--custom-headers",json.dumps(GetHeaders()),"-t","10","-f","smart","-o", "json", target]
    # rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # output, error = rsp.communicate()
    # #  "--[Mission Complete]--"  是任务结束的分隔字符串
    # result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
    # # print(result)
    # req_list = result["req_list"]
    # for url in req_list:
    #     print(url['url'])
    # print(req_list)


if __name__ == '__main__':
    main()
import simplejson
import subprocess
import json
import config
from fake_useragent import UserAgent
ua = UserAgent()


# def GetHeaders():
#     headers = {'User-Agent': ua.random}
#     return headers

'''
    使用集合去除重复的URL
    将去重后的URL存储进入queue队列
'''
def removeDuplicates(req_list):
    req_pool=set()
    for url in req_list:
        req_pool.add(url['url'].strip())
    return req_pool
    # while len(req_pool)!=0:
    #     url=req_pool.pop()
    #     config.xray_queue.put(url)


'''
    使用crawlergo进行目标页面URL的爬取
'''
def crawlergoGet(target):
    try:
        cmd = [config.crawlergo_Path, "-c", config.Chrome_Path, "--custom-headers", json.dumps(config.GetHeaders()), "-t", "10", "-f",
               "smart", "-o", "json", target]
        rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = rsp.communicate()
        #  "--[Mission Complete]--"  是任务结束的分隔字符串
        result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
        # print(result)
        req_list = result["req_list"]
    except Exception as e:
        print(e)
        req_list=[]
        pass
    print("target {} crawlergo end~".format(target))
    return removeDuplicates(req_list)
    # print("{} removeDuplicates End~".format(target))

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
import simplejson
import subprocess
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
    try:
        for url in req_list:
            req_pool.add(url['url'].strip())
    except Exception as e :
        print(e)
        pass
    return req_pool



'''
    使用crawlergo进行目标页面URL的爬取
'''
def crawlergoGet(target):
    print(f"{config.yellow}Now crawlergoGet : {target}{config.end}")
    try:
        cmd = [config.crawlergo_Path, "-c", config.Chrome_Path, "-t", "10", "-f",
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
    print(f"{config.yellow}target {target} crawlergo end~{config.end}")
    print(f"{config.green}crawlergo get url number {len(req_list)}{config.end}")
    return removeDuplicates(req_list)

def main():
    return



if __name__ == '__main__':
    main()
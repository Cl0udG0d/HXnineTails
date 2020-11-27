import simplejson
import subprocess
import os

def main():
    target = "http://testphp.vulnweb.com/"
    cmd = ["./crawlergo", "-c", "chrome.exe", "-t","10","-o", "json", target]
    print("aaa")
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("bbb")
    output, error = rsp.communicate()
    print("bbb")
    #  "--[Mission Complete]--"  是任务结束的分隔字符串
    result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
    print("bbb")
    req_list = result["req_list"]
    print("bbb")
    print(req_list[0])


if __name__ == '__main__':
    main()
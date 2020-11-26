from multiprocessing.pool import ThreadPool
import re
import requests
from fake_useragent import UserAgent
import socket

ua = UserAgent()
portlist=['80','8080','8000','8081','8001']

'''
GetHeaders()函数
    使用fake-useragent函数
    返回一个随机生成的请求头，防止因为python自带的请求头而被屏蔽
'''
def GetHeaders():
    headers = {'User-Agent': ua.random}
    return headers

'''
CScan C段扫描代码
    传入IP
    对其进行访问之后返回其title信息
'''
def CScan(ip):
    try:
        rep = requests.get("http://" + ip, headers=GetHeaders(), timeout=2, verify=False)
        if rep.status_code != 404:
            title = re.findall(r'<title>(.*?)</title>', rep.text)
            if title:
                return "[T]" + ip + ' >>> ' + title[0] + "\n"
            else:
                return "[H]" + ip + " >>> have reason\n"
    except Exception as e:
        pass

'''
C段扫描控制函数 CScanConole(host,filename,path)
    传入host，可以为域名或者IP,对于域名使用socket.gethostbyname进行转换
    同时传入filename为host的MD5 hash之后的结果
    传入的path为保存文件项目的绝对路径，方便保存到指定的文件夹下
    缺点是不能绕过CDN防护
    使用线程池进行多线程C段扫描 线程最大数量默认为 20
    将结果经过过滤后保存到相应的域名MD5文件中
'''
def CScanConsole(host,filename,path):
    pattern = re.compile('^\d+\.\d+\.\d+\.\d+(:(\d+))?$')
    if not pattern.findall(host):
        ip = socket.gethostbyname(host)
    if pattern.findall(host) and ":" in host:
        ip = host.split(":")[0]
    hostList = []
    ip = ip.split('.')
    pools = 20
    for tmpCip in range(1, 256):
        ip[-1] = str(tmpCip)
        host = ".".join(ip)
        hostList.append(host)
    pool = ThreadPool(pools)
    C_Message = pool.map(CScan, hostList)
    pool.close()
    pool.join()
    content="".join(list(filter(None, C_Message)))
    Cfilename=path+'\\save\\saveCplus\\'+filename+".txt"
    with open(Cfilename, "a", encoding='utf-8') as fobject:
        fobject.write(content)
    print("CSan END,the path:" + Cfilename)

def main():
    return

if __name__ == '__main__':
    main()


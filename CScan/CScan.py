from multiprocessing.pool import ThreadPool
import re
import requests
import socket
import config


'''
CScan C段扫描代码
    传入IP
    对其进行访问之后返回其title信息
'''
def CScan(ip):
    try:
        rep = requests.get("http://" + ip, headers=config.GetHeaders(), timeout=2, verify=False)
        if rep.status_code != 404:
            title = re.findall(r'<title>(.*?)</title>', rep.text)
            if title:
                return "[T]" + ip + ' >>> ' + title[0] + "\n"
            else:
                return "[H]" + ip + " >>> have reason\n"
    except Exception as e:
        pass


'''
C段扫描控制函数 CScanConole(host,Cfilename,path)
    传入host，可以为域名或者IP,对于域名使用socket.gethostbyname进行转换
    同时传入filename为host的MD5 hash之后的结果
    传入的path为保存文件项目的绝对路径，方便保存到指定的文件夹下
    缺点是不能绕过CDN防护
    使用线程池进行多线程C段扫描 线程最大数量默认为 20
    将结果经过过滤后保存到相应的域名MD5文件中
'''
def CScanConsole(host, Cfilename = '', path = ''):
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
        for port in config.portlist:
            host=host+":"+str(port)
            hostList.append(host)
    pool = ThreadPool(pools)
    C_Message = pool.map(CScan, hostList)
    pool.close()
    pool.join()
    content="".join(list(filter(None, C_Message)))
    print(content)
    print("CSan END,the path:" + Cfilename)

def main():
    CScanConsole('120.53.133.61:80')

if __name__ == '__main__':
    main()


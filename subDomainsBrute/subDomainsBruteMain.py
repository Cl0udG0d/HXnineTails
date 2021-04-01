import os

import base
import config



'''
subDomainsBruteScan(target) 函数
参数：
    target 需要收集子域名的目标 例如：baidu.com
作用：
    使用subDomainsBrute进行子域名收集 并且将结果存储到 sub_queue 队列中
输出：
    无
'''
def subDomainsBruteScan(target,filename):
    subDomainsBrute_py='{}subDomainsBrute.py'.format(config.subDomainsBrute_Path)
    saveFilePath='{}{}.txt'.format(config.Temp_path,base.url_http_delete(filename))
    scanCommand="{} {} -t 10 --output {} {}".format(config.PYTHON,subDomainsBrute_py,saveFilePath,base.url_http_delete(target))
    print(scanCommand)
    os.system(scanCommand)
    if os.path.exists(saveFilePath):
        f = open(saveFilePath)
        lines = f.readlines()
        for line in lines:
            temp_url=line.split()[0].rstrip('\n')
            # print(temp_url)
            config.sub_queue.put(temp_url)
        f.close()
    print("{} subDomainsBruteScan Scan End ~".format(target))
    return

def main():
    # filename=hash('baidu.com')
    subDomainsBruteScan('wkj.work',"aa")
    return

if __name__ == '__main__':
    main()
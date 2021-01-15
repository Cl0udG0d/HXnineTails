import config
import os


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
    saveFilePath='{}{}'.format(config.Root_Path,filename)
    scanCommand="{} {} -t 10 --output {} {}".format(config.PYTHON,subDomainsBrute_py,filename,target)
    os.system(scanCommand)
    f = open(saveFilePath)
    lines = f.readlines()
    for line in lines:
        temp_url=line.split()[0].rstrip('\n')
        print(temp_url)
        config.sub_queue.put(temp_url)
    f.close()
    print("{} subDomainsBruteScan Scan End ~".format(target))
    return

def main():
    filename=hash('baidu.com')
    subDomainsBruteScan('baidu.com',filename)
    return

if __name__ == '__main__':
    main()
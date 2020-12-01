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
def subDomainsBruteScan(target):
    subDomainsBrute_py='{}subDomainsBrute.py'.format(config.subDomainsBrute_Path)
    saveFilePath='{}target.txt'.format(config.subDomainsBrute_Path)
    scanCommand="python3 {} -t 10 --output target.txt {}".format(subDomainsBrute_py,target)
    os.system(scanCommand)
    f = open(saveFilePath)
    lines = f.readlines()
    for line in lines:
        print(line.strip())
        config.sub_queue.put(line.rstrip('\n'))
    f.close()
    print("{} subDomainsBruteScan Scan End ~".format(target))
    return

def main():
    subDomainsBruteScan('baidu.com')
    return

if __name__ == '__main__':
    main()
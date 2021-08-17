import os

import Hx_config
import base

'''
subDomainsBruteScan(target) 函数
参数：
    target 需要收集子域名的目标 例如：baidu.com
作用：
    使用subDomainsBrute进行子域名收集 并且将结果存储到 sub_queue 队列中
输出：
    无
'''


def subDomainsBruteScan(target, filename):
    print(f"{Hx_config.yellow}{target} subDomainsBruteScan Scan Start ~{Hx_config.end}")
    subDomainsBrute_py = '{}subDomainsBrute.py'.format(Hx_config.subDomainsBrute_Path)
    saveFilePath = '{}{}.txt'.format(Hx_config.Temp_path, base.url_http_delete(filename))
    scanCommand = "{} {} -t 10 --output {} {}".format(Hx_config.PYTHON, subDomainsBrute_py, saveFilePath,
                                                      base.url_http_delete(target))
    print(f"{Hx_config.blue}{scanCommand}{Hx_config.end}")
    os.system(scanCommand)
    if os.path.exists(saveFilePath):
        f = open(saveFilePath)
        lines = f.readlines()
        for line in lines:
            temp_url = line.split()[0].rstrip('\n')
            # print(temp_url)
            Hx_config.sub_queue.put(temp_url)
        f.close()
    print(f"{Hx_config.yellow}{target} subDomainsBruteScan Scan End ~{Hx_config.end}")
    print(f"{Hx_config.green}subdomainsbrute 结束 ！当前的url个数为{Hx_config.sub_queue.qsize()}{Hx_config.end}")
    return


def main():
    # filename=hash('baidu.com')
    subDomainsBruteScan('wkj.work', "aa")
    return


if __name__ == '__main__':
    main()

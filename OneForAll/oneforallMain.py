import config
import os
import csv

import base
'''
OneForALLScan调度主函数
    输入：target ，为目标域名，例如：baidu.com
    功能：将需要获取域名的target使用oneforall进行子域名收集，并将结果存储在队列中
'''
def OneForAllScan(target):
    print(f"{config.yellow}{target} OneForALL Scan Start~ {config.end}")
    results_path = f"{config.OneForAll_Path}results"
    oneforall_filename = "{}\\{}".format(results_path, base.get_filename(results_path, target))
    '''
    如果存在csv文件，则不需要爬取了
    '''
    try:
        csvFile = open(oneforall_filename, "r")
        csv_read(csvFile)
        print(f"{config.blue}{oneforall_filename}{config.end}")
        print(f"{config.green}文件已存在，不进行oneforall扫描。{config.end}")
    except FileNotFoundError:
        oneforall_py = "{}\\oneforall.py".format(config.OneForAll_Path)
        scanCommand = "{} {} --target {} run".format(config.PYTHON, oneforall_py, target)
        print(f"{config.blue}{scanCommand}{config.end}")
        os.system(scanCommand)
        oneforall_filename = "{}\\{}".format(results_path, base.get_filename(results_path, target))
        print(f"{config.blue}{oneforall_filename}{config.end}")
        csvFile = open(oneforall_filename, "r")
        csv_read(csvFile)

    print(f"{config.yellow}{target} OneForALL Scan end~ {config.end}")
    print(f"{config.green}oneforall 结束 ！当前的url个数为{config.sub_queue.qsize()}{config.end}")

    return 0

def csv_read(file_data):
    reader = csv.reader(file_data)
    for item in reader:
        if reader.line_num == 1:        # 忽略第一行
            continue
        # print(item[4])
        config.sub_queue.put(item[4])



def main():
    OneForAllScan('vulnweb.com')
    return

if __name__ == '__main__':
    main()
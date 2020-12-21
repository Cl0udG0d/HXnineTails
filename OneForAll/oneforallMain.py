import config
import os
import csv

'''
OneForALLScan调度主函数
    输入：target ，为目标域名，例如：baidu.com
    功能：将需要获取域名的target使用oneforall进行子域名收集，并将结果存储在队列中
'''
def OneForAllScan(target):
    oneforall_py="{}\\oneforall.py".format(config.OneForAll_Path)
    scanCommand = "{} {} --target {} run".format(config.PYTHON,oneforall_py,target)
    print(scanCommand)
    os.system(scanCommand)
    print("{} OneForALL Scan end~".format(target))
    oneforall_filename="{}results\\{}.csv".format(config.OneForAll_Path,target)
    print(oneforall_filename)
    csvFile = open(oneforall_filename, "r")
    reader = csv.reader(csvFile)
    for item in reader:
        if reader.line_num == 1:        # 忽略第一行
            continue
        # print(item[4])
        config.sub_queue.put(item[4])
    return

def main():
    OneForAllScan('vulnweb.com')
    return

if __name__ == '__main__':
    main()
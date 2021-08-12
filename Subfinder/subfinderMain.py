import os
import config

'''
subfinderScan(target)
'''
def subfinderScan(target,filename):
    print(f"{config.yellow}{target} subfinderScan Scan Start ~{config.end}")
    tempFilePath="{}{}".format(config.Temp_path,filename)
    scanCommand = "{}subfinder.exe -d {} -o {}".format(config.subfinder_Path,target,tempFilePath)

    os.system(scanCommand)
    f = open(tempFilePath)
    lines = f.readlines()
    for line in lines:
        print(f"{config.green}{line.strip()}{config.end}")
        config.sub_queue.put(line.rstrip('\n'))
    f.close()
    print(f"{config.yellow}{target} subfinderScan Scan End ~{config.end}")
    print(f"{config.green}subfinderScan 结束 ！当前的url个数为{config.sub_queue.qsize()}{config.end}")
    return

def main():
    subfinderScan('baidu.com')
    return

if __name__ == '__main__':
    main()
import os
import config

'''
subfinderScan(target)
'''
def subfinderScan(target,filename):
    print("{} subfinderScan Scan Start ~".format(target))
    tempFilePath="{}{}".format(config.Temp_path,filename)
    scanCommand = "{}subfinder.exe -d {} -o {}".format(config.subfinder_Path,target,tempFilePath)

    os.system(scanCommand)
    f = open(tempFilePath)
    lines = f.readlines()
    for line in lines:
        print(line.strip())
        config.sub_queue.put(line.rstrip('\n'))
    f.close()
    print("{} subfinderScan Scan End ~".format(target))
    print(f"subfinderScan 结束 ！当前的url个数为{config.sub_queue.qsize()}")
    return

def main():
    subfinderScan('baidu.com')
    return

if __name__ == '__main__':
    main()
import os
import config

'''
subfinderScan(target)
'''
def subfinderScan(target,filename):
    tempFilePath="{}\\{}".format(config.Temp_report_path,filename)
    scanCommand = "{}subfinder.exe -d {} -o {}".format(config.subfinder_Path,target,tempFilePath)

    os.system(scanCommand)
    f = open(tempFilePath)
    lines = f.readlines()
    for line in lines:
        print(line.strip())
        config.sub_queue.put(line.rstrip('\n'))
    f.close()
    print("{} subDomainsBruteScan Scan End ~".format(target))
    return

def main():
    subfinderScan('baidu.com')
    return

if __name__ == '__main__':
    main()
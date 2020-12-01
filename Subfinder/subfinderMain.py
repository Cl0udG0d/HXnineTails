import os
import config

'''
subfinderScan(target)
'''
def subfinderScan(target):
    scanCommand = "{}subfinder.exe -d {} -o output.txt".format(config.subfinder_Path,target)

    os.system(scanCommand)
    f = open('output.txt')
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
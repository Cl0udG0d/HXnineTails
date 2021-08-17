import os
import Hx_config

'''
subfinderScan(target)
'''
def subfinderScan(target,filename):
    print(f"{Hx_config.yellow}{target} subfinderScan Scan Start ~{Hx_config.end}")
    tempFilePath="{}{}".format(Hx_config.Temp_path, filename)
    scanCommand = "{}subfinder.exe -d {} -o {}".format(Hx_config.subfinder_Path, target, tempFilePath)

    os.system(scanCommand)
    f = open(tempFilePath)
    lines = f.readlines()
    for line in lines:
        print(f"{Hx_config.green}{line.strip()}{Hx_config.end}")
        Hx_config.sub_queue.put(line.rstrip('\n'))
    f.close()
    print(f"{Hx_config.yellow}{target} subfinderScan Scan End ~{Hx_config.end}")
    print(f"{Hx_config.green}subfinderScan 结束 ！当前的url个数为{Hx_config.sub_queue.qsize()}{Hx_config.end}")
    return

def main():
    subfinderScan('baidu.com')
    return

if __name__ == '__main__':
    main()
import hashlib
import base
import os
from scan import pppFoxScan
import config
def subGet(target):
    filename = hashlib.md5(target.encode("utf-8")).hexdigest()
    print("Start attsrc foxScan {}\nfilename : {}\n".format(target, filename))
    base.subScan(target, filename)
    return
PATH='C:\\Users\\Administrator\\Desktop\\heheSEC\\target\\'

def main():
    try:
        if not os.path.exists(config.Save_path):
            os.makedirs(config.Save_path)
            os.makedirs(config.Xray_report_path)
            os.makedirs(config.Xray_temp_report_path)
            os.makedirs(config.CScan_report_path)
            os.makedirs(config.Sub_report_path)
            os.makedirs(config.Temp_path)
            os.makedirs(config.JS_report_path)
    except Exception as e:
        print(e)
        exit(0)
    print("目录初始化完成")
    reportList=os.listdir(PATH)
    print(reportList)
    for report in reportList:
        current_file=PATH+report
        pppFoxScan(current_file)


if __name__ == '__main__':
    main()
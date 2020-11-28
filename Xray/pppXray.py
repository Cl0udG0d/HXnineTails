import os
import hashlib
import config


def logo():
    logo='''
 _ __  _ __  _ __         
| '_ \| '_ \| '_ \        
| |_) | |_) | |_) |       
| .__/| .__/| .__/        
| |   | |   | |           
|_|   |_|   |_|           
   __   __                
   \ \ / /                
    \ V / _ __ __ _ _   _ 
    /   \| '__/ _` | | | |
   / /^\ \ | | (_| | |_| |
   \/   \/_|  \__,_|\__, |
                     __/ |
                    |___/ 
                            v1.0
                            author:springbird
    '''
    return logo


def xrayScan(targeturl,outputfilename="test"):
    scanCommand="{} webscan --basic-crawler {} --html-output {}\{}.html".format(config.Xray_Path,targeturl,config.Xray_report_path,outputfilename)
    print(scanCommand)
    os.system(scanCommand)
    return


def pppGet(req_queue):
    while not req_queue.empty():
        try:
            target=req_queue.get()
            outputfilename = hashlib.md5(target.encode("utf-8"))
            xrayScan(target.strip(), outputfilename.hexdigest())
        except Exception as e:
            print(e)
            pass
    print("Xray Scan End~")
    return
    # f = open("target.txt")
    # lines = f.readlines()
    # pattern = re.compile(r'^http://')
    # for line in lines:
    #     try:
    #         if not pattern.match(line.strip()):
    #             targeturl="https://"+line.strip()
    #         else:
    #             targeturl=line.strip()
    #         print(targeturl.strip())
    #         outputfilename=hashlib.md5(targeturl.encode("utf-8"))
    #         xrayScan(targeturl.strip(), outputfilename.hexdigest())
    #         # print(type(line))
    #     except Exception as e:
    #         print(e)
    #         pass
    # f.close()
    # print("Xray Scan End~")
    # return

def main():
    print(logo())
    xrayScan("http://127.0.0.1/")
    # pppGet()
    return

if __name__ == '__main__':
    main()
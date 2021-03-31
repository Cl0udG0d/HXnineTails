import os
import queue
import shutil
from fake_useragent import UserAgent

'''
配置文件:
    Root_Path路径信息 项目根目录的绝对路径
'''

Root_Path = os.path.dirname(os.path.abspath(__file__))

'''
Server酱your_key
'''
SERVERKEY=''

'''
ARL的api_key
'''
API_KEY = 'test123' # 在 ARL/docker/config-docker.yaml里修改

'''
工具所在路径：
    chrome路径信息 Chrome_Path 例如:C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe
    Xray路径信息 Xray_Path 例如:D:\\Xray\\xray.exe
    crawlergo 可执行文件的所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\crawlergo\\crawlergo.exe
    OneForAll 文件夹所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\OneForAll-master\\
    subDomainsBrute 文件夹所在位置 
'''
Chrome_Path='C:\\Users\HXnineTails\\chrome-win\\chrome.exe'

Xray_Path='C:\\Users\\HXnineTails\\xray\\xray.exe'
crawlergo_Path='C:\\Users\\HXnineTails\\crawlergo.exe'
OneForAll_Path='C:\\Users\\Kitty\\Desktop\\HACK\\渗透测试\\信息收集\\OneForAll-master'
subDomainsBrute_Path='C:\\Users\\HXnineTails\\subDomainsBrute-master'
subfinder_Path='C:\\Users\\HXnineTails\\subfinder_2.4.5_windows_amd64'
arl_url_Path='http://192.168.160.129:5004'
# Xray_Path='C:\\Users\\Cl0udG0d\\Desktop\\Xray\\xray.exe'
# crawlergo_Path='C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\crawlergo\\crawlergo.exe'
# OneForAll_Path='C:\\Users\\Cl0udG0d\\Desktop\\OneForAll-master\\'
# subDomainsBrute_Path='C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\subDomainsBrute-master\\'
# subfinder_Path='C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\subfinder_2.4.5_windows_amd64\\'


'''
输出报告路径：
    报告全部输出在save文件夹下
    Xray_report_path Xray扫描后的输出html报告
    CScan_report_path C段扫描后的输出txt文件
'''
Save_path="{}\\save".format(Root_Path)
Xray_report_path="{}\\save\\saveXray".format(Root_Path)
Xray_temp_report_path='{}\\save\\saveTempXray'.format(Root_Path)
CScan_report_path="{}\\save\\saveCplus\\".format(Root_Path)
Sub_report_path="{}\\save\\saveSub\\".format(Root_Path)
Temp_path="{}\\save\\temp\\".format(Root_Path)
JS_report_path='{}\\save\\saveJS\\'.format(Root_Path)

'''
一些全局通用配置：
    portlist C段探测时的默认端口 默认为:80,8080,8000,8081,8001
    sub_queue 存储子域名的队列，用于保存所有工具获取到的子域名
'''
portlist=['80','8080','8000','8081','8001']
blacklist=["spider","org"]
ThreadNum=5
PYTHON="py -3.9"

'''
全局队列：

'''
sub_queue=queue.Queue()
target_queue=queue.Queue()
xray_queue=queue.Queue()
ppp_queue=queue.Queue()


'''
GetHeaders()函数
    使用fake-useragent函数
    返回一个随机生成的请求头，防止因为python自带的请求头而被屏蔽
'''
ua = UserAgent()
def GetHeaders():
    try:
        headers = {'User-Agent': ua.random}
    except Exception as e:
        print(e)
        headers={'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'}
    return headers


def logo():
    print('''

 +-+-+-+-+-+-+-+-+-+-+-+
 |H|X|n|i|n|e|T|a|i|l|s|
 +-+-+-+-+-+-+-+-+-+-+-+
                        v1.03

    ''')

'''
递归删除临时保存目录下的保存信息
'''
def delModel():
    saveFolderList=['saveCplus','saveJS','saveSub','saveXray']
    for tempFolder in saveFolderList:
        shutil.rmtree("{}\\save\\{}".format(Root_Path,tempFolder))
        os.mkdir("{}\\save\\{}".format(Root_Path,tempFolder))
    print("clean end :)")
    return


'''
帮助信息
'''
def scanHelp():
    print(
        'scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:'
        'scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n\t-r --readppp <readfilename attack> '
        'example: scan.py -r target.txt\n\t-t --thread number of threads\n\t-c --clean clean saveFiles\n\t-h --help output help information\n'
    )


def main():
    print(Root_Path)
    return

if __name__ == '__main__':
    main()
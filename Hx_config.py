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
SERVERKEY = ''

'''
ARL的api配置和网络路径
'''
API_KEY = 'token_is_123'  # 在 ARL/docker/config-docker.yaml里修改
arl_url_Path = 'https://127.0.0.1:5004'

'''
xray以后的参数
'''
plugins = None

'''
工具所在路径：
    chrome路径信息 Chrome_Path 例如:C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe
    Xray路径信息 Xray_Path 例如:D:\\Xray\\xray.exe
    crawlergo 可执行文件的所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\crawlergo\\crawlergo.exe
    OneForAll 文件夹所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\OneForAll-master\\
    subDomainsBrute 文件夹所在位置 
'''
Chrome_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\chrome-win\\chrome.exe'
Xray_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\xray\\xray.exe'
crawlergo_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\crawlergo.exe'
OneForAll_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\OneForAll-master\\'
subDomainsBrute_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\subDomainsBrute-master\\'
subfinder_Path = 'C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\subfinder_2.4.5_windows_amd64\\'
# Chrome_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\chrome-win\\chrome.exe'
# Xray_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\xray\\xray.exe'
# crawlergo_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\crawlergo.exe'
# OneForAll_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\OneForAll-master\\'
# subDomainsBrute_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\subDomainsBrute-master\\'
# subfinder_Path='C:\\Users\\Th\\Documents\\工具库\\HxnineTails_Script\\subfinder_2.4.5_windows_amd64\\'

'''
一些全局通用配置：
    portlist C段探测时的默认端口 默认为:80,8080,8000,8081,8001
    sub_queue 存储子域名的队列，用于保存所有工具获取到的子域名
'''
portlist = ['80', '8080', '8000', '8081', '8001']
blacklist = ["spider", "org"]
ThreadNum = 5
PYTHON = "py -3.8"

'''
输出报告路径：
    报告全部输出在save文件夹下
    Xray_report_path Xray扫描后的输出html报告
    CScan_report_path C段扫描后的输出txt文件
'''
Save_path = "{}\\save".format(Root_Path)
Xray_report_path = "{}\\save\\saveXray".format(Root_Path)
Xray_temp_report_path = '{}\\save\\saveTempXray'.format(Root_Path)
CScan_report_path = "{}\\save\\saveCplus\\".format(Root_Path)
Sub_report_path = "{}\\save\\saveSub\\".format(Root_Path)
Temp_path = "{}\\save\\temp\\".format(Root_Path)
JS_report_path = '{}\\save\\saveJS\\'.format(Root_Path)
ARL_save_path = '{}\\save\\saveARL\\'.format(Root_Path)
Crawlergo_save_path = '{}\\save\\saveCrawlergo\\'.format(Root_Path)

'''
全局队列
'''
sub_queue = queue.Queue()
target_queue = queue.Queue()
xray_queue = queue.Queue()
ppp_queue = queue.Queue()

'''
GetHeaders()函数
    使用fake-useragent函数
    返回一个随机生成的请求头，防止因为python自带的请求头而被屏蔽
'''


def GetHeaders():
    try:
        ua = UserAgent(path='Useragent.json')
        headers = {'User-Agent': ua.random}
    except Exception as e:
        print(e)
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'}
    return headers


'''
颜色配置
'''
yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'


def logo():
    print(f'''
{blue}花溪九尾，懒人必备web扫描器！{green}
 +-+-+-+-+-+-+-+-+-+-+-+
 |{red}H|{yellow}X|n|{green}i|n|e|T|a|{yellow}i|l|{red}s|
 {green}+-+-+-+-+-+-+-+-+-+-+-+{white}
                        v1.1{end}
    ''')


'''
递归删除临时保存目录下的保存信息
'''


def delModel():
    saveFolderList = ['saveCplus', 'saveJS', 'saveSub', 'saveXray', 'saveARL', 'temp', 'saveTempXray', 'saveCrawlergo']
    for tempFolder in saveFolderList:
        shutil.rmtree("{}\\save\\{}".format(Root_Path, tempFolder))
        os.mkdir("{}\\save\\{}".format(Root_Path, tempFolder))
    print(f"{green}clean end :){end}")
    return


'''
帮助信息
'''


def scanHelp():
    print(
        f'{green}scan.py [options]\n\t-a --attone <attack one url> example: scan.py -a https://www.baidu.com\n\t-s --attsrc <attack one src> example:{end}'
        f'{green}scan.py -s baidu.com\n\t-d --attdetail <attack one src detail> example: scan.py -d baidu.com\n\t-r --readppp <readfilename attack>{end}'
        f'{green}example: scan.py -r target.txt\n\t-t --thread number of threads\n\t-c --clean clean saveFiles\n\t-h --help output help information\n{end}'
    )


def main():
    print(Root_Path)
    return


if __name__ == '__main__':
    main()

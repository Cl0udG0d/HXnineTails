import os


'''
配置文件:
    Root_Path路径信息 项目根目录的绝对路径
    
'''

Root_Path = os.path.dirname(os.path.abspath(__file__))

'''
工具所在路径：
    chrome路径信息 Chrome_Path 例如:C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe
    Xray路径信息 Xray_Path 例如:D:\\Xray\\xray.exe
    crawlergo 可执行文件的所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\crawlergo\\crawlergo.exe
    OneForAll oneforall.py所在的位置 例如：C:\\Users\\Cl0udG0d\\Desktop\\OneForAll-master\\oneforall.py
'''
Chrome_Path='C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
Xray_Path='D:\\Xray\\xray.exe'
crawlergo_Path='C:\\Users\\Cl0udG0d\\Desktop\\sec_tools\\crawlergo\\crawlergo.exe'
OneForAll_Path='C:\\Users\\Cl0udG0d\\Desktop\\OneForAll-master\\oneforall.py'

'''
输出报告路径：
    报告全部输出在save文件夹下
    Xray_report_path Xray扫描后的输出html报告
    CScan_report_path C段扫描后的输出txt文件
'''
Xray_report_path="{}\\save\\saveXray".format(Root_Path)
CScan_report_path="{}\\save\\saveCplus\\".format(Root_Path)

'''
一些全局通用配置：
    portlist C段探测时的默认端口 默认为:80,8080,8000,8081,8001
'''
portlist=['80','8080','8000','8081','8001']

def main():
    print(Root_Path)
    return

if __name__ == '__main__':
    main()
import os


'''
配置文件:
    Root_Path路径信息 项目根目录的绝对路径
    chrome路径信息 Chrome_Path 例如:C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe
    Xray路径信息 Xray_Path 例如:D:\\Xray\\xray.exe
    portlist C段探测时的默认端口 默认为:80,8080,8000,8081,8001
'''

Root_Path = os.path.dirname(os.path.abspath(__file__))
Chrome_Path='C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
Xray_Path='D:\\Xray\\xray.exe'
crawlergo_Path='C:\\Users\\Administrator\\Desktop\\HXnineTails\\crawlergo\\crawlergo.exe'

Xray_report_path="{}\save\saveXray".format(Root_Path)
portlist=['80','8080','8000','8081','8001']

def main():
    print(Root_Path)
    return

if __name__ == '__main__':
    main()
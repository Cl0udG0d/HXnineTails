import config
import sys
from scan import oneFoxScan,foxScan,foxScanDetail,pppFoxScan
import click
import os

'''
init() 扫描初始化函数
功能：
    初始化保存文件目录
    初始化扫描各参数
    attone=, attsrc=, attdetail=, readppp=, thread=,clean ,plugins=

'''
@click.command()
@click.option('-a', '--attone',help='对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 python3 scan.py -a https://www.baidu.com',type=str)
@click.option('-s', '--attsrc',help='对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC python3 scan.py -s baidu.com',type=str)
@click.option('-d', '--attdetail',help='对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 python3 scan.py -d baidu.com',type=str)
@click.option('-t', '--thread',default=5,help='线程数量，默认线程为5 如 python3 scan.py -t 10 -a http://testphp.vulnweb.com/ ',type=int)
@click.option('-r', '--readfile',help='读取待扫描txt文件，每行一个URL 对取出的每个URL进行 -a 扫描，如 python3 scan.py -t 10 -r target.txt',type=str)
@click.option('-c', '--clean',help='对保存的漏洞相关报告进行清理，即清理save文件夹下的文件',is_flag=True)
@click.option('-p','--plugins',help='自定义xray插件 plugins')
def init(attone,attsrc,attdetail,thread,readfile,clean,plugins):
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
    config.ThreadNum = int(thread)
    if plugins:
        config.plugins = plugins
    if clean:
        config.delModel()
        sys.exit()
    if attone:
        oneFoxScan(attone)
    if attsrc:
        foxScan(attsrc)
    if attdetail:
        foxScanDetail(attdetail)
    if readfile:
        pppFoxScan(readfile)
    return


'''
init() 扫描初始化函数
功能：
    初始化保存文件目录
'''
def old_init():
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
    print("初始化完成")
    return

'''
单元测试代码
支持三个攻击参数：
    1,-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 输入 https://www.baidu.com
    2,-s --attsrc 对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC  输入 baidu.com
    3,-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 baidu.com
'''


def main():
    try:
        config.logo()
        init.main(standalone_mode=False)
    except Exception as e:
        print(e)
        pass
    return

if __name__ == '__main__':
    main()

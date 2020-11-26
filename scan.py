from JSmessage.jsfinder import JSFinder

'''
扫描控制主函数
参数：
    url
    格式如：https://www.baidu.com

扫描联动工具：
    JS方面：
        JSfinder
        JSscan
    漏洞扫描：
        360 0Kee-Team 的 crawlergo动态爬虫 -> Xray高级版
    C段：
        BBScan
'''


'''
transferJSFinder(url,filename)函数
参数：
    url 待扫描的URL
    filename 实际上为待扫描URL的MD5值，作为输出文件名的一部分

调用并魔改JSFinder代码
输出：
    从JS中获取到的URL和subdomain
    输出文件名为：
        output_url_filename="url_"+outputfilename
        output_subdomain_filename="subdomain"+outputfilename
'''
def transferJSFinder(url,filename):
    try:
        urls=JSFinder.find_by_url(url)
        JSFinder.giveresult(urls,url,filename)
    except Exception as e:
        print("JSFinder ERROR!")
        print(e)
        pass

def octopusScan(url):
    return

'''
单元测试代码
'''
def main():
    transferJSFinder('https://www.baidu.com','ksdjalsjda')
    return


if __name__ == '__main__':
    main()
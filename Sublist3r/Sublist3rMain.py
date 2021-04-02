import config
from Sublist3r import sublist3r

'''
Sublist3rScan(target) 函数
参数：
    target 需要收集子域名的目标 例如：baidu.com
作用：
    使用Sublist3r进行子域名收集 并且将结果存储到 sub_queue 队列中
    使用Sublist3r 模块化用法 sublist3r.main
输出：
    无
'''
def Sublist3rScan(target):
    print("{} Sublist3rScan Scan Start ~".format(target))
    subdomains = sublist3r.main(target, 40, savefile=None, ports=None, silent=False, verbose=False,
                                enable_bruteforce=False, engines=None)
    print("{} Sublist3rScan Scan End ~".format(target))
    for temp_sub in subdomains:
        config.sub_queue.put(temp_sub)
    print("{} Sublist3r Save queue End ~".format(target))
    print(f"Sublist3r 结束 ！当前的url个数为{config.sub_queue.qsize()}")
    return

def main():
    Sublist3rScan('baidu.com')
    return

if __name__ == '__main__':
    main()
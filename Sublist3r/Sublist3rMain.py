import Hx_config
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
    print(f"{Hx_config.yellow}{target} Sublist3rScan Scan Start ~{Hx_config.end}")
    subdomains = sublist3r.main(target, 40, savefile=None, ports=None, silent=False, verbose=False,
                                enable_bruteforce=False, engines=None)
    print(f"{Hx_config.yellow}{target} Sublist3rScan Scan End ~{Hx_config.end}")
    for temp_sub in subdomains:
        Hx_config.sub_queue.put(temp_sub)
    print(f"{Hx_config.yellow}{target} Sublist3r Save queue End ~{Hx_config.end}")
    print(f"{Hx_config.green}Sublist3r 结束 ！当前的url个数为{Hx_config.sub_queue.qsize()}{Hx_config.end}")
    return

def main():
    Sublist3rScan('baidu.com')
    return

if __name__ == '__main__':
    main()
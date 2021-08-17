# *coding:UTF-8 *
import requests
import Hx_config
import json
import base
import time


class Scan(object):
    def __init__(self, name = '', targets_list = ''):
        self._ = ''
        self.targets = ''
        self.name = base.url_http_delete(name)
        self._list = targets_list
        self.Prevent_duplicate_scanning()
        self.headers = {
            "token": Hx_config.API_KEY,
            "Content-type": "application/json",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36'
}
        self.proxy = {
            'http':'http://127.0.0.1:8080',
            'https':'http://127.0.0.1:8080'
}


    def make_targets(self, __list): # 获取发送给ARL服务器特定格式的targets
        self.targets = "\n".join(list(__list))
        print(f"{Hx_config.green}ARL will add{Hx_config.end}")
        print(f"{Hx_config.green}{list(__list)}{Hx_config.end}")


    def Prevent_duplicate_scanning(self, delete_signal=False): # 防止多次对ARl服务器add同一个地址
        self._ = set(map(base.url_http_delete, self._list))
        __file_name = f'save\\saveARL\\{self.name}.txt'

        if delete_signal is True: # 如果没有正确执行ARL。则就删除之前保存下的文件里的url
            with open(__file_name, 'w+') as f2:
                lines = f2.readlines()
                __ = [line for line in lines if line not in self._]
                for i in __:
                    f2.write(i)
            return

        try:
            with open(__file_name, 'r') as f: # 有文件，和此次即将add的目标进行对比，把重复的去除，没有的继续添加扫描
                print(__file_name)
                lines = f.readlines()
                self._ = [item for item in self._ if item not in [line.strip() for line in lines]]
                print(self._)
        except:
            pass

        with open(__file_name, 'a+') as f1:
            print(f"{Hx_config.green}ARL新增{len(self._)}个domain{Hx_config.end}")
            for i in self._:
                f1.write(i + '\n')
            self.make_targets(self._)


    # 添加任务
    def add_task(self):
        url = Hx_config.arl_url_Path + '/api/task/'
        data = {"name": f"{self.name}", "target": f"{self.targets}", "domain_brute_type": "big", "port_scan_type": "top100",
                "domain_brute": True, "alt_dns": True, "riskiq_search": True, "arl_search": True,
                "port_scan": True,
                "service_detection": True, "os_detection": True, "fofa_search": True, "ssl_cert": True,
                "site_identify": True, "search_engines": True, "site_spider": True, "site_capture": True,
                "file_leak": True}
        try:
            r = requests.post(url=url, headers=self.headers, data=json.dumps(data), timeout=5, verify=False)
            result = r.json()
            print (f"{Hx_config.green}ARL_result : {str(result)}{Hx_config.end}")
            if len(result['items']) == 0: # 同样也是没有成功add
                self.Prevent_duplicate_scanning(delete_signal=True)
        except:
            if self._list == '' and len(self._list) == 1:
                print(f"{Hx_config.red}ARL没有接受到任何参数{Hx_config.end}")
            print(f"{Hx_config.red}ARL扫描启动失败,请检查ARL服务器网络！{Hx_config.end}")
            self.Prevent_duplicate_scanning(delete_signal=True)

if __name__ == '__main__':
    a = Scan(name='test', targets_list=["baidu","baidu.com"]).add_task()
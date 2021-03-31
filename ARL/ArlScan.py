# *coding:UTF-8 *
import requests
import config
import json


class Scan(object):
    def __init__(self, name = '', targets_list = ''):
        self.name = name
        self._list = targets_list
        self.make_targets()
        self.headers = {
    "token": config.API_KEY,
    "Content-type": "application/json",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36'
}


        self.proxy = {
            'http':'http://127.0.0.1:7001',
            'https':'http://127.0.0.1:7001'
                     }


    def make_targets(self):
        self.targets = "\n".join(self._list)
        print(self.targets)

    # 添加任务
    def add_task(self):
        url = config.arl_url_Path + '/api/task/'
        data = {"name": f"{self.name}", "target": f"{self.targets}", "domain_brute_type": "big", "port_scan_type": "top100",
                "domain_brute": True, "alt_dns": True, "riskiq_search": True, "arl_search": True,
                "port_scan": True,
                "service_detection": True, "os_detection": True, "fofa_search": True, "ssl_cert": True,
                "site_identify": True, "search_engines": True, "site_spider": True, "site_capture": True,
                "file_leak": True}
        try:
            r = requests.post(url=url, headers=self.headers, data=json.dumps(data), proxies=self.proxy)
            result = r.json()
            print ("ARL_result : ", result)
        except:
            if self._list[0] == '' and len(self._list) == 1:
                print("ARL没有接受到任何参数")
            print("ARL扫描启动失败！")

if __name__ == '__main__':
    a = Scan("baidu","baidu.com").add_task()
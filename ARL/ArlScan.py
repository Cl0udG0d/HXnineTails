# *coding:UTF-8 *
import requests
import config
import json
import base
import time


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
            'http':'http://127.0.0.1:8080',
            'https':'http://127.0.0.1:8080'
}


    def make_targets(self):
        _ = set(map(base.url_http_delete, self._list))
        self.targets = "\n".join(list(_))
        print(f"{config.green}ARL will add{config.end}")
        print(f"{config.green}{list(_)}{config.end}")

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
            r = requests.post(url=url, headers=self.headers, data=json.dumps(data))
            result = r.json()
            print (f"{config.green}ARL_result : {str(result)}{config.end}")
            time.sleep(5) # 短暂延迟
        except:
            if self._list == '' and len(self._list) == 1:
                print(f"{config.red}ARL没有接受到任何参数{config.end}")
            print(f"{config.red}ARL扫描启动失败,请检查ARL服务器网络！{config.end}")

if __name__ == '__main__':
    a = Scan("baidu","baidu.com").add_task()
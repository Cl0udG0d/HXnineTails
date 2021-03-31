# *coding:UTF-8 *
import requests
import config
import json


class Add_tasks(object):
    def __init__(self, name, targets):
        self.name = name
        self.targets = targets
        self.headers = {
    "token": config.API_KEY,
    "Content-type": "application/json",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36'
}


        self.proxy = {
            'http':'http://127.0.0.1:8080',
            'https':'http://127.0.0.1:8080'
                     }

    # 添加任务
    def add_task(self):
        url = config.arl_url_Path + '/api/task/'
        data = {"name": f"{self.name}", "target": f"{self.targets}", "domain_brute_type": "big", "port_scan_type": "top100",
                "domain_brute": False, "alt_dns": False, "riskiq_search": False, "arl_search": False,
                "port_scan": False,
                "service_detection": False, "os_detection": False, "fofa_search": False, "ssl_cert": False,
                "site_identify": False, "search_engines": False, "site_spider": False, "site_capture": True,
                "file_leak": False}
        r = requests.post(url=url, headers=self.headers, data=json.dumps(data), proxies=self.proxy)
        result = r.json()
        print (result)


a = Add_tasks("baidu","baidu.com").add_task()
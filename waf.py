import requests
import config
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


'''
输入：待检测的url列表
功能：检测该url是否有waf
输出：没有waf的列表
'''
class WAF(object):
    def __init__(self, __list):
        self.__list = __list
        self.__result = []
        self.__waf_info()

    def __once_detect(self,url):
        headers = config.GetHeaders()
        headers["Referer"] = url
        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code < 400:
                if self.__identify(resp.headers, resp.text):
                    parse = urlparse(resp.url)
                    new_url = "%s://%s/" % (parse.scheme, parse.netloc)
                    self.__result.append(new_url)
                    self.__result.append(url)
        except:
            print(f"{config.red}WAF~ {url} 网络连接失败{config.end}")

        return


    def run_detect(self):
        print(f"{config.green}WAF检测中~{config.end}")
        with ThreadPoolExecutor() as pool:
            pool.map(self.__once_detect, self.__list)
            as_completed(True)

        print(f"{config.blue}检测完毕，没有WAF的url：")
        for item in list(set(self.__result)):
            print(item)

        print(config.end)

        return list(set(self.__result))


    def __waf_info(self):
        self.__mark_list = []
        all_waf = '''WAF:Topsec-Waf|index|index|<META NAME="Copyright" CONTENT="Topsec Network Security Technology Co.,Ltd"/>|<META NAME="DESCRIPTION" CONTENT="Topsec web UI"/>
                                 WAF:360|headers|X-Powered-By-360wzb|wangzhan\.360\.cn
                                 WAF:360|url|/wzws-waf-cgi/|360wzws
                                 WAF:Anquanbao|headers|X-Powered-By-Anquanbao|MISS
                                 WAF:Anquanbao|url|/aqb_cc/error/|ASERVER
                                 WAF:BaiduYunjiasu|headers|Server|yunjiasu-nginx
                                 WAF:BigIP|headers|Server|BigIP|BIGipServer
                                 WAF:BigIP|headers|Set-Cookie|BigIP|BIGipServer
                                 WAF:BinarySEC|headers|x-binarysec-cache|fill|miss
                                 WAF:BinarySEC|headers|x-binarysec-via|binarysec\.com
                                 WAF:BlockDoS|headers|Server|BlockDos\.net
                                 WAF:CloudFlare|headers|Server|cloudflare-nginx
                                 WAF:Cloudfront|headers|Server|cloudfront
                                 WAF:Cloudfront|headers|X-Cache|cloudfront
                                 WAF:Comodo|headers|Server|Protected by COMODO
                                 WAF:IBM-DataPower|headers|X-Backside-Transport|\A(OK|FAIL)
                                 WAF:DenyAll|headers|Set-Cookie|\Asessioncookie=
                                 WAF:dotDefender|headers|X-dotDefender-denied|1
                                 WAF:Incapsula|headers|X-CDN|Incapsula
                                 WAF:Jiasule|headers|Set-Cookie|jsluid=
                                 WAF:KSYUN|headers|Server|KSYUN ELB
                                 WAF:KONA|headers|Server|AkamaiGHost
                                 WAF:ModSecurity|headers|Server|Mod_Security|NOYB
                                 WAF:NetContinuum|headers|Cneonction|\Aclose
                                 WAF:NetContinuum|headers|nnCoection|\Aclose
                                 WAF:NetContinuum|headers|Set-Cookie|citrix_ns_id
                                 WAF:Newdefend|headers|Server|newdefend
                                 WAF:NSFOCUS|headers|Server|NSFocus
                                 WAF:Safe3|headers|X-Powered-By|Safe3WAF
                                 WAF:Safe3|headers|Server|Safe3 Web Firewall
                                 WAF:Safedog|headers|X-Powered-By|WAF/2\.0
                                 WAF:Safedog|headers|Server|Safedog
                                 WAF:Safedog|headers|Set-Cookie|Safedog
                                 WAF:SonicWALL|headers|Server|SonicWALL
                                 WAF:Stingray|headers|Set-Cookie|\AX-Mapping-
                                 WAF:Sucuri|headers|Server|Sucuri/Cloudproxy
                                 WAF:Usp-Sec|headers|Server|Secure Entry Server
                                 WAF:Varnish|headers|X-Varnish|.*?
                                 WAF:Varnish|headers|Server|varnish
                                 WAF:Wallarm|headers|Server|nginx-wallarm
                                 WAF:WebKnight|headers|Server|WebKnight
                                 WAF:Yundun|headers|Server|YUNDUN
                                 WAF:Yundun|headers|X-Cache|YUNDUN
                                 WAF:Yunsuo|headers|Set-Cookie|yunsuo
                                 '''
        marks = all_waf.strip().splitlines()  # 按行显示
        for mark in marks:
            name, location, key, value = mark.strip().split("|", 3)
            self.__mark_list.append([name, location, key, value])

    def __identify(self,header, html):
        for line in self.__mark_list:
            name, location, key, reg = line
            if location == "headers":
                if key in header and re.search(reg, header[key], re.I):
                    return False
            elif location == "index":
                if re.search(reg, html, re.I):
                    return False

        return True

if __name__ == '__main__':
    list1 = WAF(['http://59.63.200.79:8014/dom_xss/', 'https://qq.com'])
    list1.run_detect()
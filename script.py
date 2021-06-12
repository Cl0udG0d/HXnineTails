import configparser
import os
import csv


FILE = 'config.ini'
conf = configparser.ConfigParser()
conf.read(FILE, encoding="utf-8")
PYTHON = conf.items('commom')[0][1]


def choose_config(items, data):
    for item in items:
        if item[0] == 'script_path':
            _tmp = list(item)
            _tmp[0] = ''
            item = tuple(_tmp)
        if item[1]:
            data.append(item)

    return


class oneforall():
    def __init__(self, target):
        items = conf.items('oneforall')
        self.data = list()
        self.target = target
        choose_config(items, self.data)

    def run(self):
        cmd = PYTHON + f' {self.data[0][1]}oneforall.py'
        for item in self.data[1:]:
            cmd += f' {item[0]} {item[1]} ' #注意空格
        cmd += f' --target {self.target} run'
        # os.system(cmd)

    def save(self):
        def http_url_delete(url):
            if ':' in url:
                _tmp = url.split(':///')
                url = _tmp[1]
            if '.' in url:
                _tmp = url.split('.')
                url = f'{_tmp[-3]}.{_tmp[-2]}.{_tmp[-1]}'

            return url

        save_path = self.data[0][1] + 'results\\' + f'{http_url_delete(self.target)}.csv'
        reader = csv.reader(open(save_path, "r"))
        for item in reader:
            if reader.line_num == 1:  # 忽略第一行
                continue
            print(item[4])
            #config.sub_queue.put(item[4])



class subdomainbrute():
    def __init__(self, target):
        items = conf.items('subdomainbrute')
        print(items)


class sublist3r():
    pass

class subfinderscan():
    pass

class xray():
    pass

# a = oneforall('cqut.edu.cn')
# a.run()
# a.save()

subdomainbrute('cqut.edu.cn')

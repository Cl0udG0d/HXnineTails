import configparser
import os
import csv,logging


logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


FILE = 'config.ini'
conf = configparser.ConfigParser()
conf.read(FILE, encoding="GBK")
PYTHON = conf.items('commom')[0][1]
current_work_path = os.getcwd()

# 一些小功能函数
class base():
    #删除url的http头
    def http_url_delete(self, url):
        if ':' in url:
            _tmp = url.split(':///')
            url = _tmp[1]
        if '.' in url:
            _tmp = url.split('.')
            url = f'{_tmp[-3]}.{_tmp[-2]}.{_tmp[-1]}'

        return url


# 配置一组有效参数
def configure_a_group_param(items):
    valid_param = list()
    for item in items:
        if item[0] == 'script_path':
            _tmp = list(item)
            valid_param.append(_tmp[1])
            continue
        if item[0] == 'True':
            _tmp = list(item)
            _tmp[1] = ' '
            continue
            valid_param.append(_tmp)
        if item[1]:
            valid_param.append(item)
            
    return valid_param


class oneforall():
    def __init__(self, target):
        self.target = target

    def run(self):
        cmd = PYTHON + f' {oneforall_param[0]}oneforall.py'
        for item in oneforall_param[1:]:
        #将配置好的参数交付给对应脚本执行
            cmd += f' {item[0]} {item[1]} ' 
        cmd += f' --target {self.target} run'
        logger.info("oneforall run : " + cmd)
        # os.system(cmd)

        #提取csv文件里的扫描信息
        save_path = oneforall_param[0] + 'results\\' + f'{func.http_url_delete(self.target)}.csv'
        reader = csv.reader(open(save_path, "r"))
        for item in reader:
            if reader.line_num == 1:  # 忽略第一行
                continue
            #print(item[4])
            #config.sub_queue.put(item[4])



class subdomainbrute():
    def __init__(self, target):
        self.target = target

    def run(self):
        cmd = PYTHON + f' {subdomainbrute_param[0]}subDomainsBrute.py'
        for item in subdomainbrute_param[1:]:
        #将配置好的参数交付给对应脚本执行
            cmd += f' {item[0]} {item[1]} ' 
        cmd += f' {self.target}'
        logger.info("subdomainbrute run : " + cmd)
        #os.system(cmd)


class sublist3r_():
    def __init__(self, target):
        self.target = target

    def run(self):
        cmd = PYTHON + f' {sublist3r_param[0]}sublist3r.py'
        for item in sublist3r_param[1:]:
        #将配置好的参数交付给对应脚本执行
            cmd += f' {item[0]} {item[1]} '
        cmd += f' -d {self.target}'
        logger.info("sublist3r run : " + cmd)
        os.system(cmd)


class subfinder():
    def __init__(self, target):
        self.target = target

    def run(self):
        cmd = PYTHON + f' {subdomainbrute_param[0]}subDomainsBrute.py'
        for item in subdomainbrute_param[1:]:
        #将配置好的参数交付给对应脚本执行
            cmd += f' {item[0]} {item[1]} ' 
        os.system(cmd)


class xray():
    pass


if __name__ == '__main__':
    # 循环为所有脚本获取参数
    for name in conf.sections():
        if name == 'common':
            pass
        if name == 'oneforall':
            oneforall_param = configure_a_group_param(conf.items(name))
        if name == 'subdomainbrute':
            subdomainbrute_param = configure_a_group_param(conf.items(name))
        if name == 'sublist3r':
            sublist3r_param = configure_a_group_param(conf.items(name))
        if name == 'subfinder':
            subfinder_param = configure_a_group_param(conf.items(name))


    func = base()
    subdomainbrute('cqut.edu.cn').run()
    oneforall('cqut.edu.cn').run()
    sublist3r_('cqut.edu.cn').run()




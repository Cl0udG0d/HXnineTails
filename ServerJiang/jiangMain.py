import requests

from Hx_config import SERVERKEY

'''
项目集成Server酱进行扫描结束的消息推送
关于Server酱：http://sc.ftqq.com/3.version
'''
api = "https://sc.ftqq.com/{}.send".format(SERVERKEY)


def SendNotice(message):
    try:
        title = "花溪九尾 扫描通知"
        data = {
            "text": title,
            "desp": message
        }
        req = requests.post(api, data=data)
    except Exception as e:
        print(e)
        pass
    return

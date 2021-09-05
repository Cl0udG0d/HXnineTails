import json
import random
def GetHeaders():
    try:
        with open('Useragent.json', 'r') as f:
            data = json.load(f)
            data_browsers =data['browsers']
            data_randomize = list(data['randomize'].values())
            browser = random.choice(data_randomize)
            headers = {'User-Agent': random.choice(data_browsers[browser])}

            return headers
    except Exception as e:
        exit("[*]Hx_config.py   :   GetHeaders error!")

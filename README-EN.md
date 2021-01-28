
## HXnineTails 花溪九尾

> **Plain** **Violent** **Powerful** **Self-expanding stitching monster**

```python
+-+-+-+-+-+-+-+-+-+-+-+-+
|H|X|n|i|n|e|T|a|i|l|s|
+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Content List🚀

- [Introduction](#Introduction)
- [Install](#Install)
- [Instructions](#Instructions)
- [screenshots](#screenshots)
- [TODO](#TODO)
- [Maintainer](#Maintainer)
- [Contribute](#Contribute)
- [Reward](#Reward)
- [License](#License)
- [Appreciation_Code](#Appreciation_Code)



### Introduction

:paw_prints:`python3` implementation of a command-line WEB scanning tool that integrates several scanning tools on `github`.

:trident:The goal is to lie down and dig a hole

The project code is tested under the latest community version of `xray1.7` without errors

Currently integrated in this project: [crawlergo](https://github.com/0Kee-Team/crawlergo) [OneForAll](https://github.com/shmilylty/OneForAll) [subDomainsBrute] (https://github.com/lijiejie/subDomainsBrute) [Subfinder](https://github.com/projectdiscovery/subfinder) [Sublist3r](https://) github.com/aboul3la/Sublist3r) [Xray](https://github.com/chaitin/xray) [JSfinder](https://github.com/Threezh1/JSFinder) [pppXray]( https://github.com/Cl0udG0d/pppXray) [Server Sauce](http://sc.ftqq.com/3.version)

The next project that I want to integrate is [ARL Asset Lighthouse System](https://github.com/TophantTechnology/ARL)

The result of the project is the fusion of these individually powerful components into a single application, suitable for SRC batch scanning, CNVD vertical upscaling, etc.

`Project structure: `

! [Project Structure](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Architecture.png)



### Installation

Install `python3` (`python2` is not supported at this time)

Download the code for this project: `git clone https://github.com/Cl0udG0d/HXnineTails`

Install the appropriate library files `pip3 install -r requirements.txt` 

> For domestic users, the first line of `requirements.txt` uses the Aliyun mirror
>
> If you are installing `python` library files on a foreign server, please delete the first line of `requirements.txt` for speedup

The following project needs to be installed and the path configured in the `config.py` file

[Google Chrome](https://www.google.com/intl/zh-CN/chrome/)

[Xray](https://github.com/chaitin/xray/releases) (better with the premium version)

[crawlergo](https://github.com/0Kee-Team/crawlergo/releases)

[OneForAll](https://github.com/shmilylty/OneForAll/releases)

[subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)

[subfinder](https://github.com/projectdiscovery/subfinder/releases)



For example, on my personal laptop, the path information in `config.py` is

```python
'''
Paths where each project is located.
'''
Chrome_Path='C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
Xray_Path='D:\\Xray\\\xray.exe'
crawlergo_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\crawlergo.exe'
OneForAll_Path='C:\\\Users\\\Administrator\\\Desktop\\\test_tools\\\\OneForAll-master\'
subDomainsBrute_Path='C:\\Users\\\Administrator\\\Desktop\\\test_tools\\\\\subDomainsBrute-master\'
subfinder_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\subfinder\\'
```

Open the command line in the `HXnineTails` folder and enter the scan parameters



### Instructions

Command line use, with the following parameter details.

```python
-h --help output help information such as python3 scan.py --help
-a --attone for a single URL, only crawlergo dynamic crawler + xray scan For example Baidu official website python3 scan.py -a https://www.baidu.com
-s --attsrc for SRC assets, information gathering +crawlergo+xray , for example Baidu SRC python3 scan.py -s baidu.com
-d --attdetail for SRC assets, information collection + crawlergo + xray + C segment information collection + js sensitive information collection , for example Baidu SRC input python3 scan.py -d baidu.com
-t --thread Number of threads, default is 5 e.g. python3 scan.py -t 10 -a http://testphp.vulnweb.com/ 
-r reads the txt file to be scanned, one URL per line, and -a scans each URL taken out, e.g. python3 scan.py -t 10 -r target.txt
-c Clean up the saved vulnerability-related reports, i.e. clean up the files in the save folder
```

It is recommended to use the `-a` or `-s` parameter for scanning

There are also some global configurations in `config.py` that can be modified by yourself, such as

```python
SERVERKEY=''

portlist=['80','8080','8000','8081','8001']
blacklist=["spider", "org"]

ThreadNum=5
PYTHON="python3"
```

`SERVERKEY` is the `key` value used by Server Sauce for your registration

`portlist` is the default list of ports scanned during C-segment scanning

The string in `blacklist` that appears in the URL to be scanned will not be scanned

`ThreadNum` The default number of threads

`PYTHON` The name of the host python interpreter, default is `python3`



**Some external programs or configurations are mentioned above, if you don't need to use them in your scan, you can leave them uninstalled and they will pass by themselves during the program run**

### screenshots

```shell
python3 scan.py --help
```

! [Screenshot 1](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/1.png)

```shell
python3 scan.py -t 3 -a http://testphp.vulnweb.com/
```

! [Screenshot 2](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/2.png)

View saved reports

! [Screenshot 3](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/3.png)



### TODO

+ ~~Write an English readme~~
+ Streamline and add modules
+ Add ARL module
+ ...



### Maintainer

[@春告鳥](https://github.com/Cl0udG0d)
[@HNIJK](https://github.com/HNIJK)



### Contribute

:beer:You're very welcome to join us! [Raise an Issue](https://github.com/Cl0udG0d/HXnineTails/issues/new) or submit a Pull Request.

:beers:And of course feel free to send me an email at 2585614464@qq.com Join us!



### Reward

+ `Backer Language` 



### License

[MIT](LICENSE) © Spring Teller



### Appreciation_Code

**If it helps you, how about buying the author a cup of milk tea? ~~(hehehe)~~:+1: (Please leave a message with your ID** when you reward

![打赏码](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Praise.png)

## HXnineTails 花溪九尾

[English](https://github.com/Cl0udG0d/HXnineTails/blob/main/README.md) | 简体中文

> **平凡** **暴力** **强大** **可自行扩展的缝合怪物**

```python
+-+-+-+-+-+-+-+-+-+-+-+
|H|X|n|i|n|e|T|a|i|l|s|
+-+-+-+-+-+-+-+-+-+-+-+
```

### 内容列表🚀

- [简介](#简介)
- [安装](#安装)
- [使用说明](#使用说明)
- [部分截图](#部分截图)
- [TODO](#TODO)
- [维护者](#维护者)
- [如何贡献](#如何贡献)
- [打赏列表](#打赏列表)
- [使用许可](#使用许可)
- [赞赏码](#赞赏码)



### 简介

:paw_prints:`python3`实现的集成了`github`上多个扫描工具的命令行WEB扫描工具

:trident:目标是躺着挖洞

项目代码在最新版社区版`xray1.7`，专业版`xray1.3.3`下检测无误

该项目中目前集成：[crawlergo](https://github.com/0Kee-Team/crawlergo) [OneForAll](https://github.com/shmilylty/OneForAll) [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute) [Subfinder](https://github.com/projectdiscovery/subfinder) [Sublist3r](https://github.com/aboul3la/Sublist3r) [Xray](https://github.com/chaitin/xray) [JSfinder](https://github.com/Threezh1/JSFinder) [pppXray](https://github.com/Cl0udG0d/pppXray) [Server酱](http://sc.ftqq.com/3.version)

下一个想要集成的项目是[ARL资产灯塔系统](https://github.com/TophantTechnology/ARL)

项目的成果在于将这些单独强大的组件融合到一个单一的应用中，适用于SRC批量扫描，CNVD垂直上分等

`项目结构：`

![项目结构](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Architecture.png)

### 安装

安装`python3` （暂不支持 `python2`

下载本项目代码: `git clone https://github.com/Cl0udG0d/HXnineTails`

安装相应的库文件 `pip3 install -r requirements.txt` 

> 为方便国内用户，在`requirements.txt`第一行使用了阿里云镜像
>
> 如果是国外服务器进行`python`库文件安装，为提速请删除`requirements.txt`第一行

需要安装下列项目，并将路径配置在`config.py`文件中

[谷歌浏览器](https://www.google.com/intl/zh-CN/chrome/)

[Xray](https://github.com/chaitin/xray/releases) （配合高级版食用更佳

[crawlergo](https://github.com/0Kee-Team/crawlergo/releases)

[OneForAll](https://github.com/shmilylty/OneForAll/releases)

[subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)

[subfinder](https://github.com/projectdiscovery/subfinder/releases)



例如在我的个人笔记本电脑上，`config.py`中的路径信息为：

```python
'''
各个项目所在路径：
'''
Chrome_Path='C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
Xray_Path='D:\\Xray\\xray.exe'
crawlergo_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\crawlergo.exe'
OneForAll_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\OneForAll-master\\'
subDomainsBrute_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\subDomainsBrute-master\\'
subfinder_Path='C:\\Users\\Administrator\\Desktop\\test_tools\\subfinder\\'
```

在`HXnineTails`文件夹下打开命令行输入扫描参数

### ARL配置

第一步：确定部署完成并且可以正确访问ARL后台

第二步：修改黑名单（如果有需要的话）

![image-20210818003323362](C:\Users\Th\Documents\工具库\HXnineTails\README-ZH.assets\image-20210818003323362.png)

第三步：设置api访问token

打开这个文件进行设置

![image-20210817235844858](C:\Users\Th\Documents\工具库\HXnineTails\README-ZH.assets\image-20210817235844858.png)

另外如果你是本地访问的话，下面BlACK_IPS记得注释掉本地地址

![image-20210818003406757](C:\Users\Th\Documents\工具库\HXnineTails\README-ZH.assets\image-20210818003406757.png)

测试：



![image-20210818003639711](C:\Users\Th\Documents\工具库\HXnineTails\README-ZH.assets\image-20210818003639711.png)

### 使用说明

命令行使用，参数详情为：

```python
--help 输出帮助信息 如python3 scan.py --help
-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 python3 scan.py -a https://www.baidu.com
-s --attsrc 对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC python3 scan.py -s baidu.com
-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入 python3 scan.py -d baidu.com
-t --thread 线程数量，默认线程为5 如 python3 scan.py -t 10 -a http://testphp.vulnweb.com/ 
-r 读取待扫描txt文件，每行一个URL 对取出的每个URL进行 -a 扫描，如 python3 scan.py -t 10 -r target.txt
-c 对保存的漏洞相关报告进行清理，即清理save文件夹下的文件
-p --plugins 自定义xray插件 例如 python3 scan.py -a https://www.baidu.com --plugins sqldet
```

建议使用 `-a` 或 `-s`参数进行扫描

另外有一些全局配置在`config.py`中，可以自行修改，如：

```python
SERVERKEY=''

portlist=['80','8080','8000','8081','8001']
blacklist=["spider","org"]

ThreadNum=5
PYTHON="python3"
```

`SERVERKEY`是Server酱 你注册使用的`key`值

`portlist`是C段扫描时的默认扫描端口列表

`blacklist` 中的字符串，若出现在待扫描URL中，该URL不会被扫描

`ThreadNum` 默认的线程数量

`PYTHON` 主机python解释器的名称，默认为`python3`



**上面提到了一些外部程序或配置，如果在你的扫描中不需要用到的话，可以不进行安装，在程序运行过程中会自行pass掉**

### 部分截图

```shell
python3 scan.py --help
```

![截图1](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/1.png)

```shell
python3 scan.py -t 3 -a http://testphp.vulnweb.com/
```

![截图2](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/2.png)

查看保存的报告

![截图3](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/3.png)



### TODO

+ ~~写个英文readme~~（感谢老哥 [wenyurush](https://github.com/wenyurush)）
+ 精简和添加模块
+ 添加ARL模块
+ ...



### 维护者

[@春告鳥](https://github.com/Cl0udG0d)

[@Throokie](https://github.com/Throokie)



### 如何贡献

:beer:非常欢迎你的加入！[提一个 Issue](https://github.com/Cl0udG0d/AutumnWater/issues/new) 或者提交一个 Pull Request。

:beers:当然也欢迎给我发邮件  2585614464@qq.com Join us！

🍻也可以给Throokie发邮件！326516678@qq.com


### 打赏列表

+ `背人语` 
+ `掌控安全-hab`



### 使用许可

[MIT](LICENSE)  © 春告鳥



### 赞赏码

**如果对你有帮助的话要不请作者喝杯奶茶?~~(嘿嘿)~~:+1: (打赏时请留言你的ID**

![打赏码](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Praise.png)

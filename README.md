## HXnineTails 花溪九尾

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

该项目中目前集成：[crawlergo](https://github.com/0Kee-Team/crawlergo) [OneForAll](https://github.com/shmilylty/OneForAll) [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute) [Subfinder](https://github.com/projectdiscovery/subfinder) [Sublist3r](https://github.com/aboul3la/Sublist3r) [Xray](https://github.com/chaitin/xray) [JSfinder](https://github.com/Threezh1/JSFinder) [pppXray](https://github.com/Cl0udG0d/pppXray)

下一个想要集成的项目是[ARL资产灯塔系统](https://github.com/TophantTechnology/ARL)

项目的成果在于将这些单独强大的组件融合到一个单一的应用中，适用于SRC批量扫描，CNVD垂直上分等

`项目结构：`

![项目结构](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Architecture.png)



### 安装

安装`python3` 暂不支持 `python2`

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





### 使用说明

命令行使用，参数详情为：

```python
-h --help 输出帮助信息
-a --attone 对单个URL，只进行crawlergo动态爬虫+xray扫描 例如 百度官网 输入 https://www.baidu.com
-s --attsrc 对SRC资产，进行信息搜集+crawlergo+xray , 例如 百度SRC  输入 baidu.com
-d --attdetail 对SRC资产,进行信息搜集+crawlergo+xray+C段信息搜集+js敏感信息搜集 , 例如 百度SRC 输入baidu.com
-t --thread 线程数量
-r 读取待扫描txt文件，每行一个URL 对取出的每个URL进行 -a 扫描
```

`默认对输入的域名进行 -s 扫描`



### 部分截图





### TODO

+ 写个英文readme
+ 精简和添加模块
+ Server酱提醒



### 维护者

[@春告鳥](https://github.com/Cl0udG0d)



### 如何贡献

:beer:非常欢迎你的加入！[提一个 Issue](https://github.com/Cl0udG0d/AutumnWater/issues/new) 或者提交一个 Pull Request。

:beers:当然也欢迎给我发邮件  2585614464@qq.com Join us！



### 打赏列表





### 使用许可

[MIT](LICENSE)  © 春告鳥



### 赞赏码

**如果对你有帮助的话要不请作者喝杯奶茶?~~(嘿嘿)~~:+1: (打赏时请留言你的ID**

![打赏码](https://github.com/Cl0udG0d/HXnineTails/blob/main/images/Praise.png)
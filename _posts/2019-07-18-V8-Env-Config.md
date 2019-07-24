---
layout: post
title:  "V8环境搭建，100%成功版"
date:   2019-07-18 00:00:00 +0000
categories: jekyll update
---

## 0x00 前言

众所周知，V8是著名浏览器Chrome的JavaScript引擎，而Chrome又由Google开发，又因为某些不能说的原因，我们没有办法直接访问一些Google在因特网上的服务，包括当配置V8环境时所需要下载的部分资源。这导致搭建V8环境的时候，非常的痛苦。目前在网上有一些方法可以成功搭建，但是都有一些局限，而且容易失败，尤其是当我折腾的时候。我有一种超能力，就是在搭建环境的时候可以把所有的坑，不管是有人遇到过的还是没人遇到过的，不管是能解决的还是不能解决的，都特么会撞上。这里介绍的方法，就算是在我身上，都可以成功搭建。所以如果有人用这个方法搭建失败的话，我直播女装。

## 0x01 废话

这一小节我会讲一些废话，关于自己搭建环境的心路历程，如果只是想来看怎么搭建V8环境的话可以直接跳过。

最开始，我是搞了个在香港的阿里云，然后参考[这个](http://eternalsakura13.com/2018/06/26/v8_environment/)搭建的。这篇文章简单地来说就是让你在墙外的服务器上搭建编译好，然后用FTP传回来（其实`scp`也行）。简单暴力，我喜欢。

但是这有两个问题，第一个问题，编译好的V8真的是大，用`tar`压缩好之后都有1.8个G，然后传回来的速度有时候特慢，正常情况是`100 kb/s`左右，这传一次就要3个小时，这真是生动的体现了“做题5分钟，搭建3小时”。

第二个问题，远程编译的时候，会出错会出错会出错。远程服务器是Ubuntu的时候，执行`tools/dev/v8gen.py`脚本的时候，会出现异常；远程服务器是CentOS的时候，编译debug版本的时候，`clang++`会直接炸。上几张图感受一下。

![什么叫做绝望1](/images/1563443101608.png)

![什么叫做绝望2](/images/1563443019673.png)

然后还有一个方法，就是[搭全局VPN](http://eternalsakura13.com/2018/07/20/v8_xcode/)，但是这很容易被某些不能说的东西检测到然后被ban，所以这个方法肯定也不行。

## 0x02 准备

环境`Ubuntu 18.04`，非此环境本人不负责女装，但是就算不是这个环境应该也不会出错。

首先我们需要一个http代理，这个用ＳＳＲ就行，具体因为某些不能说的原因不详细阐述。

然后先配置代理，首先我们需要[配置git的代理](https://gist.github.com/evantoli/f8c23a37eb3558ab8765)，这样在执行git命令的时候，比方说`git clone`，就会通过代理来下载。具体命令：

```bash
git config --global http.proxy http://proxyUsername:proxyPassword@proxy.server.com:port
```

一般来讲ＳＳＲ是没有用户名和密码的，所以一般这条命令会长这样：

```bash
git config --global http.proxy http://ip:port
```

其中`ip`可以是`127.0.0.1`也可以是`192.168.xxx.xxx`，取决于你的http代理在哪，`port`同理。

然后配置git的代理还不够，因为配置环境的时候也会用到`curl`这条命令，所以还得在环境变量设置一个代理。具体方法是在`~/.bashrc`最后面加上这两行命令，其中`ip:port`换成你的http代理：

```bash
export http_proxy="http://ip:port/"
export https_proxy=$http_proxy
```

然后在命令行里打`bash`，这样可以重新加载`~/.bashrc`，载入代理的环境变量。

## 0x03 配置

这个就简单了，跟网上[其他人的资料](http://eternalsakura13.com/2018/05/06/v8/)的没啥区别。

### 安装depot_tools

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
echo 'export PATH=$PATH:"/path/to/depot_tools"' >> ~/.bashrc
# clone depot_tools，并且把depot_tools的目录加到PATH环境变量，
# /path/to/depot_tools改成depot_tools的目录
# 因为git加了代理所以第一个命令可以成功clone了
```

### 安装ninja

```bash
git clone https://github.com/ninja-build/ninja.git
cd ninja && ./configure.py --bootstrap && cd ..
# clone并且configure
echo 'export PATH=$PATH:"/path/to/ninja"' >> ~/.bashrc
# /path/to/ninja改成ninja的目录
```

### 编译v8

```bash
bash
# 重新开一个bash，这样新的环境变量才会被加载
fetch v8
# 下载v8的repo，这个也是需要git代理才能成功下载的
cd v8 && gclient sync
# gclient sync 用来下载一些其他需要的东西，
# 这个还需要curl的代理，之前也已经在环境变量配置了
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug
# 编译
```

然后如果只是想编译`d8`的话（这样更快），最后一个命令后面加个`d8`的参数`ninja -C out.gn/x64.debug d8`。

编译release版本的话，最后两行改成这个。

```bash
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release
```

同理最后一个命令改成`ninja -C out.gn/x64.release d8`只编译`d8`。

然后顺便说一下，在执行`gclient sync`的时候，可能会提示这个。

>NOTICE: You have PROXY values set in your environment, but gsutilin depot_tools does not (yet) obey them.
Also, --no_auth prevents the normal BOTO_CONFIG environmentvariable from being used.
To use a proxy in this situation, please supply those settingsin a .boto file pointed to by the NO_AUTH_BOTO_CONFIG environmentvariable.

这个无所谓，似乎因为在这里要下载的东西不会被墙，如果哪天这个会导致失败的话就按照这个指示设置一下环境变量，如果可以成功本人也不负责女装。

## 0x04 启动

### release

```bash
./out.gn/x64.release/d8
# 启动interactive d8 shell
./out.gn/x64.release/d8 test.js
# 运行test.js
```

### debug

```bash
./out.gn/x64.debug/d8
# 启动interactive d8 shell
./out.gn/x64.debug/d8 test.js
# 运行test.js
```

## 0x05 Turbolizer搭建

首先，Ubuntu下默认的apt里面的nodejs不好使，必须得[安装最新版的](https://tecadmin.net/install-latest-nodejs-npm-on-ubuntu/)：

```bash
sudo apt-get install curl python-software-properties
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt-get install nodejs
```

`python-software-properties` 有些情况下他可能会找不到，然后会提示你安装另一个包，如果是这样的话根据提示安装那个包就好了。

然后安装并启动turbolizer

```bash
cd v8/tools/turbolizer
npm i
npm run-script build
python -m SimpleHTTPServer
```

接着用chrome浏览器访问`ip:8000`就能用了，这个完全加载好要等一小会，因为如果你看HTTP包的话会发现他会从`cdn.rawgit.com`获取了一个文件，而这个是有点慢的。不过如果开梯子的话就会快多了。

以后如果有空的话我会研究一下弄个docker，这样配置起来就会方便多了。

## 0x06 GDB插件

V8还有一个gdb插件，可以方便GDB调试。具体安装方法很简单了，在文件`~/.gdbinit`最后面加上这两行。

```
source /path/to/v8/tools/gdbinit
source /path/to/v8/tools/gdb-v8-support.py
```

`/path/to/`改成实际放置v8 repo的文件夹绝对路径。
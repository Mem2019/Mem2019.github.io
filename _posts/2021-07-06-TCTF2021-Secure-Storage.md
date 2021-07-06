---
layout: post
title:  "TCTF 2021 Secure Storage"
date:   2021-07-06 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Last weekend I played TCTF Qualifier online and spent all of my time on this challenge, but still failed to solve it in time. After the contest, I finally solved this challenge. This is a crazy nested challenge: we firstly need to use side channel attack to leak `admin_key.txt`; then we need to exploit `ss_agent` to get the ability to open and operate on `/dev/ss`; then we need to exploit `ss.ko` to get the root shell; finally we need to exploit `qemu` to get the flag outside. Since the `qemu` part has no relation to other parts of the challenge, and it's my teammate rather than me who solved this part, I will not cover it in this writeup. 

## 0x01 Reverse Engineering

### ss_agent

This is a menu Pwn challenge. In initialization, it firstly adds a `flock` to itself to prevent multiple instances being run, and reads `admin_key.txt` to a global buffer. It has 4 options:

1. **register**: read a length and a name from `stdin`, and store them with `admin_key` to kernel storage slot 0; note that the length passed to kernel storage is buffer length instead of actual length of the name, so it is possible to leak uninitialized heap buffer data here.
2. **store**: read slot, data and key from `stdin`, and store them to kernel storage with given slot. The slot here cannot be 0.
3. **retrieve**: read slot and key from `stdin`, and compare the given key with key stored in kernel storage with given slot; if they are same, output the data stored in kernel storage.
4. **kick**: read admin key from `stdin`, and compare the given key with key stored in kernel storage slot 0; if they are same, output the data in storage 0 (which is the name provided in register) and free the name pointer without setting it to `NULL`, so here is a *double free*.

The **kernel storage** access is implemented by `ioctl` and `mmap`, the user-space code is shown below:

```c
char *__fastcall get_ss_mmap_page(unsigned int slot)
{
  char *result; // rax
  signed int fd; // [rsp+10h] [rbp-10h]
  int fd_4; // [rsp+14h] [rbp-Ch]
  char *v4; // [rsp+18h] [rbp-8h]

  fd = open("/dev/ss", 2); // open /dev/ss
  if ( fd < 0 )
    return 0LL;
  if ( (ioctl(fd, 0, slot) & 0x80000000) == 0LL ) // use ioctl to set the slot
  {
    v4 = (char *)mmap(0LL, 0x10000uLL, 3uLL, 1uLL, (unsigned int)fd, 0LL);
    // use mmap to map the kernel storage into user space
    fd_4 = close(fd);
    if ( v4 && fd_4 >= 0 )
      result = v4; // return the kernel page if there is no problem
    else
      result = 0LL;
  }
  else ...
  return result;
}
```

The format of kernel storage is 8-byte data length + data + 32-byte key, as we can see when `ss_agent` writes the storage.

```c
__int64 __fastcall write_to_storage(unsigned int slot, char *a2, unsigned __int64 len, char *a4)
{
  __int64 result; // rax
  char *v7; // [rsp+28h] [rbp-8h]

  if ( len > 0xFFD7 )
    return 0xFFFFFFFFLL;
  v7 = get_ss_mmap_page(slot);
  if ( !v7 )
    return 0xFFFFFFFFLL;
  *(_QWORD *)v7 = len;
  _memcpy((v7 + 8), a2, len);
  _memcpy(&v7[len + 8], a4, 32LL);// layout: length + data + key
  if ( (int)munmap((__int64)v7) >= 0 )
    result = 0LL;
  else
    result = 0xFFFFFFFFLL;
  return result;
}
```

However, to exploit this `ss_agent`, we have to leak `admin_key.txt` first, otherwise we cannot trigger the double free bug.

### ss.ko

This is the kernel module that implements `/dev/ss` device. The functionality can be briefly described as follows:

1. In handler of `open` at `0x390`, `private_data` field (`+0xc8`) of `struct file*` is initialized to a structure used to store `slot`, which is initialized to value `-1`.
2. In handler of `ioctl` at `0x710`, slot is stored into structure pointed by `private_data`; note that we can only call `ioctl` once for each `fd`.
3. In handler of `mmap` at `0x7e0`, page fault handler `0x3e0` is registered.
4. The handler of page fault at `0x3e0` is an important function, so its code is shown below:

```c
__int64 __fastcall fault(struct vm_fault *fau)
{
  unsigned int v1; // er14
  int v2; // eax
  unsigned __int64 access_off; // rbx
  __int64 slot; // r12
  char *returned_vpage; // r15
  __int64 phy_page; // rax
  __int64 v7; // rcx
  __int64 v8; // rdx
  __int64 v9; // r13
  int v10; // er12
  mut *v11; // r13
  int page_idx; // eax
  int v13; // ebx
  char *v14; // r12
  int v15; // edx

  v1 = 2;
  v2 = (LODWORD(fau->vma->vm_pgoff) << 12) + ((fau->pgoff - LODWORD(fau->vma->vm_start)) & 0xFFFFF000);
  // vm_pgoff seems to be 0;
  // pgoff seems to be virtual address accessed with low 12 bits cleared to 0;
  // vm_start seems to be base virtual address returned from mmap
  if ( v2 <= 0xFFFF ) // negative v2 can pass the check!
  {
    access_off = v2;
    slot = **(_QWORD **)(fau->vma->vm_file + 200);
    returned_vpage = &mmap_buffer[0x10000 * slot + v2];
    // calculate buffer address corresponding to the access
    phy_page = vmalloc_to_page(returned_vpage);
    v7 = *(_QWORD *)(phy_page + 8);
    v8 = v7 - 1;
    if ( (v7 & 1) == 0 )
      v8 = phy_page;
    _InterlockedIncrement((volatile signed __int32 *)(v8 + 0x34));
    fau->page = (struct page *)phy_page;        // return the page
    v9 = slot;
    v10 = 16 * slot;
    v11 = &mutexes[v9];
    mutex_lock(v11);
    page_idx = v10 + (access_off >> 12);        // offset to mmap_buffer >> 12
    v13 = ((_BYTE)v10 + (unsigned __int8)(access_off >> 12)) & 7;
    v14 = &bitmap[page_idx >> 3];
    v15 = (unsigned __int8)*v14;
    if ( !_bittest(&v15, v13) )
    // use offset in PAGE_SIZE unit as index to access the bitmap
    {
      if ( (unsigned int)sub_90(page_idx, returned_vpage, 0) )
      {
        mutex_unlock(v11);
        return v1;
      }
      *v14 |= 1 << v13;                         // set to 1
    }
    v1 = 0;
    mutex_unlock(v11);
  }
  return v1;
}
```

When we use this kernel module, following occurs step by step:

1. We call `open` to open `/dev/ss`, `ioctl` to set slot, and `mmap` to register the fault handler and return a piece of virtual memory corresponding to the handler, without actually allocating physical memory for the virtual memory.
2. When we first time use the virtual memory returned from `mmap`, the page fault handler at `0x3e0` is called.
3. The handler firstly calculate the offset of accessed page to virtual address returned from `mmap`, the value is stored in `v2`; and then it checks value of `v2`, the process continues only if `v2 <= 0xffff`.
4. The handler obtains value of `slot` from `struct file*`, it then calculates the page to be returned using `&mmap_buffer[0x10000 * slot + v2]`; in other word, this kernel page is going to be mapped into user space; `mmap_buffer` is a global buffer in `ss.ko` with size `0x100000`.
5. Then `vmalloc_to_page` is called to convert the kernel virtual address into physical address, and its return value is set to `page` field of `struct vm_fault*` as the result of this fault handler.
6. Then the offset stored in `v2` is shifted and used as index to a bitmap; if the returned bit is zero, `sub_90` is called on the returned page, in which many operations are done; then that bit is set to one.
7. After fault handler is returned, the corresponding virtual memory in user space now has physical memory mapping, which maps to corresponding page in `mmap_buffer`; so future access to this virtual page will not cause fault anymore.

### Debugging

To inspect memory of `ss.ko` and set breakpoint to `ss.ko`, we need to know its address in memory. My approach is shown as following:

1. Use `cat /proc/kallsyms | grep cleanup_module` to get address of function `cleanup_module`
2. In `gdb`, type `x/2i` on address from step 1, then we can get address of `unk_1300`
3. In `gdb`, type `x/10gx` on address from step 2, then we can get address of `sub_0`, which is base address of code segment
4. In `gdb`, type `x/i` on address from step 3 `+0x669`, we can get address of `mmap_buffer`

## 0x02 Side Channel Attack

Now we are going to leak `admin_key.txt` using time-based side channel attack. We observed that: 1. `memcmp` function is implemented byte-by-byte; 2. page fault that calls `sub_90` takes quite long time. Therefore, we can manipulate the layout of slot 0 so that the first byte of `admin_key` is in the first page and remaining parts are in the second page. Therefore, when we call `kick`, if first byte of our input does not equal to first byte of `admin_key`, the second page will not be accessed so comparison should be fast; otherwise the second byte will be accessed, causing page fault and `sub_90` to be called, which makes comparison slow. We can use this approach to brute-force first byte of `admin_key`. Then we can shift the `admin_key` to left (e.i. reduce length of name) by 1 byte and use the same approach to get the following bytes.

Note that we cannot do this in Python `pwntools`, because network latency fluctuation is much more than the difference mentioned above. Instead, we have used C to implement such attack. We upload the program to remote and run it directly, so there will be no network latency. Anonymous pipe is used for IO interaction, and `__rdtsc` is used for time difference calculation, you can read exploit code for more details.

Another thing to note is we need to ensure `sub_90` to be called when handling page fault, otherwise the latency might be insignificant. This is the case if we separate name registration and kick comparison into different process instances.

The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/SecureStorage/exp.c).

## 0x03 Exploit `ss_agent`

As I briefly mentioned above, there is a double free bug in `ss_agent`. Trying the double free for small-size chunk, we found that there is no crash, and there is `tcache` string in the binary, so I would say the static binary is generated using possibly `libc-2.27`. Knowing this, we can write exploit like a normal menu challenge:

1. Trigger double free to poison `tcache`, so we can leak heap address.
2. By debugging, we found that some program data addresses are stored in heap section; although I am not sure why, program address can be leaked by allocating chunk at that region.
3. There is also a stack address stored in heap section, so we can leak it in the same way as step 2.
4. Allocate a chunk at stack, so we can write ROP, which means `ss_agent` has already been compromised.

Instead of using `pwntools`, I used C for this part again, because I found that sending binary data via `qemu` interface causes problem.

To debug this binary, I patched it so that only heap operations remain. Thus we can run it without `/dev/ss`. This makes debugging much more convenient since we don't need to deal with kernel stuff anymore.

The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/SecureStorage/exp2.c).

Initially I thought I could have root once `ss_agent` is compromised, because it has a `setgid` being set. However, this is wrong. The access permission of `/challenge/ss_agent` is `-rwxr-sr-x` and access permission of `/dev/ss` is `crw-rw----`. Therefore, although `ss_agent` can access `/dev/ss`, it does not run in root; instead, it runs in the group of root; and such group privilege even does not persist after an `execve` system call.

However, we need to run arbitrary code that can operate on `/dev/ss` in order to exploit `ss.ko`. I came up with 2 approaches:

1. Compile the exploit into shellcode, and run the shellcode in `/challenge/ss_agent` process to get the root shell; however, this is quite complicated to do.
2. Open `/dev/ss` in ROP chain, and `execve` to our exploit; these opened file descriptors will remain valid after `execve`; thus we can operate on `/dev/ss` even if we don't have permission to open it.

Obviously, the second one is more convenient for us.

## 0x04 Exploit `ss.ko`

Now we come back to `ss.ko` in order to get root shell. The bug is in page fault handler: `v2 <= 0xFFFF` is a signed comparison; if `v2` is negative, we can pass the check and map unintended page into user space. Since `v2` is a 32-bit signed integer, we can call `mmap` with size `0x100000000`, and access the last few pages to make `v2 = -0x1000 * n`. It turns out `returned_vpage` will be page before `mmap_buffer`. 

In addition, to prevent `sub_90` from being called, we need to ensure `_bittest` to return 1. Fortunately, the bitmap is behind `mmap_buffer` exactly, so if we set the last page of `mmap_buffer` to `0xff`, `_bittest` can always return 1 for small negative index.

By debugging, we found there are many useful leaks in the pages before `mmap_buffer`: we can leak the Linux kernel address and `ss.ko` address easily.

I have come up with 4 approaches for exploitation, but finally only the last one works:

1. Map kernel heap into user space; however, heap is too far from `ss.ko`: heap address is usually `0xffffxxxxxxxxxxxx` but `ss.ko` address is `0xffffffffxxxxxxxx`, so we cannot reach heap in 32 bits.
2. Map page that stores `modprobe` path into user space; however, when calling `vmalloc_to_page` on that page, the function returns `NULL`. I think the reason is probably that this function can convert virtual address to physical address only if this virtual address is allocated via `vmalloc`, and that page does not satisfy this condition.
3. Change the function pointer at `0x1600` to hijack kernel rip. We can do this because when we call `mmap`, the function here will be registered as page fault handler. However, we can do nothing after controlling `rip`, since `smep` is enabled.
4. Map code page of `ss.ko` into user space and write shellcode into kernel directly. Yes! We can do this! Although code page in kernel is not writable, this is not the case after we map it into user space. Therefore, what I did is rewriting code of `mmap` handler in kernel into `commit_creds(prepare_kernel_cred(0))`, so that we can get root privilege after `mmap` is called.

The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/SecureStorage/exp3.c).

## 0x05 Conclusion

This nested challenge is really complicated, but I have learned a lot from it. In addition, I think it is better to put one flag at each stage, instead of one flag for the whole exploit chain.


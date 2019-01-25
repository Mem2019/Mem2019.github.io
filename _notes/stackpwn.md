# stack pwn

`call arch_prctl(0x1003, $rsp - 0x8)` show segement register base address

`ret to syscall`, using the technique of partial rewrite, need to control eax and relevent argument

`SROP`, use `SigreturnFrame` in pwntools

`pwntools cyclinc` to locate data flow

`fs` of thread is in stack, which can be controlled

## format string

```assembly
; printf(buf, 0, 0x11111, 0x22222, 0x33333);
   0x400579 <main+19>    mov    r8d, 0x33333
   0x40057f <main+25>    mov    ecx, 0x22222
   0x400584 <main+30>    mov    edx, 0x11111
   0x400589 <main+35>    mov    esi, 0
   0x40058e <main+40>    mov    edi, buf <0x601040>
   0x400593 <main+45>    mov    eax, 0
   0x400598 <main+50>    call   printf

; printf(buf, 0.0, 0x11111, 0x22222, 0x33333);
   0x400579 <main+19>    mov    ecx, 0x33333
   0x40057e <main+24>    mov    edx, 0x22222
   0x400583 <main+29>    mov    esi, 0x11111
   0x400588 <main+34>    pxor   xmm0, xmm0
   0x40058c <main+38>    mov    edi, buf <0x601040>
   0x400591 <main+43>    mov    eax, 1
   0x400596 <main+48>    call   printf
```

when `eax=0`, xmm should not be used, if used using `%a`, it is dirty data, which is leak

maybe this eax tells printf if the value of `xmm` can be changed, 1 means cannot change since it's argument, and 0 means can be changed to improve efficiency since it should not be used for argument passing

`xmm0-xmm7` for floating point number argument, other floats are on stack
# stack pwn

`call arch_prctl(0x1003, $rsp - 0x8)` show segement register base address

`ret to syscall`, using the technique of partial rewrite, need to control eax and relevent argument

`SROP`, use `SigreturnFrame` in pwntools

`pwntools cyclinc` to locate data flow

`fs` of thread is in stack, which can be controlled
//`mona`

`msvcrtxx.dll` like `libc` in linux

`ntdll.dll` like `ld` in linux

register being cleared in SEH handler

`free with corrupted heap -> SEH handler`

## gadget for SEH when bypass GS

second argument usually points to buffer that can be controlled

```assembly
;1
pop xxx
pop xxx
pop esp
;....
ret

;2
mov eax,[ebp/esp + xxx]
call [eax+xxx]

;3
add esp,xxx
ret

;4
pop xx
pop xx
ret ; no DEP required, XP
```

## SEH bypass anti-virus

```assembly
mov dword ptr fs:[0],entry_point
xor eax,eax
mov [eax],0
```

## windows open shell

`system("cmd.exe")`

`WinExec("cmd.exe", SW_SHOW(5))`

`nc -e stack.exe -p 1234`

## x64dbg plugins

`detect it easy`

`checksec`

# protection

## LFH

randomized allocation of small chunks

## randomize allocation offset

## encoded heap header



## thicall stack migration

`mov esp,ecx; ret`

### problem

`WinExec/system -> malloc -> overlap with stack!`

1. `VirtualProtect/mprotect -> jmp heap`
2. `PEB has heap && dlls` `GetProcessHeap -> PEB->heap`, rewrite it to change the heap
3. `mov [eax],ebx; ret`, write a ROP in `.data`, then migrate the stack there

## SEH protection

### SEHOP

last one must be default handler in ntdll

last 6 bits of default handler is random, padding with nop

### SafeSEH

SEH handler must be recorded in a data structure in `.rodata` in the module

## CFG

`call xxx` must call to a valid function start address

`ntdll!NtContinue`, set registers according to saved registers in context, which can bypass CFG, similar to SROP

## 镜像劫持
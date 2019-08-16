---
layout: post
title:  "AFL Reading Notes 1: Instrumentation, Initialization and Fork Server"
date:   2019-08-09 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Recently I am investigating AFL Fuzzer, and this is some of my notes about its source code. In this article I will discuss how AFL compiler instruments the target binary to be fuzzed and how some initialization of fuzzer is done. I will also discuss fork server, which enable AFL to not call `execve` each time the target program is run.

Disclaimer: since this is just my reading notes and my capability is limited, it is possible for the contents to be inaccurate or even wrong, and I will be glad if you can point out any mistake here.

## 0x01 Instrumentation

In AFL, instrumentation is done in compilation time. The instrumentation is done at assembly level: in other word, after C/C++ source code is compiled into assembly text, the instrumentation is done and a instrumented assembly text is generated, which is then used to generate the binary file.

For the instrumentation, I will only focus on *how instrumentation is done* instead of *how instrumentation is implemented*. The latter one might involve some assembly text processing, for example, which we might not be interested in as a person who only wants to learn some fuzzing techniques. 

The main instrumentation logic is done in `afl-as.c`, and the codes to be instrumented, which is written in assembly, is in `afl-as.h` as string format.

### Instrumented Code

The instrumented code is written in ATT assembly, but such assembly format is uncomfortable to read, so I will use `afl-gcc` to compile a binary and put it into IDA to read the instrumented code, with reference to the comments written in `afl-as.h`.

AFL instruments a piece of code on each basic block, shown below.

```assembly
lea     rsp, [rsp-98h] ; allocate some stack space
mov     qword ptr [rsp+98h+input+0F80h], rdx
mov     qword ptr [rsp+98h+input+0F88h], rcx
mov     qword ptr [rsp+98h+input+0F90h], rax ; save registers
mov     rcx, 0FC50h ; rcx is the block identifier, generated randomly
call    __afl_maybe_log
mov     rax, qword ptr [rsp+98h+input+0F90h]
mov     rcx, qword ptr [rsp+98h+input+0F88h]
mov     rdx, qword ptr [rsp+98h+input+0F80h]
lea     rsp, [rsp+98h] ; recover stack and variables
```

Function `__afl_maybe_log`:

```assembly
__afl_maybe_log:
lahf
seto    al ; store some flags into ax
mov     rdx, cs:__afl_area_ptr ; NULL for the first time
test    rdx, rdx
jz      short __afl_setup ; this will jump for the first time
```

`__afl_setup` is used to initialize shared memory pointer and start fork server, which will be detailed later.

```assembly
__afl_setup:
cmp     cs:__afl_setup_failure, 0
jnz     short __afl_return
; do not retry setup if we had previous failures
lea     rdx, __afl_global_area_ptr
mov     rdx, [rdx]
test    rdx, rdx
jz      short __afl_setup_first
; use the global pointer if it is not NULL
mov     cs:__afl_area_ptr, rdx
jmp     short __afl_store

__afl_setup_first:
lea     rsp, [rsp-160h]
mov     [rsp+160h+var_160], rax
mov     [rsp+160h+var_158], rcx
mov     [rsp+160h+var_150], rdi
mov     [rsp+160h+var_140], rsi
mov     [rsp+160h+var_138], r8
mov     [rsp+160h+var_130], r9
mov     [rsp+160h+var_128], r10
mov     [rsp+160h+var_120], r11
movq    [rsp+160h+var_100], xmm0
movq    [rsp+160h+var_F0], xmm1
movq    [rsp+160h+var_E0], xmm2
movq    [rsp+160h+var_D0], xmm3
movq    [rsp+160h+var_C0], xmm4
movq    [rsp+160h+var_B0], xmm5
movq    [rsp+160h+var_A0], xmm6
movq    [rsp+160h+var_90], xmm7
movq    [rsp+160h+var_80], xmm8
movq    [rsp+160h+var_70], xmm9
movq    [rsp+160h+var_60], xmm10
movq    [rsp+160h+var_50], xmm11
movq    [rsp+160h+var_40], xmm12
movq    [rsp+160h+var_30], xmm13
movq    [rsp+160h+var_20], xmm14
movq    [rsp+160h+var_10], xmm15
; save registers into stack
push    r12
mov     r12, rsp
; save rsp
sub     rsp, 10h
and     rsp, 0FFFFFFFFFFFFFFF0h
; align rsp

lea     rdi, _AFL_SHM_ENV ; "__AFL_SHM_ID"
call    _getenv
test    rax, rax
; get shared memory id from environment var
jz      __afl_setup_abort
mov     rdi, rax        ; nptr
call    _atoi
xor     rdx, rdx        ; shmflg
xor     rsi, rsi        ; shmaddr
mov     rdi, rax        ; shmid
call    _shmat
; map shared memory into virtual space

cmp     rax, 0FFFFFFFFFFFFFFFFh
jz      __afl_setup_abort
mov     rdx, rax
mov     cs:__afl_area_ptr, rax
lea     rdx, __afl_global_area_ptr
mov     [rdx], rax
mov     rdx, rax
; save shared memory virtual address
```

At this point the shared memory pointer initialization is done, after then is the [fork server](http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html). In simple words, fork server works by stopping at the beginning of the main function, and fork a child process if a new instance is needed for fuzzing. This technique significantly reduces the performance bottleneck exerted by `execve` call.

```assembly
__afl_forkserver:
push    rdx
push    rdx
mov     rdx, 4          ; n
lea     rsi, __afl_temp ; buf
mov     rdi, 199        ; fd used to communicate with afl-fuzz, covered later
call    _write
; tell afl-fuzz that fork server is ready
; there is a corresponding `read` in afl-fuzz, covered later
; the specific byte contents does not matter
cmp     rax, 4
jnz     __afl_fork_resume
```

Then a loop is entered.

```assembly
__afl_fork_wait_loop:   ; nbytes
mov     rdx, 4
lea     rsi, __afl_temp ; buf
mov     rdi, 198        ; status
call    _read
; wait for afl-fuzzer to start a new fuzzing process
; specific byte contents does not matter either
cmp     rax, 4
jnz     __afl_die

call    _fork ; fork a child process for fuzzing
cmp     rax, 0
jl      __afl_die
jz      short __afl_fork_resume
```

The child process will simply record the path coverage information into shared memory and return from this function.

```assembly
__afl_fork_resume:      ; fd
mov     rdi, 198
call    _close
mov     rdi, 199       ; fd
call    _close
; close the fd
pop     rdx
pop     rdx
mov     rsp, r12
pop     r12
mov     rax, [rsp+160h+var_160]
mov     rcx, [rsp+160h+var_158]
mov     rdi, [rsp+160h+var_150]
mov     rsi, [rsp+160h+var_140]
mov     r8, [rsp+160h+var_138]
mov     r9, [rsp+160h+var_130]
mov     r10, [rsp+160h+var_128]
mov     r11, [rsp+160h+var_120]
movq    xmm0, [rsp+160h+var_100]
movq    xmm1, [rsp+160h+var_F0]
movq    xmm2, [rsp+160h+var_E0]
movq    xmm3, [rsp+160h+var_D0]
movq    xmm4, [rsp+160h+var_C0]
movq    xmm5, [rsp+160h+var_B0]
movq    xmm6, [rsp+160h+var_A0]
movq    xmm7, [rsp+160h+var_90]
movq    xmm8, [rsp+160h+var_80]
movq    xmm9, [rsp+160h+var_70]
movq    xmm10, [rsp+160h+var_60]
movq    xmm11, [rsp+160h+var_50]
movq    xmm12, [rsp+160h+var_40]
movq    xmm13, [rsp+160h+var_30]
movq    xmm14, [rsp+160h+var_20]
movq    xmm15, [rsp+160h+var_10]
lea     rsp, [rsp+160h]
; resume stack and registers
jmp     __afl_store

__afl_store:
; rcx is this_loc
xor     rcx, cs:__afl_prev_loc
xor     cs:__afl_prev_loc, rcx
; prev_loc == prev_loc ^ this_loc ^ prev_loc == this_loc
shr     cs:__afl_prev_loc, 1
; prev_loc = this_loc >> 1
inc     byte ptr [rdx+rcx]
; rcx is ((last_this_loc >> 1) ^ this_loc)
; increment corresponding bytes in shared memory
; which can record information about path cov
; "path A followed by path B is executed"
; although with possible collision

__afl_return:
add     al, 7Fh ; a hacky way to resume O flag :)
sahf
; resume flags
retn
```

The parent process send `pid` of child process to `afl-fuzz`, wait child process to finish, and send return status of the child process to `afl-fuzz`.

```assembly
mov     cs:__afl_fork_pid, eax
mov     rdx, 4          ; n
lea     rsi, __afl_fork_pid ; buf
mov     rdi, 199        ; fd
call    _write
; write child pid to fd 199
mov     rdx, 0          ; options
lea     rsi, __afl_temp ; stat_loc
mov     rdi, qword ptr cs:__afl_fork_pid ; pid
call    _waitpid
; wait child process
cmp     rax, 0
jle     __afl_die

mov     rdx, 4          ; n
lea     rsi, __afl_temp ; buf
mov     rdi, 199        ; fd
call    _write
; write return status of child process to fd 199
jmp     __afl_fork_wait_loop
; jump back to the start of loop
```

When this function is executed for the second time, `__afl_area_ptr` or `__afl_global_area_ptr` is not `NULL`, so it will jump to `__afl_store` directly in order to record path coverage information for this particular control block.

## 0x02 Fork Server Initialization

The fork server initialization is done in `init_forkserver`, which is called in the first time the target is run.

```c
EXP_ST void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");
  // initilize the pipe
  forksrv_pid = fork();
  // fork a process as fork server
  if (forksrv_pid < 0) PFATAL("fork() failed");
  /* ...to be covered later... */
}
```

In the child process:

```c
if (!forksrv_pid) {

  /* ...some settings, which is not very intersting...*/

  dup2(dev_null_fd, 1);
  dup2(dev_null_fd, 2);
  // set stdout and stderr to /dev/null
  if (out_file) {

    dup2(dev_null_fd, 0);
    // if input is given by file (e.i. @@ in arguments)
    // stdin is also set to /dev/null
  } else {

    dup2(out_fd, 0);
    close(out_fd);
    // if input is given by stdin
    // stdin is set to out_fd, 
    // which is used to transmit testcase input data
  }

  /* Set up control and status pipes, close the unneeded original fds. */

  if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
  if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");
  // #define FORKSRV_FD 198
  // remember fd 198 and 199 that appears in instrumented code

  close(ctl_pipe[0]);
  close(ctl_pipe[1]);
  close(st_pipe[0]);
  close(st_pipe[1]);

  close(out_dir_fd);
  close(dev_null_fd);
  close(dev_urandom_fd);
  close(fileno(plot_file));
  // close fds
  /* This should improve performance a bit, since it stops the linker from
     doing extra work post-fork(). */

  if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

  /* Set sane defaults for ASAN if nothing else specified. */

  setenv("ASAN_OPTIONS", "abort_on_error=1:"
                         "detect_leaks=0:"
                         "symbolize=0:"
                         "allocator_may_return_null=1", 0);

  /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
     point. So, we do this in a very hacky way. */

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "symbolize=0:"
                         "abort_on_error=1:"
                         "allocator_may_return_null=1:"
                         "msan_track_origins=0", 0);
  // set some environment variables
  execv(target_path, argv);
  // start the target binary, which will stop at fork server
  /* Use a distinctive bitmap signature to tell the parent about execv()
     falling through. */

  *(u32*)trace_bits = EXEC_FAIL_SIG;
  exit(0);

}
```

In parent process:

```c
/* Close the unneeded endpoints. */

close(ctl_pipe[0]);
close(st_pipe[1]);

fsrv_ctl_fd = ctl_pipe[1];
fsrv_st_fd  = st_pipe[0]; //store pipe fd to globals

/* Wait for the fork server to come up, but don't wait too long. */

it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

setitimer(ITIMER_REAL, &it, NULL);

rlen = read(fsrv_st_fd, &status, 4);
// this corresponds to the first write before fork server loop
it.it_value.tv_sec = 0;
it.it_value.tv_usec = 0;

setitimer(ITIMER_REAL, &it, NULL);

/* If we have a four-byte "hello" message from the server, we're all set.
   Otherwise, try to figure out what went wrong. */

if (rlen == 4) {
  OKF("All right - fork server is up.");
  return; // if no error occurs, this function will return
}

/* ...error handlings, not interesting...*/
```

## 0x03 Instance Running

Before running an instance for fuzzing, `afl-fuzz` firstly write testcase input data into `out_fd` by function `write_to_testcase` and `write_with_gap`.

```c
/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file); // write data into fd

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (skip_at) ck_write(fd, mem, skip_at, out_file);
  if (tail_len) ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);
  // write 2 chunks of data into fd

  if (!out_file) {

    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}
```

Then, a function `run_target` is called to run the instance.

```c
/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv, u32 timeout) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver) {

  /* ...when there is no fork server, not interesting... */

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    } // write 4 bytes, corresponds to `read`
      // at the start of fork server loop
      // so that fork server will start to execut
      // and fork a new instance 

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    } // get the pid of new forked instance

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) { // not important

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) { // get return status

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

    }

  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;
  // process the return status, todo: investigate in detail
}
```


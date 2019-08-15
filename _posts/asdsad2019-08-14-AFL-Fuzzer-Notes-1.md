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

AFL instruments a piece of code on each basic block, shown below.

```assembly

```


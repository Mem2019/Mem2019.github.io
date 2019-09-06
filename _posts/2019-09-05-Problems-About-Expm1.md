---
layout: post
title:  "Problems about Math.Expm1 Bug in V8"
date:   2019-09-05 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

This is some of my notes about `krautflare` challenge in 35C3 CTF, and is not a complete write-up for this challenge. For a complete write-up, please read [this](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/) and [this](https://www.jaybosamiya.com/blog/2019/01/02/krautflare/). [This](https://github.com/vngkv123/aSiagaming/blob/master/Chrome-v8-Math.expm1/exploit.js) is also a complete exploit. I will discuss some of problems I encountered and how I solved them when I was working on this challenge.

### PoC

Here is the working PoC that can triggers OOB read.

```javascript
function f(v)
{
	const arr = [1.1, 2.2, 3.3];
	const o = {z1: -0}
	let res = Object.is(Math.expm1(v), o.z1);
	return arr[res * 1337];
}
f("a");
%OptimizeFunctionOnNextCall(f);
f("a");
%OptimizeFunctionOnNextCall(f);
/* or
for (var i = 0; i < 0x4000; i++)
	f("a");
*/
print(f(-0));
```

### Graph

Here are graphs before and after `SimplifiedLowring` phase, the critical phase that triggers OOB access.

![](/images/expm1-EA.png)

![](/images/expm1-SL.png)


## 0x01 Array Length Matters

In PoC, the array length is 3, but if we reduce it to 2 or 1, OOB cannot be triggered.

### Length 2 Case

When `arr = [1.1, 2.2]`, the result is `2.2`, which is non-sense at first glance, because we are multiplying a `boolean` value with `1337`, which can never be `1`!

But it is clear if we look at turbolizer. This is the graph just after `EscapeAnalysis`, so the critical phase `SimplifiedLowering` that removes bound checking has not been reached yet.

![](/images/expm1-arrlen2.png)

As we can see, instead of accessing array as the result, the code is optimized to a `if-else` statement. In other word, it is optimized to pseudo-code like this: 

```javascript
tmp = res * 1337;
CheckBounds(tmp, 2); 
// will be eliminated later in SimplifiedLowering
return tmp == 0 ? 1.1 : 2.2;
```

Therefore, after `CheckBounds` node is eliminated, and when `tmp==1337`, the result will be `2`. However, if array length is larger than 2, such optimization cannot be done, therefore the array access will still present so that we can trigger the OOB read.

### Length 1 Case

When `arr = [1.1, 2.2]`, the result is `1.1`. We look at graph just after `EscapeAnalysis` again.

![](/images/expm1-arrlen1.png)

The pseudo-code now becomes this.

```javascript
tmp = res * 1337;
CheckBounds(tmp, 1); 
// will be eliminated later in SimplifiedLowering
return 1.1;
```

The basic logic is, the result should always be `1.1`. If `tmp` is larger than 1, it should be bailed out in `CheckBounds` operation, which will be eliminated later in `SimplifiedLowering`. The idea of such optimization is, if we know `tmp` is within the bound, it must be `0`, so `arr[tmp]` is unnecessary as it is always `1.1`.

## 0x02 Bound Check Elimination

For the working PoC that can cause OOB read, the graph is a bit weird: type for `SameValue` node is `Boolean`, even if from input nodes type `false` can already be inferred. Such type propagates and causes `Range(0, 1337)` to appear at `NumberMultiply` node, which does not seem to give information that can eliminates the `CheckBounds` node, since the array length is `3`. Nonetheless, the `CheckBounds` node is still eliminated after `SimplifiedLowering`, and type for `Int32Mul` is still `Range(0,1337)`. How can `CheckBounds` node be eliminated given that index is typed with `Range(0,1337)`?

The code corresponds to bound checking elimination is at `simplified-lowering.cc:1559`.

```c++
if (lowering->poisoning_level_ ==
        PoisoningMitigationLevel::kDontPoison &&
    (index_type.IsNone() || length_type.IsNone() ||
     (index_type.Min() >= 0.0 &&
      index_type.Max() < length_type.Min()))) {
  // The bounds check is redundant if we already know that
  // the index is within the bounds of [0.0, length[.
  DeferReplacement(node, node->InputAt(0));
} else {
  NodeProperties::ChangeOp(
      node, simplified()->CheckedUint32Bounds(p.feedback()));
}
```

If I set a breakpoint here, it stops 2 times. For the first time, `index_type` is indeed `Range(0,1337)`, and the elimination is not done. However, for the second time, `index_type` becomes `Range(0,0)`, and at this point the `CheckBounds` node is eliminated.

_In my opinion_, after first time the breakpoint stops, the type information of `SameValue` node will be retyped to `false` during `SimplifiedLowering` phase. Such retyped type information will be used for bound checking elimination again, and this is where second time the breakpoint stops. Then `SameValue` node is typed back to `Boolean` again, which explains `Range(0,1337)` of `Int32Mul` after `SimplifiedLowering` phase. This does NOT have to be correct, and is just my guess, since the code is too long and I cannot find related code about this.

## 0x03 JIT

### Twice Compilation

In PoC, `OptimizeFunctionOnNextCall` is used twice. For the first time `NumberExpm1` node is generated for `Math.expm1`, and in the next call, since `"a"` is not a number, the function will be optimized. For the second time, a `Call` node will be generated. For the loop case, optimization also occurs twice, and de-optimization occurs just after the first optimization.

I am not sure why turbofan does not generate a `Call` node in the first time, given the previous argument is always a string instead of a number, since obviously it is very likely for this optimization to bail out in the next call, making such optimization useless. Turbofan should optimize the function in favor of information about arguments gathered in previous calls, so I am not sure what happened here. Maybe I was wrong at some point?

### Effect of Early `f(-0)` Call

Another point to note is that we cannot put `f(-0)` before function is compiled, otherwise the result will be `undefined`.

For example,

```javascript
f(-0);
f("a");
%OptimizeFunctionOnNextCall(f);
f("a");
%OptimizeFunctionOnNextCall(f);
print(f(-0));
```

Let's see what happened.

![](/images/expm1-fm1-EA.png)

![](/images/expm1-fm1-SL.png)

Before `SimplifiedLowering`, bound value that `CheckBounds` node is using is`0x7fffffff`, which is`INT_MAX`. Certainly it has no effect and will be eliminated soon in `SimplifiedLowering`. The actual bound checking work is done by `NumberLessThan`, and if this gives `false`, `undefined` will be returned. In `SimplifiedLowering`, such `NumberLessThan` will not be eliminated but will be lowered to `Uint32LessThan`, unlike `CheckBounds` node in the working PoC. In other word, the bound guard will not be eliminated by `SimplifiedLowering` in this case, but just exist in another form.

I _think_ the reason for this is that `f(-1)` causes out-of-bound, so turbofan can learn from such call and produce graph that handle the out-of-bound case, instead of just bailing out when OOB occurs, which is the case when `f(-1)` is not called.

### `f(0)` Call

In one of the previous articles, a piece of code that triggers the bug is provided.

```javascript
function foo(x) {
    return Object.is(Math.expm1(x), -0);
}
foo(0);
for(let i = 0; i < 100000; i++)
    foo("0");
console.log(foo(-0)); //false
```

The author is not sure why `f(0)` is required, since things do not work if we delete this. If we look at the JIT, you will find the second compilation, which is used to produce `Call` node, is not done. Only the first compilation that generates `NumberExpm1` is done, which is de-optimized in the next call. If we look at files that `--trace-turbo` generated, file `turbo-foo-1.json` does not present. 

If we force the second optimization, bug can be triggered.

```javascript
for(let i = 0; i < 100000; i++)
    foo("0");
%OptimizeFunctionOnNextCall(foo);
console.log(foo(-0)); //false
```

In addition, if we separate the loop, the bug can also be triggered.

```javascript
for(let i = 0; i < 50000; i++)
    foo("0");
for(let i = 0; i < 50000; i++)
    foo("0");
console.log(foo(-0)); //false
```

My _guess_ is, as the loop goes, V8 finds that `foo` have no side-effect, so it will not execute `foo` function anymore, otherwise there is no reason for the second optimization to not occur after de-optimization. Indeed, if we add some side-effect to `foo`, the bug can be triggered again.

```javascript
var g = 0;
function foo(x) {
    g++;
    return Object.is(Math.expm1(x), -0);
}
for(let i = 0; i < 100000; i++)
    foo("0");
console.log(foo(-0)); //false
```

Again, this is just my guess and does not have to be correct. I will be glad if anyone can point out my mistake.


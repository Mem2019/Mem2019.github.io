---
layout: post
title:  "Reflection about Taint Analysis"
date:   2019-01-26 01:01:05 +0000
categories: jekyll update
---

## 0x01 Introduction

In this [paper](https://users.ece.cmu.edu/~aavgerin/papers/Oakland10.pdf), a formal algorithm for taint analysis is defined by Operational Semantics of SIMPIL language, which can be transformed to from languages like C. However, it is possible that some of the rules may create incorrect result.

## 0x02 T\-LOAD

![1548465137086](/images/1548465137086.png)

As shown, whether the evaluation result is tainted depends on the return value of `Pmem`, which is typically defined as `Pmem(ta, tv) = tv` according to the `Table 3` in the paper. That is saying we only consider whether the source memory at the given address is tainted, ignoring the taint state of address value. However, this cause problem when we use a "map table" to convert the form of data. For example, in `base64` encode, we may need a utility like this

```c
char map_to_base64_char(uint8_t val)
{//pre:0<=val<64
    char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return tab[val];
}
```

Since the a constant string is assigned to `tab`, the contents in tab must be untainted. According to `Pmem(ta, tv) = tv`, the `tab[val]` is also untainted, which is clearly not the case: `tab[val]` is `base64` form for `val`, so if `val` is tainted, `tab[val]` should also be tainted!

Then, what if we change the definition to `Pmem(ta, tv) = ta ∨ tv`? However, we can still let it produce wrong result. Consider this code

```c
char return_A(size_t some_tainted_data)
{
    char a[0x100];
    size_t still_tainted = some_tainted_data % 0x100;
    memset(a, 'A', 0x100);
    return a[still_tainted];
}
```

For this function, whatever the `some_tainted_data` is, the function always returns a constant `'A'`. However, the rule `Pmem(ta, tv) = ta ∨ tv` will say that `a[still_tainted]` is tainted, which is not what we want. Fortunately this kind of codes rarely occurs unless the developer has intentionally added some anti reverse engineering obfuscation codes.


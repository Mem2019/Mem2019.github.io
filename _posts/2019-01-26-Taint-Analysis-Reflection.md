---
layout: post
title:  "Reflection about Taint Analysis"
date:   2019-01-26 01:01:05 +0000
categories: jekyll update
---

## 0x01 Introduction

In this [paper](https://users.ece.cmu.edu/~aavgerin/papers/Oakland10.pdf), a formal algorithm for taint analysis is defined by Operational Semantics of `SIMPIL` language, which can be transformed to from languages like C. However, it is possible that some of the rules may create incorrect result.

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

Another way to fix this issue is to record the address or contents of a specific mapping table, and denote it as a function. Only if the address or content matches the table we have recorded do we consider `ta` as a `taint contributor`. However, this requires information about both `table start` and `index`, which cannot be represented by semantics of `SIMPIL`. But in other kinds of instruction set such as `x86`, the compiler will generate the code like this when we use mapping table: `mov dst_reg, [mapping_tab + index * size_of_element]`, where `mapping_tab` can be both immediate number of register, `index` is usually a register, and `size_of_element` is a constant that can be power of 2. Using this feature, we may redefine it as `Pmem(tat, tai, tv) = if_mapping_table(tat) ? tai : tv`, where `tat` stands for address of mapping table and `tai` stands for the index.

And how do we define `if_mapping_table`? As I said, we can define it using `address itself` or `content within address`, or both. We may just use the value of address, since usually the mapping table is in global variable. But what if not? Like the case of `map_to_base64_char` above. From my perspective, using content must be an effective way but it is slow, so we can check the address first, then secondly check content if address does not match to know addresses.

## 0x03 T\-BINOP

![1548620761843](D:\1projects\github\Mem2019.github.io\images\1548620761843.png)

`Pbinop(t1, t2) = t1 ∨ t2`, and `Pbincheck` always returns `true` according to his definition.

This is saying, the taint state of the return value of binary operator is an `or` operation of taint states of 2 input values. This will be problematic in some cases.

```c
int tainted1， tainted2;
//...
int tainted_wrong1 = tainted1 - tainted1;
int tainted_wrong2 = tainted1 ^ tainted1;
```

As shown above, it is obvious that 2 `tainted_wrong` variables are `0` always, but the semantics above will identify them as tainted. This can be resolved by doing some simple check against the operator and value, but what about this case?

```c
size_t tainted;
//...
size_t still_tainted = tainted + 0xdeadbeef;
size_t tainted_wrong = still_tainted - tainted;
```

This should return `0xdeadbeef` including the case where the overflow occurs. And there is also cases where the 2 input values are not necessarily always identical but we have them equal accidentally in some cases when this binary operation is executed. In this case we should not have simply classified it as untainted but the algorithm will. For example
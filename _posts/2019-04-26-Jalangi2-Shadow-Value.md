---
layout: post
title:  "Jalangi2 Shadow Value"
date:   2019-04-26 01:01:05 +0000
categories: jekyll update
---

Recently I am working on JavaScript Taint Analysis by using Jalangi2. However, I found that mechanism of shadow value of Jalangi2, which is used to store taint state here, works differently from the one mentioned in this [paper](https://people.eecs.berkeley.edu/~ksen/papers/jalangi.pdf). The reason might be that the version is different: the paper covers Jalangi1 while I am using Jalangi2.

In the paper, it is suggested to use a `AnnotatedValue` to replace some variables, and as long as the variable is used for some operation, `actual(value)` is used to convert it to actual value for operation. Then when our analysis callback function `analysis.binary` is called, `value` is passed as the arguments instead of `actual(value)`, shown as below, according to the seudo-codes in the paper.

```javascript
//definition of AnotatedValue
function AnotatedValue(val, shadow)
{
	this.val = val;
	this.shadow = shadow;
}
function actual(val)
{
	return val instanceof AnotatedValue ? val.val : val;
}
//when executing instrumented code of binary operator
var result = actual(left) op actual(right) //call `actual` to operands 
if (analysis && analysis.binary)
    analysis.binary(op, left, right, result)
```

However, in Jalangi2, things works differently, here is the part of the source code of Jalangi2.

```javascript

	function B(iid, op, left, right, flags) {
	var bFlags = decodeBitPattern(flags, 3); // [isComputed, isOpAssign, isSwitchCaseComparison]
	var result, aret, skip = false;

	if (sandbox.analysis && sandbox.analysis.binaryPre) {
		aret = sandbox.analysis.binaryPre(iid, op, left, right, bFlags[1], bFlags[2], bFlags[0]);
		if (aret) {
			op = aret.op;
			left = aret.left;
			right = aret.right;
			skip = aret.skip;
		}//a `binaryPre` is added
	}
	if (!skip) {
		switch (op) {
			case "+": // not actual(left) + actual(right)
				result = left + right;
				break;
			//... other operators
			default:
				throw new Error(op + " at " + iid + " not found");
				break;
		}
	}

	if (sandbox.analysis && sandbox.analysis.binary) {
        //left and right being passed to `analysis.binary` 
        //are same as ones used as operands
        //which is different from the approach mentioned in paper
		aret = sandbox.analysis.binary(iid, op, left, right, result, bFlags[1], bFlags[2], bFlags[0]);
		if (aret) {
			result = aret.result;
		}
	}
	return (lastComputedValue = result);
}
```

Therefore, it seems that `AnnotatedValue` class is not supported in Jalangi2, but instead, shadow value is associated with a object reference. `SMemory` is a mechanism that support shadow value feature in Jalangi2. However, the drawback of this approach is that we cannot have a shadow value assoicated with primitive value, including `string`. Therefore, since the approach of Jalangi1 mentioned in the paper is better for me to use, I will define `AnotatedValue` by myself, and then define `analysis.binaryPre` to let `skip === true`, and perform calculation inside `analysis.binary` instead. Also, I will do this for all operations, not only binary operator.

Here is the codes that describe what I am thinking about.

```javascript
this.binaryPre = function(iid, op, left, right)
{
	return {op:op,left:left,right:right,skip:true}//skip
}
this.binary = function(iid, op, left, right, result)
{
	var result;
	var aleft = actual(left);
	var aright = actual(right);
	switch (op)
	{//switch copied from source code of Jalangi2 
	case "+":
		result = aleft + aright;
		break;
	//... many other operands
	default:
		throw new Error(op + " at " + iid + " not found");
		break;
	}

	//use left and right to perform analysis

	return {result : result} 
	//eval("left"+op+"right")} eval might be insecure
}
```

In this way we can use the shadow value in the same way as Jalangi1.
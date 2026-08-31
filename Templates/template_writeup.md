# [Category] Challenge Name

- **Event / Platform:** CTF Name / Platform (e.g., Dreamhack, PicoCTF)
- **Date:** YYYY-MM-DD
- **Difficulty:** Easy / Medium / Hard
- **Tags:** #pwn #shellcode #restricted-bytes #troubleshooting

---

## 1. Challenge Overview (문제 개요)

> [!info] **문제 요약**
> - **목표:** Flag 획득 (`/flag` 읽기 또는 `execve` 쉘 획득)
> - **제약 조건:** 특정 명령어 금지 (`mov` 불가), 널 바이트 (`\x00`) 미허용 등

- **제공 파일:** `chall`, `chall.c`, `Dockerfile`
- **보호 기법 (Checksec):**
	- RelRO / Canary / NX / PIE 설정 여부 요약

---

## 2. Vulnerability Analysis (취약점 분석)

### 소스 코드 / 디컴파일 분석
```c
// 핵심이 되는 소스 코드 및 취약점 지점
int main() {
	char buf[0x20];
	read(0, buf, 0x100); // Buffer Overflow 발생 지점
	return 0;
}
```

### 취약점 원인 (Root Cause)
- **발생 원인:** 입력값 경계 검사 미흡으로 인한 오버플로우 / 로직 오류
- **파급 효과:** RET 덮어쓰기 가능, 제어 흐름 탈취 등

---

## 3. Trial & Error (삽질 및 실패 기록)

> [!failure]- Attempt 1: [첫 번째 가설/시도 제목] (클릭하여 펼치기)
> - **가설:** A 기법을 사용해서 X 제약 조건을 우회할 수 있을 것이다.
> - **시도 내용:**
> 	- `push` 명령어를 사용해 문자열을 스택에 직접 대입
> - **결과 및 에러:** `Segmentation Fault` 발생
> - **원인 분석:**
> 	- 64비트 모드에서 `push`는 스택을 8바이트 단위로 옮기기 때문에 남은 공간에 `\x00`이 채워져 문자열이 끊김
> - **에러 로그 / 터미널 출력:**
> 	```text
> 	[GDB output or error trace text]
> 	```

> [!failure]- ❌ Attempt 2: [두 번째 가설/시도 제목] 
> - **가설:** `mov` 대신 `or` 연산만 사용해 64비트 문자열을 한 번에 입력한다.
> - **시도 내용:**
> 	- `or rax, 0x68732f2f6e69622f` 수행
> - **결과 및 원인:**
> 	- 어셈블리 에러 발생 (`imm32` 제한). x86-64 `or` 명령어는 64비트 즉시값을 직접 받지 못함을 뒤늦게 파악함.

---

## 4. Exploit Strategy (최종 해결 전략)

> [!success] **돌파구 (Breakthrough)**
> 레지스터가 `0`으로 초기화된 상태를 활용해 **32비트 단위 `or` 연산 + `shl`** 조합으로 `mov` 없이 64비트 문자열 완성.

1. `or eax, 0x68732f2f` 로 상위 32비트 대입 후 `shl rax, 32`로 밀어 올림
2. `or eax, 0x6e69622f` 로 하위 32비트 채움
3. `push 0x3b` / `pop rax` 로 `mov` 없이 `execve` 시스템콜 번호(59) 세팅
---

## 5. Exploit Code (최종 코드)

```python
#!/usr/bin/python3
from pwn import *
# 등등... 소스 코드
```

---

## 6. 배운 점 & 오답 노트

- **새로 알게 된 어셈블리/ISA 제약:**
	- x86-64에서 `or` 명령어는 64비트 즉시값(`imm64`)을 직접 인자로 받지 못한다 (32비트 단위로 쪼개야 함)
- **다음에 기억할 디버깅 키워드:**
	- `Null-Free` 쉘코드 작성 시 8바이트 문자열 처리 규칙 (`/bin//sh` 활용)
- **유용했던 GDB 명령어 / 팁:**
	- `x/10i $rip` 로 현재 주소 어셈블리 명령어 확인
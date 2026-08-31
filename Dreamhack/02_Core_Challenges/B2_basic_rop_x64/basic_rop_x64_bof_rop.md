# [Dreamhack.io] basic_rop_x64 Write-Up

* **Platform:** Dreamhack
* **Date:** 2026-08-29 (solved) / 2026-08-31 (written)
* **Difficulty:** Easy
---

## 1. Challenge Overview (문제 개요)

> [!TIP]
> 📖 **문제 요약**
> - **목표:** `/bin/sh\x00` 획득
> - **제공 파일:** `Dockerfile`, `basic_rop_x64`, `basic_rop_x64.c`, `flag`, `libc.so.6`
> - **보호 기법:**
> 	```text
> 	Arch: amd64-64-little
> 	RELRO: Partial RELRO
> 	Stack: No canary found
> 	NX: NX enabled
> 	PIE: No PIE (0x400000)
> 	Stripped: No
> 	```

---

## 2. Vulnerability Analysis (취약점 분석)

### 소스 코드 / 디컴파일 분석

```c
int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

* `read(0, buf, 0x400)`에서 스택 버퍼 오버플로우가 발생한다.

### 취약점 원인 (Root Cause)
* **발생 원인:** 변수보다 많이 입력받아 생기는 스택 버퍼 오버플로우
* **파급 효과:** `RET` 주소 변경 가능. `Partial RELRO` 이므로 `GOT Overwrite` 가능

---

## 3. Exploit Strategy (최종 해결 전략)

> [!TIP]
> ‼️ 페이로드 구성
> `main` 함수가 리턴될 시점에는 `read`와 `write` 함수의 `got` 테이블에는 해당 함수의 실제 링킹된 주소가 적혀있다. 가젯을 통해 `read` 함수의 `got` 테이블 값을 `system` 함수로 바꾸고, `system("/bin/sh\x00")`을 실행한다.


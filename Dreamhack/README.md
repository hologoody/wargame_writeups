# 🚀 Dreamhack Pwnable Archive

> 드림핵(Dreamhack) 시스템 해킹 문제 풀이 및 공부 기록 저장소입니다.
> 기초부터 심화 문제까지 단계별로 분류하여 기록하고 있습니다.

</br>

## 📊 아카이브 구조

| 분류  | 난이도 | 목적  | 아카이빙 방식 |
| :-- | :--- | :--- | :------- |
| **01_Fundamentals** | Beginner ~ Bronze 3 | 기본 개념 및 도구 익히기 | exploit 파일명 규칙화 & 내부 주석 요약 |
| **02_Core_Challenges** | Bronze 2 ~ Sliver 3 | 주요 공격 기법 자산화 | md 형식 라이트업 (exploit 방법 위주) |
| **03_Deep_Dive** | Sliver 2 ~ Gold+ | 고난도 문제 분석 및 디버깅 능력 증명 | 분석, 도전, 해결 과정을 담은 **상세 라이트업** |

</br>

## 🔍 문제 색인 (Ctrl + F 검색용)

### 📂 01. Fundamentals (Beginner ~ Bronze 3)
기초적인 BOF 및 환경 구축 단계입니다. 파일 이름을 `[문제명_취약점_공격방식]`으로 하여 직관성을 높였습니다.
* 🟢 [basic_exploitation_001_bof_ret2win.py](./01_Fundamentals/basic_exploitation_001_bof_ret2win.py) - `Stack BOF`, `ret2win`
* 🟢 [cat_jump_command_injection_ctypes.py](./01_Fundamentals/cat_jump_command_injection_ctypes.py) - `Command Injection`, `ctypes srand predict`
* 🟢 [cpp_string_mem_leak.py](./01_Fundamentals/cpp_string_mem_leak.py) - `Memory Leak`, `Null Byte Stripping`
* 🟢 [mmapped_bof_var_overwrite.py](./01_Fundamentals/mmapped_bof_var_overwrite.py) - `Stack BOF`, `Variable Overwrite`
* 🟢 [out_of_bound_oob.py](./01_Fundamentals/out_of_bound_oob.py) - `Out of Bound`, `Offset Calculation`
* 🟢 [return_to_shellcode_canary_leak_binsh_shellcode.py](./01_Fundamentals/return_to_shellcode_canary_leak_binsh_shellcode.py) - `Canary Leak`, `Shellcode`, `binsh shellcode`, `x86_64`
* 🟢 [shell_basic_orw_shellcode.py](./01_Fundamentals/shell_basic_orw_shellcode.py) - `Shellcode`, `ORW shellcode`, `x86_64`
* 🟢 [sint_integer_underflow_ret2win.py](./01_Fundamentals/sint_integer_underflow_ret2win.py) - `Interger Underflow`

### 📂 02. Core Challenges (Bronze 2 ~ Sliver 3)
* 🟡

### 📂 03. Deep Dive (Sliver 2 ~ Gold +) ⭐⭐
* 🔴
1. 0x3,00,00,00,00,00 위치에 0x298 바이트 (664 바이트) mmap
	* prot: 3 (PROT_READ | PROT_WRITE)
	* flags: 0x21 (MAP_SHARED | MAP_ANONYMOUS)
		* MAP_SHARED: 부모와 자식 프로세스 간에 메모리 공유
		* MAP_ANONYMOUS: 연결할 파일이 없는 순수 메모리를 할당 (fd: -1)
	* fd: -1 (MAP_ANONYMOUS 속성이 있으므로 파일 디스크럽터는 -1)
	* offset: 0 (연결할 파일이 없으니 상관 없음)
	* 오프셋 8 위치에 0x0a, 나머지는 0x00
2. heap 영역에 특정 위치 (하위 3바이트가 0xec0)에 어떤 정보가 있어.
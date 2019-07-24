#include <Windows.h>

int main() {
	asm(".byte 0xde,0xad,0xbe,0xef,0x00\n\t"
		"ret\n\t");

	return 0;
}
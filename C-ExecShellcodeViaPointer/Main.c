#include <windows.h>

main(int argc, char** argv)
{

	char buf[] = "\xcc\xcc\xcc\xcc";

	// ## one way to do it
	(*(int(*)()) buf)();
	// ## Another way
	//(*(void(*)()) buf)();
	// ## And another way
	//int (*func)();
	//func = (int (*)()) (void*)buf;
	//(int)(*func)();

	// sleep for a second
	Sleep(1000);
}

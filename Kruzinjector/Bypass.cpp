#include "Bypass.h"

bool BypassInject(HANDLE hProcess, const char* dllFile)
{
	LPVOID ntdll = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

	if (!ntdll) 
	{
		printf("[!] Failed to open bypass module. (0x%X)\n", GetLastError());
		return false;
	}

	char originalBytes[5];
	memcpy(originalBytes, ntdll, 5);
	if (!WriteProcessMemory(hProcess, ntdll, originalBytes, 5, NULL))
	{
		printf("[!] Failed to bypass VAC. (0x%X)\n", GetLastError());
		return false;
	}

	char CustomDLL[MAX_PATH];
	GetFullPathName(dllFile, MAX_PATH, CustomDLL, 0);

	LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(CustomDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!WriteProcessMemory(hProcess, allocatedMem, CustomDLL, sizeof(CustomDLL), NULL))
	{
		printf("[!] Failed to write process memory. (0x%X)\n", GetLastError());
		return false;
	}

	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);

	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	char Orig[5];
	memcpy(Orig, ntdll, 5);
	WriteProcessMemory(hProcess, ntdll, Orig, 0, 0);

	return true;
}
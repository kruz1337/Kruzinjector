#include "Standart.h"

bool LoadLibraryInject(HANDLE hProcess, const char* dllFile)
{
	DWORD exitCode;

	if (!GetExitCodeProcess(hProcess, &exitCode))
	{
		printf("[!] Process is not valid. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	void* mem = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mem)
	{
		printf("[!] Memory failed to allocate. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, mem, dllFile, strlen(dllFile) + 1, 0))
	{
		printf("[!] Failed to write process memory. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, mem, 0, 0);
	if (hThread)
	{
		CloseHandle(hThread);
	}

	return true;
}
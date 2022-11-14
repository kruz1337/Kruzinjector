#include "LoadLibrary.h"
#include "Execution.h"

bool ILoadLibrary(HANDLE hProcess, const char* dllFile, EXECUTION_METHOD execution)
{
	DWORD exitCode;
	if (!GetExitCodeProcess(hProcess, &exitCode))
	{
		printf("[-] Process is not valid. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	void* memory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!memory)
	{
		printf("[-] Memory failed to allocate. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, memory, dllFile, strlen(dllFile) + 1, 0))
	{
		printf("[-] Write process memory failed. (0x%X)\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	if (execution == M_NtCreateThreadEx)
	{
		CreateThreadEx(hProcess, LoadLibraryA, memory);
	}
	else if (execution == M_ThreadHijacking)
	{
		HijackThread(hProcess, LoadLibraryA, memory);
	}

	return true;
}
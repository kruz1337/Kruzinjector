#include "Execution.h"

bool CreateThreadEx(HANDLE hProcess, void* shellCode, void* targetBase)
{
	HANDLE thread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellCode), targetBase, 0, nullptr);
	if (!thread)
	{
		printf("[-] Remote thread creation failed. (0x%X)\n", GetLastError());
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(thread);
}

bool HijackThread(HANDLE hProcess, void* shellCode, void* targetBase)
{
	void* codeCave = VirtualAllocEx(hProcess, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!codeCave)
	{
		printf("[-] Failed to open code cave. (0x%X)\n", GetLastError());
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		return false;
	}

	DWORD processId = GetProcessId(hProcess);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	HANDLE hThread = NULL;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	Thread32First(hSnapshot, &te32);
	while (Thread32Next(hSnapshot, &te32))
	{
		if (te32.th32OwnerProcessID == processId)
		{
			hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
			if (!hThread)
			{
				printf("[-] Failed to open hijack thread. (0x%X)\n", GetLastError());
				VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
				VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
				return false;
			}
			break;
		}
	}
	CloseHandle(hSnapshot);

	if (SuspendThread(hThread) == (DWORD)-1) //https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
	{
		printf("[-] Suspend thread failed. (0x%X)\n", GetLastError());
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &ctx))
	{
		printf("[-] Retrieve thread context failed. (0x%X)\n", GetLastError());
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

#ifdef _WIN64
	BYTE code[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
		0x83, 0xEC, 0x08, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00,
		0x00, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
		0x41, 0x53, 0x9C, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x20,
		0xFF, 0xD0,	0x48, 0x83, 0xC4, 0x20, 0x48, 0x8D, 0x0D,
		0xB4, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x01, 0x9D, 0x41,
		0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,
		0x58, 0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00, 0xC3
	};

	DWORD funcOffset = 0x08;
	DWORD checkByteOffset = 0x03 + funcOffset;

	*reinterpret_cast<DWORD*>(code + 0x07 + funcOffset) = (DWORD)(ctx.Rip & 0xFFFFFFFF);
	*reinterpret_cast<DWORD*>(code + 0x0F + funcOffset) = (DWORD)((ctx.Rip >> 0x20) & 0xFFFFFFFF);
	*reinterpret_cast<void**>(code + 0x21 + funcOffset) = shellCode;
	*reinterpret_cast<void**>(code + 0x2B + funcOffset) = targetBase;

	ctx.Rip = reinterpret_cast<ULONG_PTR>(codeCave) + funcOffset;
#else
	BYTE code[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x04, 0xC7, 0x04,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x50, 0x51, 0x52, 0x9C,
		0xB9, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00,
		0x00, 0x51, 0xFF, 0xD0, 0xA3, 0x00, 0x00, 0x00, 0x00,
		0x9D, 0x5A, 0x59, 0x58, 0xC6, 0x05, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xC3
	};

	DWORD funcOffset = 0x04;
	DWORD checkByteOffset = 0x02 + funcOffset;

	*reinterpret_cast<DWORD*>(code + 0x06 + funcOffset) = ctx.Eip;
	*reinterpret_cast<void**>(code + 0x0F + funcOffset) = targetBase;
	*reinterpret_cast<void**>(code + 0x14 + funcOffset) = shellCode;
	*reinterpret_cast<void**>(code + 0x1C + funcOffset) = codeCave;
	*reinterpret_cast<BYTE**>(code + 0x26 + funcOffset) = reinterpret_cast<BYTE*>(codeCave) + checkByteOffset;

	ctx.Eip = reinterpret_cast<DWORD>(codeCave) + funcOffset;
#endif

	if (!WriteProcessMemory(hProcess, codeCave, code, sizeof(code), NULL))
	{
		printf("[-] Shellcode injection failed. (0x%X)\n", GetLastError());
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	if (!SetThreadContext(hThread, &ctx))
	{
		printf("[-] Hijacking failed. (0x%X)\n", GetLastError());
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		printf("[-] Resume thread failed. (0x%X)\n", GetLastError());
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);
}
#include "ManualMap.h"
#include "Execution.h"

bool IManualMap(HANDLE hProcess, BYTE* sourceData, SIZE_T dllSize, EXECUTION_METHOD execution)
{
	BYTE* targetBase = nullptr;
	IMAGE_NT_HEADERS* ntHeaders = nullptr;
	IMAGE_OPTIONAL_HEADER* optHeader = nullptr;
	IMAGE_FILE_HEADER* fileHeader = nullptr;

	ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(sourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_lfanew);
	optHeader = &ntHeaders->OptionalHeader;
	fileHeader = &ntHeaders->FileHeader;
	targetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, reinterpret_cast<void*>(optHeader->ImageBase), optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!targetBase)
	{
		targetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!targetBase)
		{
			printf("[-] Memory failed to AllocateEx. (0x%X)\n", GetLastError());
			return false;
		}
	}

	MANUAL_MAPPING_STRUCT data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<_GetProcAddress>(GetProcAddress);

	if (!WriteProcessMemory(hProcess, targetBase, sourceData, 0x1000, nullptr))
	{
		printf("[-] Can't write file header 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		return false;
	}

	auto* sectionheader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i != fileHeader->NumberOfSections; i++, sectionheader++)
	{
		if (sectionheader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, targetBase + sectionheader->VirtualAddress, sourceData + sectionheader->PointerToRawData, sectionheader->SizeOfRawData, nullptr))
			{
				printf("[-] Can't map sections. (0x%X)\n", GetLastError());
				VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	if (!WriteProcessMemory(hProcess, targetBase, sourceData, 0x1000, nullptr))
	{
		printf("[-] Failed to write process memory. (0x%X)\n", GetLastError());
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		return false;
	}
	WriteProcessMemory(hProcess, targetBase, &data, sizeof(data), nullptr);

	void* shellCode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellCode)
	{
		printf("[-] Shellcode allocation failed. (0x%X)\n", GetLastError());
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProcess, shellCode, ShellCode, 0x1000, nullptr))
	{
		printf("[-] Failed to write shellcode (0x%X)\n", GetLastError());
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		return false;
	}

	if (execution == M_NtCreateThreadEx)
	{
		CreateThreadEx(hProcess, shellCode, targetBase);
	}
	else if (execution == M_ThreadHijacking)
	{
		HijackThread(hProcess, shellCode, targetBase);
	}

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		DWORD exitcode = 0;
		GetExitCodeProcess(hProcess, &exitcode);

		if (exitcode != STILL_ACTIVE)
		{
			printf("[-] Process crashed. (ExitCode: %d)\n", exitcode);
			return false;
		}

		MANUAL_MAPPING_STRUCT checkedData{ 0 };
		ReadProcessMemory(hProcess, targetBase, &checkedData, sizeof(checkedData), nullptr);
		hCheck = checkedData.hMain;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
	return true;
}

void __stdcall ShellCode(MANUAL_MAPPING_STRUCT* data)
{
	if (!data)
	{
		return;
	}

	BYTE* bBase = reinterpret_cast<BYTE*>(data);
	auto* optHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(bBase + reinterpret_cast<IMAGE_DOS_HEADER*>(data)->e_lfanew)->OptionalHeader;

	auto getProcAdress = data->pGetProcAddress;
	auto dllMain = reinterpret_cast<DLL_ENTRY_POINT>(bBase + optHeader->AddressOfEntryPoint);

	BYTE* deltaLoc = bBase - optHeader->ImageBase;
	if (deltaLoc)
	{
		if (!optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			return;
		}

		auto* relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(bBase + optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (relocData->VirtualAddress)
		{
			UINT entryAmount = (relocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* rInfo = reinterpret_cast<WORD*>(relocData + 1);

			for (UINT i = 0; i != entryAmount; ++i, ++rInfo)
			{
				if (RELOC_FLAG(*rInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(bBase + relocData->VirtualAddress + ((*rInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(deltaLoc);
				}
			}
			relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(relocData) + relocData->SizeOfBlock);
		}
	}

	if (optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* importdesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(bBase + optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (importdesc->Name)
		{
			char* szType = reinterpret_cast<char*>(bBase + importdesc->Name);
			HINSTANCE hDll = data->pLoadLibraryA(szType);

			ULONG_PTR* ofirstThunk = reinterpret_cast<ULONG_PTR*>(bBase + importdesc->OriginalFirstThunk);
			ULONG_PTR* firstThunk = reinterpret_cast<ULONG_PTR*>(bBase + importdesc->FirstThunk);

			if (!ofirstThunk)
			{
				ofirstThunk = firstThunk;
			}

			for (; *ofirstThunk; ofirstThunk++, firstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*ofirstThunk))
				{
					*firstThunk = getProcAdress(hDll, reinterpret_cast<char*>(*ofirstThunk & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(bBase + (*ofirstThunk));
					*firstThunk = getProcAdress(hDll, pImport->Name);
				}
			}
			importdesc++;
		}
	}

	if (optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* tlsDir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(bBase + optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* tlsCall = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDir->AddressOfCallBacks);
		for (; tlsCall && *tlsCall; tlsCall++)
		{
			(*tlsCall)(bBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	dllMain(bBase, DLL_PROCESS_ATTACH, nullptr);

	data->hMain = reinterpret_cast<HINSTANCE>(bBase);
}
#pragma once
#include "Includes.h"

using _LoadLibraryA = HINSTANCE(WINAPI*)(const char* libFileName);
using _GetProcAddress = UINT_PTR(WINAPI*)(HMODULE hModule, const char* processName);
using DLL_ENTRY_POINT = BOOL(WINAPI*)(void* dll, DWORD reason, void* reserved);

struct MANUAL_MAPPING_STRUCT
{
	_LoadLibraryA pLoadLibraryA;
	_GetProcAddress pGetProcAddress;
	HINSTANCE hMain;
};

bool IManualMap(HANDLE hProcess, BYTE* sourceData, SIZE_T dllSize, EXECUTION_METHOD execution);
void __stdcall ShellCode(MANUAL_MAPPING_STRUCT* data);
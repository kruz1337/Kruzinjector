#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using _LoadLibraryA = HINSTANCE(WINAPI*)(const char* libFileName);
using _GetProcAddress = UINT_PTR(WINAPI*)(HMODULE hModule, const char* processName);
using DLL_ENTRY_POINT = BOOL(WINAPI*)(void* dll, DWORD reason, void* reserved);

struct MANUAL_MAPPING_STRUCT
{
	_LoadLibraryA pLoadLibraryA;
	_GetProcAddress pGetProcAddress;
	HINSTANCE hMain;
};

bool ManualMap(HANDLE hProcess, BYTE* sourceData, SIZE_T dllSize);
void __stdcall ShellCode(MANUAL_MAPPING_STRUCT* data);
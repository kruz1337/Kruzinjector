#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

bool LoadLibraryInject(HANDLE hProcess, const char* dllFile);
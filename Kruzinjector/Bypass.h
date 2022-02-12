#pragma once

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

bool BypassInject(HANDLE hProcess, const char* dllFile);
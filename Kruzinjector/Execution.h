#pragma once
#include "Includes.h"

bool HijackThread(HANDLE hProcess, void* shellCode, void* targetBase);
bool CreateThreadEx(HANDLE hProcess, void* shellCode, void* targetBase);
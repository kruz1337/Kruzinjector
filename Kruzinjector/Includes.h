#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>

#include "rapidxml/rapidxml.hpp"

#define FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define MACHINE_ARC IMAGE_FILE_MACHINE_AMD64
#define RELOC_FLAG FLAG64
#else
#define MACHINE_ARC IMAGE_FILE_MACHINE_I386
#define RELOC_FLAG FLAG32
#endif

enum INJECTION_TYPE
{
	T_LoadLibrary,
	T_ManualMap,
};

enum EXECUTION_METHOD
{
	M_NtCreateThreadEx,
	M_ThreadHijacking
};
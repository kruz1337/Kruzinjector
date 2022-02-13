#include <vector>

#include "Standart.h"
#include "ManualMap.h"
#include "Bypass.h"
#include <string>
#include <sstream>
#include "rapidxml/rapidxml.hpp"

#ifdef _WIN64
#define MACHINE_ARC IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE_ARC IMAGE_FILE_MACHINE_I386
#endif

rapidxml::xml_document<> doc;
bool isCorrupt = 0;

void createAscii()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);

	std::cout << R"(
                               ____                             __ _  __    ____                  
                              / __ \___  ____ ___  _____  _____/ /| |/ /   / __ \___ _   __  
                             / /_/ / _ \/ __ `/ / / / _ \/ ___/ __|   /   / / / / _ | | / /  
                            / _, _/  __/ /_/ / /_/ /  __(__  / /_/   |   / /_/ /  __| |/ _    
                           /_/ |_|\___/\__, /\__,_/\___/____/\__/_/|_|  /_____/\___/|___(_)         
)" << '\n';
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 94);
}

void customCls()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 1);
	system("CLS");
	createAscii();
}

/* Gets process id from process name */
DWORD GetProcessIdByName(const char* ProcessName)
{
	PROCESSENTRY32 procEntry;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &procEntry))
	{
		while (Process32Next(hSnap, &procEntry))
		{
			if (!_strcmpi(procEntry.szExeFile, ProcessName))
			{
				CloseHandle(hSnap);
				return procEntry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnap);
	return 0;
}

/* Returns true if the process is an 64-bit process */
BOOL isWow64bit(HANDLE hProcess)
{
	BOOL is64bit = FALSE;

	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS is64bitProcess;
	is64bitProcess = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (is64bitProcess != NULL && !is64bitProcess(hProcess, &is64bit))
	{
		printf("Handle Error..\n");
		return false;
	}
	return is64bit;
}

/* Checks if the process is a 32-bit process running on 64-bit */
bool isx86Process(HANDLE hProcess)
{
	SYSTEM_INFO systemInfo = { 0 };
	GetNativeSystemInfo(&systemInfo);

	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		return true;
	}

	return isWow64bit(hProcess);
}

/* Converts text lowercase */
std::string toLower(std::string string)
{
	for (int i = 0; i < string.length(); i++)
	{
		string[i] = tolower(string[i]);
	}

	return string;
}

/* Xml config functions */
std::string getSetting(const char* item)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node(item)->value();
}

std::string getSettingSub(const char* item)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node("AutoInject")->last_node(item)->value();
}

std::string getSettingAttr(const char* item, const char* attr)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node(item)->first_attribute(attr)->value();
}

/* Main inject part */
bool StartInject(int injectType, const char* injectName, const char* dllFile)
{
	DWORD PID;
	std::ifstream Dll(dllFile, std::ios::binary | std::ios::ate);

	/* Process control part */
	if (!GetProcessIdByName(injectName))
	{
		printf("[!] Process is not valid. (0x%X)\n", GetLastError());
		return false;
	}
	PID = GetProcessIdByName(injectName);

	if (!Dll) // Check Dll file is exits
	{
		printf("[!] Dll file doesn't exist\n");
		return false;
	}
	if (Dll.fail()) // Check that there is an openable file
	{
		printf("[!] Dll file open failed. (0x%X)\n", (DWORD)Dll.rdstate());
		return false;
	}

	auto dllSize = Dll.tellg();
	if (dllSize < 0x1000) // Check file is valid
	{
		printf("[!] Invalid dll file size.\n");
		return false;
	}

	BYTE* sourceData = new BYTE[(UINT_PTR)dllSize];
	if (!sourceData) {
		printf("[!] Dll file can't allocate.\n");
		Dll.close();
		return -7;
	}

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_magic != 0x5A4D) /* Checks MZ */
	{
		printf("[!] Invalid dll file.\n");
		return false;
	}

	Dll.seekg(0, std::ios::beg);
	Dll.read(reinterpret_cast<char*>(sourceData), dllSize);
	Dll.close();

	IMAGE_FILE_HEADER* fileHeader = nullptr;
	fileHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(sourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_lfanew)->FileHeader;

	if (fileHeader->Machine != MACHINE_ARC) // Check injector platform
	{
#ifdef _WIN64
		printf("[!] Invalid platform, use x86 platform!\n");
#else
		printf("[!] Invalid platform, use x64 platform!\n");
#endif
		
		return false;
	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf("[!] Failed to Create Snapshot. (0x%X)\n", GetLastError());

		return false;
	}

	// Checks if the file is injected into the correct process (64-32)
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 && isx86Process(hProcess)) 
	{
		printf("[!] You cannot inject 64-bit file into 32-bit application!\n");
		
		return false;
	}
	else if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386 && !isx86Process(hProcess))
	{
		printf("[!] You cannot inject 32-bit file into 64-bit application!\n");
		
		return false;
	}

	printf("[*] Injection started..\n");

	if (!isCorrupt)
	{
		Sleep(stoi(getSetting("Delay")));
	}
	else
	{
		Sleep(500);
	}

	if (injectType == 0)
	{
		if (LoadLibraryInject(hProcess, dllFile))
		{
			printf("[+] Dll file is succesfully injected into game. (Type: 0, Process ID: %X)\n", PID);
		}
		else
		{
			printf("[!] Something went wrong...\n");
			CloseHandle(hProcess);
			return false;
		}
	}
	else if (injectType == 1)
	{
		if (ManualMap(hProcess, sourceData, dllSize))
		{
			printf("[+] Dll file is succesfully injected into game. (Type: 1, Process ID: %X)\n", PID);
		}
		else
		{
			printf("[!] Something went wrong...\n");
			CloseHandle(hProcess);
			return false;
		}
	}
	else if (injectType == 2)
	{
		if (BypassInject(hProcess, dllFile))
		{
			printf("[+] Dll file is succesfully injected into game. (Type: 2, Process ID: %X)\n", PID);
		}
		else
		{
			printf("[!] Something went wrong...\n");
			CloseHandle(hProcess);
			return false;
		}
	}
	CloseHandle(hProcess);
	delete[] sourceData;

	return true;
}

int main()
{
	std::string injectName = "";
	std::string dllFile = "";
	std::string advancedOptions;
	int injectType = 1;

	SetConsoleTitle("DLL INJECTOR | Kruzinjector v1.0");

	createAscii();

	std::ifstream xmlFile("settings.xml");
	std::vector<char> buffer((std::istreambuf_iterator<char>(xmlFile)), std::istreambuf_iterator<char>());
	buffer.push_back('\0');
	if (xmlFile.fail())
	{
		printf("[*] Config file can't opened!\n");
		isCorrupt = 1;
	}
	xmlFile.close();

	try
	{
		doc.parse<0>(&buffer[0]);
	}
	catch (...)
	{
		printf("[*] Config file is corrupt!\n");
		isCorrupt = 1;
	}

	// If Auto Inject enabled, automatically start injection part
	if (!isCorrupt)
	{
		if (getSettingAttr("AutoInject", "enabled") == "true")
		{
			if (!(getSettingSub("IType") == "0" || getSettingSub("IType") == "1" || getSettingSub("IType") == "2"))
			{
				customCls();
				printf("[*] CONFIG: Invalid Injection Type...\n");
				system("PAUSE");
				return 0;
			}

			StartInject(stoi(getSettingSub("IType")), getSettingSub("ProcessName").c_str(), getSettingSub("IFile").c_str());
			system("PAUSE");
			return 0;
		}
	}

	printf("Process Name: ");
	std::cin >> injectName;

	printf("\n- 0: Standart\n- 1: Manual Mapping\n- 2: Load Library Bypass\n");
	printf("Select Injection Type: ");
	std::cin >> injectType;

	if (!std::cin >> injectType || !(injectType == 0 || injectType == 1 || injectType == 2))
	{
		customCls();
		printf("[*] Invalid Injection Type.\n");
		return 0;
	}

	printf("\nSelect Dll File: ");
	std::cin >> dllFile;

	customCls();

	StartInject(injectType, injectName.c_str(), dllFile.c_str());

	system("PAUSE");
	return 0;
}

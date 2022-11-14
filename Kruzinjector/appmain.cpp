#include "Utils.h"
#include "LoadLibrary.h"
#include "ManualMap.h"

using namespace std;

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

void clearCMD()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 1);
	system("CLS");
	createAscii();
}

rapidxml::xml_document<> xmlConfig;
bool isBrokenConfig;

/* Main inject part */
bool StartInject(const char* injectName, const char* dllFile, INJECTION_TYPE type, EXECUTION_METHOD execution)
{
	DWORD processId;
	std::ifstream Dll(dllFile, std::ios::binary | std::ios::ate);

	char releativePath[MAX_PATH];
	GetFullPathNameA(dllFile, MAX_PATH, releativePath, nullptr);
	dllFile = releativePath;

	processId = GetProcessIdByName(injectName);
	if (!processId)
	{
		printf("[-] Process is not valid. (0x%X)\n", GetLastError());
		return false;
	}

	if (!Dll) // Check Dll file is exits
	{
		printf("[-] Dll file doesn't exist\n");
		return false;
	}
	if (Dll.fail()) // Check that there is an openable file
	{
		printf("[-] Dll file open failed. (0x%X)\n", (DWORD)Dll.rdstate());
		return false;
	}

	auto dllSize = Dll.tellg();
	if (dllSize < 0x1000) // Check file is valid
	{
		printf("[-] Invalid dll file size.\n");
		return false;
	}

	BYTE* sourceData = new BYTE[(UINT_PTR)dllSize];
	if (!sourceData) {
		printf("[-] Dll file can't allocate.\n");
		Dll.close();
		return false;
	}

	Dll.seekg(0, std::ios::beg);
	Dll.read(reinterpret_cast<char*>(sourceData), dllSize);
	Dll.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_magic != 0x5A4D) // Checks MZ
	{
		printf("[-] Invalid dll file.\n");
		return false;
	}

	IMAGE_FILE_HEADER* fileHeader = nullptr;
	fileHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(sourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_lfanew)->FileHeader;

	if (fileHeader->Machine != MACHINE_ARC) // Check injector platform
	{
#ifdef _WIN64
		printf("[-] Invalid platform, use x86 platform!\n");
#else
		printf("[-] Invalid platform, use x64 platform!\n");
#endif
		return false;
	}

	// Checks if the file is injected into the correct process (64-32)
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 && IsX86Process(hProcess)) 
	{
		printf("[-] You cannot inject 64-bit file into 32-bit application!\n");
		return false;
	}
	else if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386 && !IsX86Process(hProcess))
	{
		printf("[-] You cannot inject 32-bit file into 64-bit application!\n");
		return false;
	}

	printf("[*] Injection started..\n\n");
	Sleep(isBrokenConfig ? 500 : stoi(GetSetting("Delay", xmlConfig)));

	if (type == T_LoadLibrary)
	{
		if (ILoadLibrary(hProcess, dllFile, execution))
		{
			printf("[+] Dll file is succesfully injected into game.\n");
		}
		else
		{
			printf("[-] Something went wrong...\n");
			CloseHandle(hProcess);
			return false;
		}
	}
	else if (type == T_ManualMap)
	{
		if (IManualMap(hProcess, sourceData, dllSize, execution))
		{
			printf("[+] Dll file is succesfully injected into game.\n");
		}
		else
		{
			printf("[-] Something went wrong...\n");
			CloseHandle(hProcess);
			return false;
		}
	}

	printf("[*] Injection Type: %i\n", type);
	printf("[*] Execution Method: %i\n", execution);
	printf("[*] Process ID: %i\n", processId);

	CloseHandle(hProcess);
	delete[] sourceData;

	return true;
}

int main()
{
	std::string injectName = "";
	std::string dllFile = "";
	std::string advancedOptions;
	int injectType = 0;
	int executionMethod = 0;

	SetConsoleTitle("DLL INJECTOR | Kruzinjector v1.1");
	createAscii();

	// Config Part
	std::ifstream xmlFile("settings.xml");
	std::vector<char> buffer((std::istreambuf_iterator<char>(xmlFile)), std::istreambuf_iterator<char>());
	buffer.push_back('\0');
	if (xmlFile.fail())
	{
		isBrokenConfig = true;
	}
	else
	{
		try
		{
			xmlConfig.parse<0>(&buffer[0]);
		}
		catch (...)
		{
			printf("[*] Config file is corrupt!\n");
			isBrokenConfig = true;
		}
	}
	xmlFile.close();

	// If Auto Inject enabled, automatically start injection part
	if (!isBrokenConfig)
	{
		int IType = stoi(GetSubSetting("InjectionType", xmlConfig));
		int IMethod = atoi(GetSubSetting("ExecutionMethod", xmlConfig));
		const char* PName = GetSubSetting("ProcessName", xmlConfig);
		const char* IFile = GetSubSetting("InjectionFile", xmlConfig);

		if (strcmp(GetAttrSetting("AutoInject", "enabled", xmlConfig), "true") == 0)
		{
			if (IType != 0 && IType != 1)
			{
				clearCMD();
				printf("[-] CONFIG: Invalid Injection Type...\n");
				system("PAUSE");
				return 0;
			}

			StartInject(PName, IFile, (INJECTION_TYPE)IType, (EXECUTION_METHOD)IMethod);
			system("PAUSE");
			return 0;
		}
	}


	printf("\n[*] Process Name: \n> ");
	std::cin >> injectName;

	printf("\n[*] Choose injection type. (0: LoadLibrary, 1: ManualMap)\n> ");
	std::cin >> injectType;

	printf("\n[*] Choose execution method. (0: CreateThreadEx, 1: ThreadHijacking)\n> ");
	std::cin >> executionMethod;

	if (!std::cin >> injectType || !(injectType == 0 || injectType == 1))
	{
		clearCMD();
		printf("[-] Invalid injection type.\n");
		return 0;
	}

	if (!std::cin >> executionMethod || !(executionMethod == 0 || executionMethod == 1))
	{
		clearCMD();
		printf("[-] Invalid execution method.\n");
		return 0;
	}

	printf("\n[*] DLL File Path: \n> ");
	std::cin >> dllFile;

	clearCMD();

	StartInject(injectName.c_str(), dllFile.c_str(), (INJECTION_TYPE)injectType, (EXECUTION_METHOD)executionMethod);

	system("PAUSE");
	return 0;
}
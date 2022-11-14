#include "Utils.h"

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
BOOL IsWow64bit(HANDLE hProcess)
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
bool IsX86Process(HANDLE hProcess)
{
	SYSTEM_INFO systemInfo = { 0 };
	GetNativeSystemInfo(&systemInfo);

	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		return true;
	}

	return IsWow64bit(hProcess);
}

std::string ToLower(std::string string)
{
	for (int i = 0; i < string.length(); i++)
	{
		string[i] = tolower(string[i]);
	}

	return string;
}

const char* GetSetting(const char* item, rapidxml::xml_document<>& doc)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node(item)->value();
}

const char* GetSubSetting(const char* item, rapidxml::xml_document<>& doc)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node("AutoInject")->last_node(item)->value();
}

const char* GetAttrSetting(const char* item, const char* attr, rapidxml::xml_document<> &doc)
{
	rapidxml::xml_node<>* root_node = NULL;
	root_node = doc.first_node("Settings");

	return root_node->last_node(item)->first_attribute(attr)->value();
}
#pragma once
#include "Includes.h"

const char* GetSetting(const char* item, rapidxml::xml_document<>& doc);
const char* GetSubSetting(const char* item, rapidxml::xml_document<>& doc);
const char* GetAttrSetting(const char* item, const char* attr, rapidxml::xml_document<>& doc);
std::string ToLower(std::string string);
DWORD GetProcessIdByName(const char* ProcessName);
BOOL IsWow64bit(HANDLE hProcess);
bool IsX86Process(HANDLE hProcess);
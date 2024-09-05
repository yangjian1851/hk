// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <windows.h>
#include "detours.h"
#include <iostream>
#include <string>
#include <iphlpapi.h>
#include <Tlhelp32.h>
#include <tchar.h> 
#include <psapi.h>
#include "Utils.h"
//#include "asyncLogger .h"

// 使用 Windows 子系统，不显示控制台窗口
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

std::string exe = "GServer.exe";
std::string exePath = "D:\\Fjdwj\\server\\sss6-1\\";
std::string hkdll = "hk_41002008.dll";



bool InjectDLL(DWORD processID, const char* dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process: " << GetLastError() << std::endl;
		return false;
	}

	void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		std::cerr << "Failed to allocate memory in target process: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
		std::cerr << "Failed to write to process memory: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL) {
		std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	std::cerr << "success to injectDll: " << dllPath << std::endl;
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

std::string GetFullPath(const std::string& path) {
	char fullPath[MAX_PATH];
	if (GetFullPathNameA(path.c_str(), MAX_PATH, fullPath, NULL)) {
		return std::string(fullPath);
	}
	else {
		return "";
	}
}

bool ArePathsSameDirectory(const std::string& path1, const std::string& path2) {
	std::string fullPath1 = GetFullPath(path1);
	std::string fullPath2 = GetFullPath(path2);

	if (fullPath1.empty() || fullPath2.empty()) {
		std::wcerr << L"Error resolving paths." << std::endl;
		return false;
	}

	return strcmp(fullPath1.c_str(), fullPath2.c_str()) == 0;
}

std::string GetProcessPath(DWORD processID) {
	char processPath[MAX_PATH] = ("");

	// 打开进程句柄
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess != NULL) {
		// 获取进程主模块路径
		if (GetModuleFileNameExA(hProcess, NULL, processPath, MAX_PATH)) {
			//std::wcout << L"Process ID: " << processID << L" Path: " << processPath << std::endl;
		}
		else {
			std::wcout << L"Failed to get process path for Process ID: " << processID << std::endl;
		}

		// 关闭进程句柄
		CloseHandle(hProcess);
		return processPath;  // 返回进程路径
	}
	else {
		std::wcout << L"Failed to open process for Process ID: " << processID << std::endl;
	}
	return processPath;  // 返回进程路径
}

void Monitor(const TCHAR* exeName, std::string curRunPath) {
	std::wcout << "Monitor exeName:" << exeName << std::endl;
	std::string dllPath = curRunPath + hkdll;
	std::cout << "dllPath:" << dllPath << std::endl;
	bool findexe = false;
	bool isInject = false;
	while (true) {
		findexe = false;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
			return;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe)) {
			do {
				if (_tcsicmp(pe.szExeFile, exeName) == 0) {
					std::string currentExePath = GetProcessPath(pe.th32ProcessID);
					size_t pos = currentExePath.find_last_of("\\/");
					if (pos != std::wstring::npos) {
						currentExePath = currentExePath.substr(0, pos+1);
					}
					//std::cout << "currentExePath:" << currentExePath << std::endl;
					//std::cout << "exePath:" << exePath << std::endl;
					if (ArePathsSameDirectory(currentExePath, exePath))
					{
						findexe = true;
						if (isInject == false)
						{
							if (InjectDLL(pe.th32ProcessID, dllPath.c_str()))
							{
								isInject = true;
							}
						}
					}
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		if (findexe == false)
		{
			isInject = false;
		}

		CloseHandle(hSnapshot);
		Sleep(500); // Check every second
	}
}

std::wstring StringToWString(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

int main(int argc, char* argv[])
//int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	std::wcout << "argc:" << argc << std::endl;

	if (argc > 3)
	{
		std::cout << "Monitor exeName:" << argv[1] << std::endl;
		std::cout << "path:" << argv[2] << std::endl;
		exe = argv[1];
		exePath = argv[2];
		hkdll = argv[3];

	}
	std::wstring wstr = StringToWString(exe);
	char path[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, path, MAX_PATH);
	std::string curRunPath = path;
	std::cout << "curRunPath:" << curRunPath << std::endl;
	size_t pos = curRunPath.find_last_of("\\/");
	if (pos != std::wstring::npos) {
		curRunPath = curRunPath.substr(0, pos + 1);
	}
	Monitor(wstr.c_str(), curRunPath);

	return 0;
}

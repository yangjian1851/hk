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
#include "asyncLogger .h"

// 使用 Windows 子系统，不显示控制台窗口
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

std::string exe = "GServer.exe";
std::string exePath = "D:\\Fjdwj\\server\\sss6-1\\";
std::string hkdll = "hk_17061300.dll";


// 定义函数指针类型，用于动态调用 OpenProcess
typedef HANDLE(WINAPI* pfnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// 定义函数指针类型，用于动态调用 VirtualAllocEx
typedef LPVOID(WINAPI* pfnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

// 定义函数指针类型，用于动态调用 WriteProcessMemory
typedef BOOL(WINAPI* pfnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

// 定义函数指针类型，用于动态调用 CreateRemoteThread
typedef HANDLE(WINAPI* pfnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

// NtAlertResumeThread 函数的原型定义
typedef LONG(NTAPI* NtAlertResumeThread_t)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

#include <winternl.h>  // 包含NTSTATUS类型的定义

// NtCreateThreadEx 函数定义
typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument,
	IN ULONG CreateFlags,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PVOID AttributeList
	);

// 注入函数
bool InjectDLLUsingSyscall(DWORD processID, const char* dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (!hProcess) {
		std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
		std::string msg = "OpenProcess failed: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		return false;
	}
	// 分配内存并写入 DLL 路径
	LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pDllPath) {
		std::cerr << "Failed to VirtualAllocEx: " << GetLastError() << std::endl;
		std::string msg = "Failed to VirtualAllocEx  " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hProcess);
		return false;
	}
	if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL))
	{
		std::string msg = "Failed to WriteProcessMemory  " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
		

	// 获取 LoadLibraryA 的地址
	LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary) {
		std::cerr << "GetProcAddress for LoadLibraryA failed: " << GetLastError() << std::endl;
		std::string msg = "GetProcAddress for LoadLibraryA failed: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取 NtCreateThreadEx 的地址
	HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");
	if (!NtCreateThreadEx)
	{
		std::string msg = "GetProcAddress for NtCreateThreadEx failed: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 创建远程线程
	HANDLE hThread = NULL;
	NTSTATUS status = NtCreateThreadEx(
		&hThread,
		0x1FFFFF, // 所有访问权限
		NULL,
		hProcess,
		pLoadLibrary,
		pDllPath,
		FALSE,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (status == 0 && hThread != NULL) {
		// 等待远程线程执行
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	std::string msg = "success to load dll ";
	gAsyncLogger.log(msg);
	return true;
}


// 动态加载 OpenProcess、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread 并调用它们
bool InjectDLL(DWORD processID, const char* dllPath) {
	std::string msg = "pre injectDll: ";
	msg += dllPath;
	gAsyncLogger.log(msg);
	// 加载 kernel32.dll 动态库
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (!hKernel32) {
		std::cerr << "Failed to get kernel32.dll handle: " << GetLastError() << std::endl;
		return false;
	}

	// 动态获取 OpenProcess 函数地址
	pfnOpenProcess OpenProcessDynamic = (pfnOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
	if (!OpenProcessDynamic) {
		std::cerr << "Failed to get OpenProcess address: " << GetLastError() << std::endl;
		return false;
	}

	// 动态获取 VirtualAllocEx 函数地址
	pfnVirtualAllocEx VirtualAllocExDynamic = (pfnVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
	if (!VirtualAllocExDynamic) {
		std::cerr << "Failed to get VirtualAllocEx address: " << GetLastError() << std::endl;
		return false;
	}

	// 动态获取 WriteProcessMemory 函数地址
	pfnWriteProcessMemory WriteProcessMemoryDynamic = (pfnWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
	if (!WriteProcessMemoryDynamic) {
		std::cerr << "Failed to get WriteProcessMemory address: " << GetLastError() << std::endl;
		return false;
	}

	// 动态获取 CreateRemoteThread 函数地址
	pfnCreateRemoteThread CreateRemoteThreadDynamic = (pfnCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
	if (!CreateRemoteThreadDynamic) {
		std::cerr << "Failed to get CreateRemoteThread address: " << GetLastError() << std::endl;
		return false;
	}

	// 使用动态加载的 OpenProcess 打开目标进程
	HANDLE hProcess = OpenProcessDynamic(PROCESS_ALL_ACCESS, FALSE, processID);
	if (!hProcess) {
		std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
		return false;
	}

	// 在目标进程中分配内存
	LPVOID pDllPath = VirtualAllocExDynamic(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pDllPath) {
		std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	// 将 DLL 路径写入目标进程
	if (!WriteProcessMemoryDynamic(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, nullptr)) {
		std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取 LoadLibraryA 的地址
	LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
	if (!pLoadLibrary) {
		std::cerr << "GetProcAddress for LoadLibraryA failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 创建远程线程加载 DLL
	HANDLE hThread = CreateRemoteThreadDynamic(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, nullptr);
	if (!hThread) {
		std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 等待远程线程执行完成
	WaitForSingleObject(hThread, INFINITE);

	// 清理
	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}



bool InjectDLL1(DWORD processID, const char* dllPath) {
	std::string msg = "pre injectDll: ";
	msg += dllPath;
	gAsyncLogger.log(msg);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process: " << GetLastError() << std::endl;
		std::string msg = "Failed to open process: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		return false;
	}

	void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		std::cerr << "Failed to allocate memory in target process: " << GetLastError() << std::endl;
		std::string msg = "Failed to allocate memory in target process: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
		std::cerr << "Failed to write to process memory: " << GetLastError() << std::endl;
		std::string msg = "Failed to write to process memory:: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL) {
		std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
		std::string msg = "Failed to create remote thread:: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	msg = "success to injectDll:" + std::to_string(GetLastError());
	gAsyncLogger.log(msg);
	std::cerr << "success to injectDll: " << dllPath << std::endl;
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

// 获取目标进程的主线程 ID
DWORD GetMainThreadId(DWORD processID) {
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	if (Thread32First(hThreadSnap, &te32)) {
		do {
			if (te32.th32OwnerProcessID == processID) {
				CloseHandle(hThreadSnap);
				return te32.th32ThreadID;  // 返回主线程 ID
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}

	CloseHandle(hThreadSnap);
	return 0;
}

// APC 注入函数
bool InjectDLLViaAPC(DWORD processID, const char* dllPath) {
	// 动态加载 ntdll.dll 中的 NtAlertResumeThread
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	NtAlertResumeThread_t NtAlertResumeThread = (NtAlertResumeThread_t)GetProcAddress(hNtdll, "NtAlertResumeThread");
	if (!NtAlertResumeThread) {
		std::cerr << "Failed to get NtAlertResumeThread address: " << GetLastError() << std::endl;
		std::string msg = "Failed to get NtAlertResumeThread address:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		return false;
	}
	// 打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (!hProcess) {
		std::cerr << "Failed to open target process: " << GetLastError() << std::endl;
		std::string msg = "Failed to open target process:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		return false;
	}

	// 分配内存，用于存储 DLL 路径
	LPVOID pDllPath = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pDllPath) {
		std::cerr << "Failed to allocate memory in target process: " << GetLastError() << std::endl;
		std::string msg = "Failed to allocate memory in target process:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hProcess);
		return false;
	}

	// 将 DLL 路径写入目标进程内存
	if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, nullptr)) {
		std::cerr << "Failed to write DLL path to target process: " << GetLastError() << std::endl;
		std::string msg = "Failed to write DLL path to target process: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取目标进程的主线程 ID
	DWORD threadID = GetMainThreadId(processID);
	if (!threadID) {
		std::cerr << "Failed to find main thread of target process." << std::endl;
		std::string msg = "Failed to find main thread of target process. " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 打开目标线程
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
	if (!hThread) {
		std::cerr << "Failed to open target thread: " << GetLastError() << std::endl;
		std::string msg = "Failed to open target thread: " + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取 LoadLibraryA 的地址
	LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibraryA) {
		std::cerr << "Failed to get LoadLibraryA address: " << GetLastError() << std::endl;
		std::string msg = "Failed to get LoadLibraryA address:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 将 LoadLibraryA 排入 APC 队列
	if (QueueUserAPC((PAPCFUNC)pLoadLibraryA, hThread, (ULONG_PTR)pDllPath) == 0) {
		std::cerr << "Failed to queue APC: " << GetLastError() << std::endl;
		std::string msg = "Failed to queue APC:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 使用 NtAlertResumeThread 恢复线程并触发 APC 执行
	ULONG suspendCount = 0;
	LONG status = NtAlertResumeThread(hThread, &suspendCount);
	if (status != 0) {
		std::cerr << "NtAlertResumeThread failed: " << GetLastError() << std::endl;
		std::string msg = "NtAlertResumeThread failed." + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	std::cout << "APC queued successfully. Target thread will load DLL when it enters alertable state." << std::endl;
	std::string msg = "APC queued successfully. Target thread will load DLL when it enters alertable state." ;
	gAsyncLogger.log(msg);
	// 关闭句柄
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
			std::string msg = "Failed to get process path for Process ID:" + std::to_string(GetLastError());
			gAsyncLogger.log(msg);
		}

		// 关闭进程句柄
		CloseHandle(hProcess);
		return processPath;  // 返回进程路径
	}
	else {
		std::wcout << L"Failed to open process for Process ID: " << processID << std::endl;
		std::string msg = "Failed to open process for Process ID:" + std::to_string(GetLastError());
		gAsyncLogger.log(msg);
	}
	return processPath;  // 返回进程路径
}

void Monitor(const TCHAR* exeName, std::string curRunPath) {
	std::wcout << "Monitor exeName:" << exeName << std::endl;
	std::string dllPath = curRunPath + hkdll;
	std::cout << "dllPath:" << dllPath << std::endl;
	std::string msg = "dllPath::" + dllPath;
	gAsyncLogger.log(msg);
	bool findexe = false;
	bool isInject = false;
	while (true) {
		findexe = false;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
			std::string msg = "Failed to create snapshot::" + std::to_string(GetLastError());
			gAsyncLogger.log(msg);
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

					if (ArePathsSameDirectory(currentExePath, exePath))
					{
						findexe = true;
						if (isInject == false)
						{
							if (InjectDLLUsingSyscall(pe.th32ProcessID, dllPath.c_str()))
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
		Sleep(3000); // Check every second
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

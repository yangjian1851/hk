// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <windows.h>
#include "detours.h"
#include <iostream>
#include <Winsock2.h>
#include <string>
#include <iphlpapi.h>
#include <Tlhelp32.h>
#include <tchar.h> 
#include <winternl.h>

TCHAR exe[16] = L"360.exe";
char hkdll[] = "hk.dll";
char dll[] = "add.dll";
// 定义原始函数类型和函数指针
typedef void (* func)();
func OriginalFunction = NULL;
//LPVOID oldcode;


#define HOOK_SIZE 5  // 5字节用于存放跳转指令
DWORD oldcode;

bool load()
{
	HMODULE hModule = LoadLibraryA(dll);
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() <<std::endl;
		return false;
	}
	// 计算函数地址，加上偏移
	DWORD offset = 0x1003;//0x10001000
	OriginalFunction = (func)((DWORD_PTR)hModule + offset);
	// 保存目标地址处的原始指令
	//memcpy(originalCode, (LPVOID)((DWORD_PTR)hModule + offset +5), 5);
	oldcode = (DWORD)OriginalFunction + 5;
	// 检查函数地址
	if (!OriginalFunction) {
		std::cerr << "Failed to get function address" << std::endl;
		FreeLibrary(hModule);
		return false;
	}
	std::cerr << "success load " << dll << std::endl;
	return true;
}
// Hook 函数
void __declspec(naked)  HookedFunction() {
	__asm {
		; mov     edx, [ecx + 8]; 恢复被破坏的代码
		; test    edx, edx
		mov     ecx, [ebp + 8]
		test    ecx, ecx

		add [ecx + 8], 4; 修改循环次数
		jmp oldcode; 跳回到原始代码后面的位置
	}
	//OriginalFunction();
}

void AttachHooks() {
	// Detour transaction to attach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	// 启用 Hook
	DetourAttach(&(PVOID&)OriginalFunction, HookedFunction);

	DetourTransactionCommit();
}

void DetachHooks() {
	// Detour transaction to detach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// Detach our hook function
	DetourDetach(&(PVOID&)OriginalFunction, HookedFunction);

	DetourTransactionCommit();
}

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

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

void Monitor(TCHAR * exeName) {
	const char* dllPath = hkdll;
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
					findexe = true;
					if (isInject == false)
					{
						if (InjectDLL(pe.th32ProcessID, dllPath))
						{
							isInject = true;
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
		Sleep(1); // Check every second
	}
}

int main(int argc, char* argv[])
//int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	if (argc > 1)
	{
		memcpy(exe, argv[1], 16);
	}
	Monitor(exe);
	/*if (argc > 1)
	{
		memcpy(dll, argv[1], 16);
	}
	std::cerr << "start load..." << std::endl;
	if (load())
	{
		AttachHooks();
	}
	while (true)
	{
		Sleep(1000);
	}

	DetachHooks();*/
	return 0;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (load())
		{
			AttachHooks();
		}
	}
		break;
	case DLL_PROCESS_DETACH:
		DetachHooks();
		break;
	}
	return TRUE;
}

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

char dll[16] = "41002008.dll";
// 定义原始函数类型和函数指针
typedef void (* func)(void *);
func OriginalFunction = NULL;

bool load()
{
	HMODULE hModule = LoadLibraryA(dll);
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() <<std::endl;
		return false;
	}
	// 计算函数地址，加上偏移
	DWORD offset = 0x1AC70;//0x1001AC70
	OriginalFunction = (func)((DWORD_PTR)hModule + offset);

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
int WINAPI HookedFunction(void *p) {
	//先调用原始的
	OriginalFunction(p);
	//在处理具体的
	std::cout << "Hooked Function called with parameters: " << p << std::endl;
	unsigned int count = *((unsigned __int8*)p + 8264);//猜测这是人数

	char card[0x68] = { 0 };
	memcpy(card, ((unsigned __int8*)p + 10142), 0x68);//得到所有的卡牌
	std::cout << "card data's: " << std::endl;
	for (int i=0; i<0x68; i++)
	{
		if ((i != 0) && (i%13 == 0))
		{
			std::cout << card[i] << std::endl;
		}
		else {
			std::cout << card[i];
		}
		
	}
	//这里可以修改卡牌的具体逻辑，得到具体的数据后实现

	//将修改后的卡牌重新还原
	memcpy(((char*)p + 10142), card, 0x68);
	return 0;
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

void InjectDLL(DWORD processID, const char* dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process: " << GetLastError() << std::endl;
		return;
	}

	void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		std::cerr << "Failed to allocate memory in target process: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return;
	}

	if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
		std::cerr << "Failed to write to process memory: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL) {
		std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
}

int main(int argc, char* argv[])
//int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	if (argc > 1)
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

	DetachHooks();
	return 0;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

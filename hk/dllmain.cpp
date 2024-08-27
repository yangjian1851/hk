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

TCHAR exe[16] = L"GServer.exe";
char hkdll[] = "hk.dll";
char dll[] = "17090400.dll";
// 定义原始函数类型和函数指针
typedef void (* func)();
func OriginalFunction = NULL;
//LPVOID oldcode;


#define HOOK_SIZE 5  // 5字节用于存放跳转指令
DWORD oldcode;
DWORD ebpValue;
BYTE* targetAddress;

bool load()
{
	//MessageBoxA(NULL, dll, "load dll", MB_OK);
	HMODULE hModule = LoadLibraryA(dll);
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() <<std::endl;
		MessageBoxA(NULL, "Failed to load DLL", "load dll", MB_OK);
		return false;
	}
	// 计算函数地址，加上偏移
	DWORD offset = 0x7F1C;//0x7F26   0x7F8B
	OriginalFunction = (func)((DWORD_PTR)hModule + offset);
	// 保存目标地址处的原始指令
	//memcpy(originalCode, (LPVOID)((DWORD_PTR)hModule + offset +5), 5);
	oldcode = (DWORD)OriginalFunction + 6;//10  6
	// 检查函数地址
	if (!OriginalFunction) {
		std::cerr << "Failed to get function address" << std::endl;
		FreeLibrary(hModule);
		return false;
	}
	std::cerr << "success load " << dll << std::endl;
	return true;
}

//char buffer[100] = { 0 }; // 用于存储18字节的内容
//unsigned char* buffer = NULL;

// 外部函数，用于显示内容
void ShowMemoryContent(const DWORD* buffer)
{
	targetAddress = (BYTE*)buffer;
	char hexString[100] = {0}; // 18字节的内容将转换为36字符的十六进制字符串
	for (int i = 0; i < 18; i++) {
		sprintf_s(hexString + i * 2, 3, "%02X,", (targetAddress+i));
	}
	// 显示结果
	MessageBoxA(NULL, hexString, "Memory Content", MB_OK);
}
unsigned char newData[18] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12
};
// Hook 函数
void __declspec(naked)  HookedFunction() {
	//__asm {
	//	pushad
	//}
	//MessageBoxA(NULL, "hooked", "Memory Content", MB_OK);
	//__asm {
	//	popad
	//}


	__asm {
		// 保存所有通用寄存器
		pushad
		mov ecx, dword ptr ss:[ebp - 0x0018]
		lea edx, dword ptr ds:[ecx + 0x26CA]

		mov edi, edx
		// 将 newData 的地址加载到 EDI 寄存器
		lea esi, newData
		// 复制 4 个双字 (16 字节)
		movsd                 // 复制第一个双字
		movsd                 // 复制第二个双字
		movsd                 // 复制第三个双字
		movsd                 // 复制第四个双字
		// 复制剩余的 2 个字节
		movsw                 // 复制一个字

		//mov edi, edx
		//mov byte ptr[edx + 0], 0x01
		//mov byte ptr[edx + 1], 0x02
		//mov byte ptr[edx + 2], 0x03
		//mov byte ptr[edx + 3], 0x04
		//mov byte ptr[edx + 4], 0x05
		//mov byte ptr[edx + 5], 0x06
		//mov byte ptr[edx + 6], 0x07
		//mov byte ptr[edx + 7], 0x08
		//mov byte ptr[edx + 8], 0x09
		//mov byte ptr[edx + 9], 0x0A
		//mov byte ptr[edx + 10], 0x0B
		//mov byte ptr[edx + 11], 0x0C
		//mov byte ptr[edx + 12], 0x0D
		//mov byte ptr[edi + 13], 0x0E
		//mov byte ptr[edx + 14], 0x0F
		//mov byte ptr[edx + 15], 0x10
		//mov byte ptr[edx + 16], 0x11
		//mov byte ptr[edx + 17], 0x12

		popad

		//mov eax, [ebp - 0x374]; 恢复被破坏的代码

		mov dword ptr ss:[ebp - 0x04A8], eax

		jmp oldcode; 跳回到原始代码后面的位置

	}
	//
	//__asm {
	//	push edx
	//	mov edx, [ebp - 18]  // 获取当前EBP寄存器的值
	//	mov ebpValue, edx
	//	pop edx
	//}
	//__asm {
	//	pushad
	//	pushfd
	//}
	//// 计算 [ebp - 0x0018 + 0x26CA] 的地址
	//targetAddress = (BYTE*)(ebpValue);

	////// 读取18字节内容
	//BYTE buffer[18];
	//for (int i = 0; i < 18; i++) {
	//	buffer[i] = targetAddress[i];
	//}

	////// 将字节内容转换为可显示的字符串
	//char hexString[100]; // 18字节的内容将转换为36字符的十六进制字符串
	//for (int i = 0; i < 18; i++) {
	//	sprintf_s(hexString + i * 2, 3, "%02X,", buffer[i]);
	//}

	////// 显示结果
	//MessageBoxA(NULL, hexString, "Memory Content", MB_OK);
	//__asm {
	//	popfd
	//	popad
	//}

	// 执行原始指令: mov [ebp - 0x0374], 0
	//__asm {
	//	mov [ebp - 0x0374], 0; 恢复被破坏的代码
	//	jmp oldcode; 跳回到原始代码后面的位置
	//}
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

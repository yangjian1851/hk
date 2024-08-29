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


#define HOOK_SIZE 6  // 5字节用于存放跳转指令
DWORD oldcode;

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
	oldcode = (DWORD)OriginalFunction + HOOK_SIZE;//10  6
	// 检查函数地址
	if (!OriginalFunction) {
		std::cerr << "Failed to get function address" << std::endl;
		FreeLibrary(hModule);
		return false;
	}
	std::cerr << "success load " << dll << std::endl;
	return true;
}

unsigned char newData[18] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12
};
DWORD userID = 0;
BYTE memoryData[36] = {0};
BYTE roomData[7] = { 0 };
BYTE g_roomData[7] = { 0 };
char buffer[64] = {0};
char *pBuffer = NULL;
FILE* file = NULL;
static int i = 0;
// Hook 函数
void __declspec(naked)  HookedFunction() {
	__asm {
		pushad
		pushfd
	}
	
	__asm {
		mov ecx, dword ptr ss : [ebp - 0x0018]
		lea edx, dword ptr ds : [ecx + 0x26CA]//9930 牌的位置

		; mov ebp, esp
		mov esi, edx             // 将 ECX 的值（内存地址）复制到 ESI
		lea edi, memoryData      // 获取 memoryData 数组的地址
		mov ecx, 36              // 准备读取 36 字节的数据
		rep movsb                // 将 ECX 个字节从 [ESI] 复制到 [EDI]

		mov ecx, dword ptr ss : [ebp - 0x0018]
		lea edx, dword ptr ds : [ecx + 0x2640]//9792 房间位置

		mov esi, edx             // 将 ECX 的值（内存地址）复制到 ESI
		lea edi, roomData       // 获取 memoryData 数组的地址
		mov ecx, 6              // 准备读取 6 字节的数据
		rep movsb               // 将 ECX 个字节从 [ESI] 复制到 [EDI]

		//; movzx eax, byte ptr ss : [ebp - 0x0031] //房间人数
		//mov ecx, dword ptr ss : [ebp - 0x0014]
		//; mov edx, dword ptr ds : [ecx + eax * 4 + 0x2060]
		//mov edx, dword ptr ds : [ecx + 0x0818]
		//mov eax, dword ptr ds : [edx + 0x00A3]
		//mov userID, eax


	}
	fopen_s(&file, "data.bin", "ab");  // 以二进制追加模式打开文件
	if (file != NULL) {
		fwrite(memoryData, 1, sizeof(memoryData), file);  // 以二进制形式写入文件
		//fwrite("\n", 1, 1, file);
		//fwrite(&userID, 1, sizeof(userID), file);
		fclose(file);  // 关闭文件
	}

	if (memcmp(g_roomData, roomData, 6) != 0)
	{
		__asm {
			popfd                    // 恢复标志寄存器
			popad                    // 恢复所有通用寄存器

			mov dword ptr ss : [ebp - 0x04A8] , eax
			jmp oldcode; 跳回到原始代码后面的位置
		}
	}
	else {
		__asm {
			// 保存所有通用寄存器
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

		}
		__asm {
			popfd                    // 恢复标志寄存器
			popad                    // 恢复所有通用寄存器

			mov dword ptr ss : [ebp - 0x04A8] , eax
			jmp oldcode; 跳回到原始代码后面的位置
		}
	}






	
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

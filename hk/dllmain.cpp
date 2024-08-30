// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <windows.h>
#include "detours.h"
#include <iostream>
#include <string>
#include <iphlpapi.h>
#include <Tlhelp32.h>
#include <tchar.h> 
#include "httplib.h"
#include <psapi.h>

using namespace httplib;

std::string exe = "GServer.exe";
std::string exePath = "C:\\Users\\Administrator\\AppData\\dwj\\";
char hkdll[] = "hk.dll";
char dll[] = "17090400.dll";
char dll_17061300[] = "17061300.dll";
// 定义原始函数类型和函数指针
typedef void (* func)();
func OriginalFunction = NULL;
func Original_17061300_Function = NULL;


#define HOOK_SIZE 10  // 5字节用于存放跳转指令
#define CARD_SIZE 78   //棋牌张数 6*D

DWORD oldcode = 0;
DWORD oldcode17061300 = 0;
BYTE memoryData[36] = { 0 };
BYTE roomData[7] = { 0 };
std::atomic<unsigned int> g_roomID = 0;

std::atomic<unsigned int> g_pos = 10;
unsigned char cardData[0x0D] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D };

unsigned char newData[CARD_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 
	0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
};

bool load_17061300()
{
	std::string loadAllPath = exePath + dll_17061300;
	HMODULE hModule = LoadLibraryA(loadAllPath.c_str());
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() << std::endl;
		//MessageBoxA(NULL, "Failed to load DLL", "load dll", MB_OK);
		return false;
	}
	// 计算函数地址，加上偏移
	DWORD offset = 0x01BC5B;//
	Original_17061300_Function = (func)((DWORD_PTR)hModule + offset);
	// 保存目标地址处的原始指令
	//memcpy(originalCode, (LPVOID)((DWORD_PTR)hModule + offset +5), 5);
	oldcode17061300 = (DWORD)Original_17061300_Function + HOOK_SIZE;//10  6
	// 检查函数地址
	if (!Original_17061300_Function) {
		std::cerr << "Failed to get function address" << std::endl;
		//MessageBoxA(NULL, "Failed to load DLL1", "load dll", MB_OK);
		FreeLibrary(hModule);
		return false;
	}
	std::cerr << "success load " << dll << std::endl;
	//MessageBoxA(NULL, "success load ", "load dll", MB_OK);
	return true;
}

bool load()
{
	//MessageBoxA(NULL, dll, "load dll", MB_OK);
	HMODULE hModule = LoadLibraryA(dll);
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() <<std::endl;
		//MessageBoxA(NULL, "Failed to load DLL", "load dll", MB_OK);
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

// Hook 函数
void __declspec(naked)  Hooked_17061300_Function() {
	__asm {
		pushad
		pushfd
	}
	//MessageBoxA(NULL, "HOOKED", "TIPS", MB_OK);
	__asm {
		//mov edx, dword ptr ss : [ebp - 0x0490]
	    //lea eax, dword ptr ds : [edx + 0x277E]//10110 牌的位置

		//mov esi, eax             // 将 ECX 的值（内存地址）复制到 ESI
		//lea edi, memoryData      // 获取 memoryData 数组的地址
		//mov ecx, CARD_SIZE              // 准备读取 36 字节的数据
		//rep movsb                // 将 ECX 个字节从 [ESI] 复制到 [EDI]

		mov ecx, dword ptr ss : [ebp - 0x0490]
		lea edx, dword ptr ds : [ecx + 0x2640]//9792 房间位置

		mov esi, edx             // 将 ECX 的值（内存地址）复制到 ESI
		lea edi, roomData       // 获取 memoryData 数组的地址
		mov ecx, 6              // 准备读取 6 字节的数据
		rep movsb               // 将 ECX 个字节从 [ESI] 复制到 [EDI]

	}

	//fopen_s(&file, "data.bin", "ab");  // 以二进制追加模式打开文件
	//if (file != NULL) {
	//	fwrite(memoryData, 1, sizeof(memoryData), file);  // 以二进制形式写入文件
	//	fwrite(roomData, 1, sizeof(roomData), file);
	//	//fwrite("\n", 1, 1, file);
	//	//fwrite(&userID, 1, sizeof(userID), file);
	//	fclose(file);  // 关闭文件
	//}

	if (atoi((const char*)roomData) != g_roomID)
	{
	}
	else {
		__asm {
			// 保存所有通用寄存器
			mov edx, dword ptr ss : [ebp - 0x0490]
			lea eax, dword ptr ds : [edx + 0x277E]//10110 牌的位置
			movzx ecx, byte ptr ds : [edx + 0x2048] //房间人数
			cmp g_pos, ecx
			jge skip
			imul ecx, g_pos, 0x0D //修改个人单独牌
			add eax, ecx
			mov edi, eax         
			lea esi, cardData      
			mov ecx, 0x0D
			rep movsb               // 将 ECX 个字节从 [ESI] 复制到 [EDI]
		skip :

			//修改整副牌
			//mov edx, dword ptr ss : [ebp - 0x0490]
			//lea eax, dword ptr ds : [edx + 0x277E]//10110 牌的位置
			//mov edi, eax
			//// 将 newData 的地址加载到 EDI 寄存器
			//lea esi, newData
			//movzx eax, byte ptr ds : [edx + 0x2048] //房间人数
			//imul eax, eax, 0x0D  // 将 EAX 寄存器中的值乘以 13，结果保存在 EAX 中
			//mov ecx, eax       // 将乘积结果从 EAX 移动到 ECX 中
			//rep movsb

		}
	}

	__asm {
		popfd                    // 恢复标志寄存器
		popad                    // 恢复所有通用寄存器

		//mov edx, dword ptr ss : [ebp - 0x0490]
		mov dword ptr ss : [ebp - 0x3A0] , 0
		//mov dword ptr ss : [ebp - 0x424] , 0;
		jmp oldcode17061300; 跳回到原始代码后面的位置
	}

}

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
		mov ecx, CARD_SIZE              // 准备读取 36 字节的数据
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
	//fopen_s(&file, "data.bin", "ab");  // 以二进制追加模式打开文件
	//if (file != NULL) {
	//	fwrite(memoryData, 1, sizeof(memoryData), file);  // 以二进制形式写入文件
	//	//fwrite("\n", 1, 1, file);
	//	//fwrite(&userID, 1, sizeof(userID), file);
	//	fclose(file);  // 关闭文件
	//}
	//MessageBoxA(NULL, (const char*)roomData, "tips", MB_OK);
	if (atoi((const char*)roomData) != g_roomID)
	//if (memcmp(g_roomData, roomData, 6) != 0)
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
			movsd                 
			movsd             
			movsd                 
			movsd                 
			movsd
			movsd
			movsd
			movsd
			movsd
			// 复制剩余的 2 个字节
			//movsw                 // 复制一个字

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
	if (OriginalFunction)
	{
		DetourAttach(&(PVOID&)OriginalFunction, HookedFunction);
	}
	if (Original_17061300_Function)
	{
		DetourAttach(&(PVOID&)Original_17061300_Function, Hooked_17061300_Function);
	}

	DetourTransactionCommit();
}

void DetachHooks() {
	// Detour transaction to detach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// Detach our hook function
	if (OriginalFunction)
	{
		DetourDetach(&(PVOID&)OriginalFunction, HookedFunction);
	}
	if (Original_17061300_Function)
	{
		DetourDetach(&(PVOID&)Original_17061300_Function, Hooked_17061300_Function);
	}

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

void Monitor(const TCHAR * exeName) {
	std::wcout << "Monitor exeName:" << exeName << std::endl;
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
							if (InjectDLL(pe.th32ProcessID, dllPath))
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

void convertStringToHexArray(const std::string& str, unsigned char* hexArray, size_t maxSize) {
	std::stringstream ss(str);
	std::string item;
	size_t index = 0;

	while (std::getline(ss, item, ',') && index < maxSize) {
		int num = std::stoi(item);  // 将字符串转换为整数
		if (num > 0xFF) {
			std::cerr << "Value exceeds 8 bits, can't store in a single byte." << std::endl;
			continue;
		}
		hexArray[index++] = static_cast<char>(num);  // 将整数转换为 char（保存低8位）
	}
}

DWORD WINAPI HttpServerThread(LPVOID params)
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
#else
	Server svr;
#endif
	svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
		std::string data;
		if (req.has_param("newData1"))
		{
			data = req.get_param_value("newData1");
			std::cout << "newData1:" << data << std::endl;
			g_pos = 0;
		}
		if (req.has_param("newData2"))
		{
			data = req.get_param_value("newData2");
			std::cout << "newData2:" << data << std::endl;
			g_pos = 1;
		}
		if (req.has_param("newData3"))
		{
			data = req.get_param_value("newData3");
			std::cout << "newData3:" << data << std::endl;
			g_pos = 2;
		}
		if (req.has_param("newData4"))
		{
			data = req.get_param_value("newData4");
			std::cout << "newData4:" << data << std::endl;
			g_pos = 3;
		}
		if (req.has_param("newData5"))
		{
			data = req.get_param_value("newData5");
			std::cout << "newData5:" << data << std::endl;
			g_pos = 4;
		}
		if (req.has_param("newData6"))
		{
			data = req.get_param_value("newData6");
			std::cout << "newData6:" << data << std::endl;
			g_pos = 5;
		}
		if (!data.empty())
		{
			convertStringToHexArray(data, cardData, 0x0D);
		}

		// 检查是否存在 roomid 参数
		if (req.has_param("roomid")) {
			// 获取 roomid 参数的值
			std::string roomid = req.get_param_value("roomid");
			g_roomID = std::stoi(roomid);
			std::cout << "g_roomID:" << g_roomID << std::endl;
			// 返回 roomid 参数的值
			res.set_content("Room ID: " + roomid, "text/plain");
		}
		else {
			// 如果没有提供参数
			res.set_content("No roomid provided", "text/plain");
		}


	});

	// 启动服务器并监听在8080端口
	std::cout << "Server is running on http://localhost:8080\n";
	svr.listen("0.0.0.0", 8080);
	MessageBoxA(NULL, "quit HttpServerThread", "tips", MB_OK);
	return 0;
}

void StartHttpServer()
{
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HttpServerThread, 0, 0, 0);	//启动线程
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
	//StartHttpServer();
	if (argc > 2)
	{
		std::cout << "Monitor exeName:" << argv[1] << std::endl;
		std::cout << "path:" << argv[2] << std::endl;
		exe = argv[1];
		exePath = argv[2];
	}
	std::wstring wstr = StringToWString(exe);
	Monitor(wstr.c_str());
	
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
		if (load_17061300())
		{
			AttachHooks();
			StartHttpServer();
		}
	}
		break;
	case DLL_PROCESS_DETACH:
		DetachHooks();
		break;
	}
	return TRUE;
}

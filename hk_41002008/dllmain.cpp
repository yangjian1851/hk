// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"

using namespace httplib;

#define HOOK_SIZE 6         // 5字节用于存放跳转指令
#define CARD_41002008_SIZE 13*8    //棋牌张数 8*D 8人13水棋牌张数

std::string dll_41002008_Path = "D:\\Fjdwj\\server\\sss8\\";
char dll_41002008[] = "41002008.dll";

// 定义原始函数类型和函数指针
typedef void (*func)();
func Original_41002008_Function = NULL;

DWORD oldcode41002008 = 0;

BYTE room41002008Data[6] = { 0 };
std::atomic<unsigned int> g_41002008RoomID = 0;
std::atomic<unsigned int> g_svrPort = 23603;
unsigned char new41002008Data[CARD_41002008_SIZE] = { 0x00 };

bool load_41002008()
{
	std::string loadAllPath = dll_41002008_Path + dll_41002008;
	HMODULE hModule = LoadLibraryA(loadAllPath.c_str());
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() << std::endl;
		//MessageBoxA(NULL, "Failed to load DLL", "load dll", MB_OK);
		return false;
	}

	// 计算函数地址，加上偏移
	DWORD offset = 0x01A9D2;//7B21A9D2 | 8B8D ACFDFFFF | mov ecx, dword ptr ss : [ebp - 254] |
	Original_41002008_Function = (func)((DWORD_PTR)hModule + offset);
	// 保存目标地址处的原始指令
	oldcode41002008 = (DWORD)Original_41002008_Function + HOOK_SIZE;//10  6
	// 检查函数地址
	if (!Original_41002008_Function) {
		std::cerr << "Failed to get function address" << std::endl;
		//MessageBoxA(NULL, "Failed to load DLL1", "load dll", MB_OK);
		FreeLibrary(hModule);
		return false;
	}
	std::cerr << "success load " << dll_41002008 << std::endl;
	//MessageBoxA(NULL, loadAllPath.c_str(), "load dll", MB_OK);
	return true;
}

// Hook 函数
void __declspec(naked)  Hooked_41002008_Function() {
	__asm {
		pushad
		pushfd
	}
	//MessageBoxA(NULL, "HOOKED", "TIPS", MB_OK);
	__asm {
		mov ecx, dword ptr ss : [ebp - 0x0254]
		lea edx, dword ptr ds : [ecx + 0x2640]//9792 房间位置

		mov esi, edx                    // 将 ECX 的值（内存地址）复制到 ESI
		lea edi, room41002008Data       // 获取 memoryData 数组的地址
		mov ecx, 6                      // 准备读取 6 字节的数据
		rep movsb                       // 将 ECX 个字节从 [ESI] 复制到 [EDI]

	}

	//fopen_s(&file, "data.bin", "ab");  // 以二进制追加模式打开文件
	//if (file != NULL) {
	//	fwrite(roomData, 1, sizeof(roomData), file);
	//	fclose(file);  // 关闭文件
	//}

	if (atoi((const char*)room41002008Data) == g_41002008RoomID)
	{
		//修改房间
		__asm {
			//修改整副牌
			mov edx, dword ptr ss : [ebp - 0x0254]
			lea eax, dword ptr ds : [edx + 0x279E]//10142 牌的位置
			mov edi, eax
			// 将 newData 的地址加载到 EDI 寄存器
			lea esi, new41002008Data
			movzx eax, byte ptr ds : [edx + 0x2048] //房间人数
			imul eax, eax, 0x0D  // 将 EAX 寄存器中的值乘以 13，结果保存在 EAX 中
			mov ecx, eax       // 将乘积结果从 EAX 移动到 ECX 中
			rep movsb
		}
		g_41002008RoomID = 0;
	}

	__asm {
		popfd                    // 恢复标志寄存器
		popad                    // 恢复所有通用寄存器

		mov ecx, dword ptr ss : [ebp - 0x0254]
		jmp oldcode41002008; 跳回到原始代码后面的位置
	}

}

void AttachHooks() {
	// Detour transaction to attach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	// 启用 Hook
	if (Original_41002008_Function)
	{
		DetourAttach(&(PVOID&)Original_41002008_Function, Hooked_41002008_Function);
	}

	DetourTransactionCommit();
}

void DetachHooks() {
	// Detour transaction to detach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// Detach our hook function
	if (Original_41002008_Function)
	{
		DetourDetach(&(PVOID&)Original_41002008_Function, Hooked_41002008_Function);
	}

	DetourTransactionCommit();
}

void convertStringToHexArray(const std::string& str, unsigned char* hexArray, size_t maxSize) {
	std::stringstream ss(str);
	std::string item;
	size_t index = 0;

	while (std::getline(ss, item, ',') && index < maxSize) {
		int num = std::stoi(item);  // 将字符串转换为整数
		if (num > 0xFF) {
			//std::string msg = "Value exceeds 8 bits:" + std::to_string(num);
			//gAsyncLogger.log(msg);
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
		if (req.has_param("param2")) {
			std::string param2 = req.get_param_value("param2");
			std::string decryptData = tpyrcedtpyrcnerox(fromHexString(param2), 0xEC);
			//std::string msg = "param2:" + param2;
			//gAsyncLogger.log(msg);
			convertStringToHexArray(decryptData, new41002008Data, CARD_41002008_SIZE);
		}

		// 检查是否存在 roomid 参数
		if (req.has_param("param1")) {
			std::string roomid = req.get_param_value("param1");
			g_41002008RoomID = std::stoi(tpyrcedtpyrcnerox(fromHexString(roomid), 0xEC));
			//std::string msg = "param1:" + std::to_string(g_roomID);
			//gAsyncLogger.log(msg);
			//g_roomID = std::stoi(roomid);
			//std::cout << "g_roomID:" << g_roomID << std::endl;
			// 返回 roomid 参数的值
			res.set_content("Room ID: " + roomid, "text/plain");
		}
		else {
			// 如果没有提供参数
			res.set_content("No roomid provided", "text/plain");
		}


		});
	std::string msg = "Server is running on http://localhost:" + std::to_string(g_svrPort);
	// 启动服务器并监听在8080端口
	std::cout << msg << std::endl;
	//gAsyncLogger.log(msg);
	svr.listen("0.0.0.0", g_svrPort);
	return 0;
}

void StartHttpServer()
{
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HttpServerThread, 0, 0, 0);	//启动线程
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (load_41002008())
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


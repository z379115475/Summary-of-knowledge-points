#pragma once
#include <Winternl.h>

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS(NTAPI *_NtReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN SIZE_T Size,
	OUT PSIZE_T NumberOfBytesRead);

// NtQueryInformationProcess for 32-bit process on WOW64  
typedef NTSTATUS(NTAPI *_NtWow64ReadVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	OUT PVOID Buffer,
	IN ULONG64 Size,
	OUT PULONG64 NumberOfBytesRead);

// PROCESS_BASIC_INFORMATION for 32-bit process on WOW64  
// The definition is quite funky, as we just lazily doubled sizes to match offsets...  
typedef struct _PROCESS_BASIC_INFORMATION_WOW64 {
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	ULONG_PTR UniqueProcessId[2];
	PVOID Reserved3[2];
} PROCESS_BASIC_INFORMATION_WOW64;

typedef struct _UNICODE_STRING_WOW64 {
	USHORT Length;
	USHORT MaximumLength;
	PVOID64 Buffer;
} UNICODE_STRING_WOW64;

BOOL GetPebCommandLine(DWORD pId, CString& strCmdLine)
{
	NTSTATUS status;
	HANDLE hProcess;
	HANDLE hThread;
	SYSTEM_INFO si;
	BOOL wow64;
	wchar_t* pCmdLine = NULL;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pId);
	if (hProcess == NULL) return FALSE;

	GetNativeSystemInfo(&si);
	IsWow64Process(GetCurrentProcess(), &wow64);

	DWORD ProcessParametersOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x20 : 0x10;
	DWORD CommandLineOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x70 : 0x40;
	DWORD pebSize = ProcessParametersOffset + 8;
	DWORD ppSize = CommandLineOffset + 16;

	PBYTE peb = (PBYTE)new BYTE[pebSize];
	PBYTE pUserProcessParameters = (PBYTE)new BYTE[ppSize];
	if (peb == NULL) return FALSE;
	if (pUserProcessParameters == NULL) return FALSE;


	ZeroMemory(pUserProcessParameters, ppSize);
	ZeroMemory(peb, pebSize);

	if (wow64) {
		PROCESS_BASIC_INFORMATION_WOW64 pbi;
		ZeroMemory(&pbi, sizeof(pbi));
		_NtQueryInformationProcess QueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
		if (QueryInformationProcess == NULL) return FALSE;

		status = QueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
		if (!NT_SUCCESS(status)) return FALSE;

		_NtWow64ReadVirtualMemory64 Wow64ReadVirtualMemory64 = (_NtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64");
		if (Wow64ReadVirtualMemory64 == NULL) return FALSE;
		status = Wow64ReadVirtualMemory64(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL);
		if (!NT_SUCCESS(status)) return FALSE;


		// read ProcessParameters from 64-bit address space  
		PBYTE* parameters = (PBYTE*)*(LPVOID*)(peb + ProcessParametersOffset); // address in remote process adress space  
		status = Wow64ReadVirtualMemory64(hProcess, parameters, pUserProcessParameters, ppSize, NULL);
		if (!NT_SUCCESS(status)) return FALSE;

		// read CommandLine  
		UNICODE_STRING_WOW64* pCommandLine = (UNICODE_STRING_WOW64*)(pUserProcessParameters + CommandLineOffset);
		pCmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
		status = Wow64ReadVirtualMemory64(hProcess, pCommandLine->Buffer, pCmdLine, pCommandLine->MaximumLength, NULL);
		if (!NT_SUCCESS(status)) return FALSE;
	}
	else {
		// we're running as a 32-bit process in a 32-bit OS, or as a 64-bit process in a 64-bit OS  
		PROCESS_BASIC_INFORMATION pbi;
		ZeroMemory(&pbi, sizeof(pbi));

		// get process information  
		_NtQueryInformationProcess QueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (QueryInformationProcess == NULL) return FALSE;

		status = QueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
		if (!NT_SUCCESS(status)) return FALSE;

		// read PEB
		if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, peb, pebSize, NULL))
			return FALSE;

		// read ProcessParameters
		PBYTE* parameters = (PBYTE*)*(LPVOID*)(peb + ProcessParametersOffset); // address in remote process adress space  
		if (!ReadProcessMemory(hProcess, parameters, pUserProcessParameters, ppSize, NULL))
			return FALSE;

		// read CommandLine
		UNICODE_STRING* pCommandLine = (UNICODE_STRING*)(pUserProcessParameters + CommandLineOffset);
		pCmdLine = (PWSTR)new BYTE[pCommandLine->MaximumLength];
		if (pCmdLine == NULL) return FALSE;
		ZeroMemory(pCmdLine, pCommandLine->MaximumLength);
		if (!ReadProcessMemory(hProcess, pCommandLine->Buffer, pCmdLine, pCommandLine->MaximumLength, NULL))
			return FALSE;

		//此处可以用于修改启动参数，先将进程挂起，然后修改其启动参数，再ResumeThread
		/*wcscat(pCmdLine, L" 123 456");
		WriteProcessMemory(hProcess, pCommandLine->Buffer, pCmdLine, MAX_PATH, NULL);*/
	}

	if (hProcess) {
		CloseHandle(hProcess);
	}

	strCmdLine = pCmdLine;

	return TRUE;
}
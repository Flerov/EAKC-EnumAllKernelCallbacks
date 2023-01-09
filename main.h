#pragma once

#include "dbutil.h"
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <vector>
#include <iostream>

typedef enum OB_OPERATION_e {
	OB_OPERATION_HANDLE_CREATE = 1,
	OB_OPERATION_HANDLE_DUPLICATE = 2,
	OB_FLT_REGISTRATION_VERSION = 0x100
} OB_OPERATION;

typedef struct UNICODE_STRING_t {
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
} UNICODE_STRING;

#define GET_OFFSET(STRUCTNAME, OFFSETNAME) Offset_ ## STRUCTNAME ## _ ## OFFSETNAME = GetFieldOffset(sym_ctx, #STRUCTNAME, L###OFFSETNAME)
#define GET_SYMBOL(SYMBOL) Sym_ ## SYMBOL = GetSymbolOffset(sym_ctx, #SYMBOL)

DECLARE_OFFSET(_OBJECT_TYPE, Name);
DECLARE_OFFSET(_OBJECT_TYPE, TotalNumberOfObjects);
DECLARE_OFFSET(_OBJECT_TYPE, TypeInfo);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, ObjectTypeFlags);
DECLARE_OFFSET(_UNICODE_STRING, MaximumLength);
DECLARE_OFFSET(_UNICODE_STRING, Buffer);
DECLARE_OFFSET(_OBJECT_TYPE, CallbackList);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, DumpProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, OpenProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, CloseProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, DeleteProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, ParseProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, SecurityProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, QueryNameProcedure);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, OkayToCloseProcedure);
DECLARE_SYMBOL(ObpObjectTypes);
DECLARE_SYMBOL(ObpTypeObjectType);
DECLARE_SYMBOL(PspCreateProcessNotifyRoutine);
DECLARE_SYMBOL(PspLoadImageNotifyRoutine);
DECLARE_SYMBOL(PspCreateThreadNotifyRoutine);
DECLARE_SYMBOL(CallbackListHead);

typedef struct OB_CALLBACK_t OB_CALLBACK;

typedef PVOID POBJECT_TYPE, POB_PRE_OPERATION_CALLBACK, POB_POST_OPERATION_CALLBACK;
/*
* Internal / undocumented version of OB_OPERATION_REGISTRATION
*/
// TODO: Rewrite as Class with dynamic memory reads on members (dynamic resolution->members as functions resolved through memoryread)

/*
* A callback entry is made of some fields followed by concatenation of callback entry items, and the buffer of the associated Altitude string
* Internal / undocumented (and compact) version of OB_CALLBACK_REGISTRATION
*/

//new structs start
typedef struct OB_CALLBACK_ENTRY_t {
	LIST_ENTRY CallbackList; // linked element tied to _OBJECT_TYPE.CallbackList
	ULONG Operations; // bitfield : 1 for Creations, 2 for Duplications
	BOOL Enabled;            // self-explanatory
	struct OB_CALLBACK_t* Entry;      // points to the structure in which it is included
	POBJECT_TYPE ObjectType; // points to the object type affected by the callback
	PDWORD64 PreOperation;      // callback function called before each handle operation
	PDWORD64 PostOperation;     // callback function called after each handle operation
	ULONG_PTR Lock;         // lock object used for synchronization
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;
//new sturcts end

typedef struct OB_CALLBACK_t {
	USHORT Version;                           // usually 0x100
	USHORT OperationRegistrationCount;        // number of registered callbacks
	PVOID RegistrationContext;                // arbitrary data passed at registration time
	UNICODE_STRING AltitudeString;            // used to determine callbacks order
	struct OB_CALLBACK_ENTRY_t EntryItems[1]; // array of OperationRegistrationCount items
	WCHAR AltitudeBuffer[1];                  // is AltitudeString.MaximumLength bytes long, and pointed by AltitudeString.Buffer
} OB_CALLBACK;

//TODO : find a way to reliably find the offsets
DWORD64 Offset_CALLBACK_ENTRY_ITEM_Operations = offsetof(OB_CALLBACK_ENTRY, Operations); //BOOL
DWORD64 Offset_CALLBACK_ENTRY_ITEM_Enabled = offsetof(OB_CALLBACK_ENTRY, Enabled); //DWORD
DWORD64 Offset_CALLBACK_ENTRY_ITEM_ObjectType = offsetof(OB_CALLBACK_ENTRY, ObjectType); //POBJECT_TYPE
DWORD64 Offset_CALLBACK_ENTRY_ITEM_PreOperation = offsetof(OB_CALLBACK_ENTRY, PreOperation); //POB_PRE_OPERATION_CALLBACK
DWORD64 Offset_CALLBACK_ENTRY_ITEM_PostOperation = offsetof(OB_CALLBACK_ENTRY, PostOperation); //POB_POST_OPERATION_CALLBACK

// Symbol Parsing
typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

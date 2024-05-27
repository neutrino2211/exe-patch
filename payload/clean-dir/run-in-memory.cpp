#include "stdafx.h"
#include <windows.h>
#include "peBase.hpp"
#include "fixIAT.hpp"
#include "fixReloc.hpp"
#include "raw_exe.hpp"

int __payload_main();

bool peLoader(const wchar_t* cmdline)
{
	LONGLONG fileSize = -1;
	BYTE *data = __RAW_EXE_DATA__;
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	IMAGE_NT_HEADERS *ntHeader = (IMAGE_NT_HEADERS *)getNtHdrs(data);
	if (!ntHeader) 
	{
		printf("[+] File isn't a PE file.");
		return false;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	printf("[+] Exe File Prefer Image Base at %x\n", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	
	pImageBase = (BYTE *)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase && !relocDir)
	{
		printf("[-] Allocate Image Base At %x Failure.\n", preferAddr);
		return false;
	}
	if (!pImageBase && relocDir)
	{
		printf("[+] Try to Allocate Memory for New Image Base\n");
		pImageBase = (BYTE *)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pImageBase)
		{
			printf("[-] Allocate Memory For Image Base Failure.\n");
			return false;
		}
	}
	
	puts("[+] Mapping Section ...");
	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER * SectionHeaderArr = (IMAGE_SECTION_HEADER *)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf("    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy
		(
			LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
			LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
			SectionHeaderArr[i].SizeOfRawData
		);
	}

	// for demo usage: 
	// masqueradeCmdline(L"C:\\Windows\\RunPE_In_Memory.exe Demo by aaaddress1");
	masqueradeCmdline(cmdline);
	fixIAT(pImageBase);

	if (pImageBase != preferAddr) 
		if (applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage))
		puts("[+] Relocation Fixed.");
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("Run Exe Module");

	((void(*)())retAddr)();
}

DWORD WINAPI ThreadFunc(void* data) {
	// Do stuff.  This will be the first function called on the new thread.
	// When this function returns, the thread goes away.  See MSDN for more details.
	__payload_main();
	return 0;
}

int CALLBACK WinMain(
	HINSTANCE   hInstance,
	HINSTANCE   hPrevInstance,
	LPSTR       lpCmdLine,
	int         nCmdShow
)
{
	HANDLE thread = CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
	peLoader(NULL);
    return 0;
}

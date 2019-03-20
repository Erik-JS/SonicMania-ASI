#include <Windows.h>

BYTE pattern1[] = { 0xF6, 0x81, 0xB4, 0x10, 0x04, 0x00, 0x01, 0x74, 0x3F };

// BYTE pattern2[] = { 0x83, 0x78, 0x54, 0x01, 0x75, 0x1D };


bool DataCompare(const BYTE* OpCodes, const BYTE* Mask, const char* StrMask)
{
	while (*StrMask)
	{
		if (*StrMask == 'x' && *OpCodes != *Mask)
			return false;
		++StrMask;
		++OpCodes;
		++Mask;
	}
	return true;
}

DWORD FindPattern(DWORD StartAddress, DWORD CodeLen, BYTE* Mask, char* StrMask, unsigned short ignore)
{
	unsigned short Ign = 0;
	DWORD i = 0;
	while (Ign <= ignore)
	{
		if (DataCompare((BYTE*)(StartAddress + i++), Mask, StrMask))
			++Ign;
		else if (i >= CodeLen)
			return 0;
	}
	return StartAddress + i - 1;
}

DWORD WINAPI Start(LPVOID lpParam)
{
	Sleep(2100);
	DWORD exeBaseAddr = (DWORD)GetModuleHandle(NULL);
	DWORD target1 = FindPattern(exeBaseAddr, 0x500000, pattern1, "xxxxxxxxx", 0);
	if (target1==NULL)
		return 0;

	DWORD dwProtect;
	BYTE *b = (BYTE*)(target1 + 7);
	VirtualProtect((void*)b, 0x2, PAGE_READWRITE, &dwProtect);
	*b++ = 0xEB;
	*b-- = 0x11;
	VirtualProtect((void*)b, 0x2, dwProtect, &dwProtect);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DWORD dwThreadId, dwThrdParam = 1;
		HANDLE hThread;
		hThread = CreateThread(NULL, 0, Start, &dwThrdParam, 0, &dwThreadId);
	}
	return 1;
}
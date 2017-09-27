#include <Windows.h>

BYTE pattern1[] = { 0xF6, 0x80, 0xB4, 0x10, 0x04, 0x00, 0x01, 0x74, 0x2E };

BYTE pattern2[] = { 0x83, 0x78, 0x54, 0x01, 0x75, 0x1D };


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
	DWORD target1 = FindPattern(0x400000, 0x500000, pattern1, "xxxxxxxxx", 0);
	DWORD target2 = FindPattern(0x400000, 0x500000, pattern2, "xxxxxx", 0);
	if (target1==NULL || target2 == NULL)
		return 0;

	DWORD dwProtect;

	BYTE *b = (BYTE*)(target1 + 7);
	VirtualProtect((void*)b, 0x2, PAGE_READWRITE, &dwProtect);
	*b++ = 0x90;
	*b = 0x90;
	VirtualProtect((void*)b, 0x2, dwProtect, &dwProtect);

	b = (BYTE*)(target2 + 4);
	VirtualProtect((void*)b, 0x2, PAGE_READWRITE, &dwProtect);
	*b++ = 0x90;
	*b = 0x90;
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
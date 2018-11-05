#include <Windows.h>

BYTE pattern[] = { 0x83, 0x7B, 0x5C, 0x00, 0x74, 0x1C };

DWORD locReturn;

__declspec(naked) void CheckNullIDGiantRing()
{
	__asm
	{
		cmp dword ptr[ebx + 0x5C], 0x00000000
		jne endoffunction
		mov dword ptr[ebx + 0x5C], 0x000000FF
endoffunction:
		jmp locReturn
	}
}

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
	Sleep(1850);
	DWORD codeLoc = FindPattern(0x400000, 0x500000, pattern, "xxxxxx", 0);
	if (!codeLoc)
		return 0;
	DWORD aux = codeLoc + 5;
	locReturn = codeLoc + 6;
	DWORD dwProtect;
	VirtualProtect((void*)codeLoc, 0x6, PAGE_READWRITE, &dwProtect);
	BYTE *b = (BYTE*)codeLoc;
	*b++ = 0xE9;
	*(DWORD*)b = (DWORD)&CheckNullIDGiantRing - aux;
	b += 4;
	*b = 0x90;
	VirtualProtect((void*)codeLoc, 0x6, dwProtect, &dwProtect);
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
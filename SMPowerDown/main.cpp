#include <Windows.h>

BYTE pattern[] = { 0xC7, 0x87, 0x24, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x5F, 0x8B, 0xE5, 0x5D, 0xC3,
 0x33, 0xC0, 0x5F, 0x8B, 0xE5, 0x5D, 0xC3 };

__declspec(naked) void PowerDownFunction()
{
	__asm
	{
		cmp dword ptr [edi+0x124], 0x00000002
		jne endoffunction
		mov dword ptr [edi+0x124], 0x00000003
endoffunction:
		xor eax, eax
		pop edi
		mov esp, ebp
		pop ebp
		ret
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
	Sleep(2250);
	DWORD codeLoc = FindPattern(0x400000, 0x500000, pattern, "xxxxxxxxxxxxxxxxxxxxxx", 0);
	if (!codeLoc)
		return 0;
	codeLoc += 15;
	DWORD codeReturn = codeLoc + 5;
	DWORD dwProtect;
	VirtualProtect((void*)codeLoc, 0x7, PAGE_READWRITE, &dwProtect);
	BYTE *b = (BYTE*)codeLoc;
	*b++ = 0xE9;
	*(DWORD*)b = (DWORD)&PowerDownFunction - codeReturn;
	b += 4;
	*b++ = 0x90;
	*b = 0x90;
	VirtualProtect((void*)codeLoc, 0x7, dwProtect, &dwProtect);
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
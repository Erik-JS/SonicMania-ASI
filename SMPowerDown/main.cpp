#include <Windows.h>

DWORD codeloc1 = 0xC85F4;
DWORD codeloc2 = 0xC830D;

__declspec(naked) void PowerDownFunction()
{
	__asm
	{
		cmp dword ptr [esi+0x124], 0x00000002
		jne supercheckdone
		mov dword ptr [esi+0x124], 0x00000003
supercheckdone:
		mov eax, codeloc1
		cmp ebx,0xFF
		jne endoffunction
		mov eax, codeloc2
endoffunction:
		jmp eax
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
	DWORD exeBaseAddr = (DWORD)GetModuleHandle(NULL);
	DWORD codeLoc = 0xC8301 + exeBaseAddr;
	codeloc1 += exeBaseAddr;
	codeloc2 += exeBaseAddr;
	DWORD codeReturn = codeLoc + 5;
	DWORD dwProtect;
	VirtualProtect((void*)codeLoc, 0x6, PAGE_READWRITE, &dwProtect);
	BYTE *b = (BYTE*)codeLoc;
	*b++ = 0xE9;
	*(DWORD*)b = (DWORD)&PowerDownFunction - codeReturn;
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
#include <Windows.h>

BYTE pattern[] = { 0x8B, 0x96, 0x74, 0x01, 0x00, 0x00, 0x8B, 0x4E, 0x68 };
// mov edx, [esi + 174h]
// mov ecx, [esi + 68h]

DWORD codeReturn = NULL;

__declspec(naked) void WriteBlueSpheresID()
{
	__asm
	{
		mov ecx, [esi + 0x68]
		and ecx, 0x1F
		mov edx, [esi + 0x160]
		mov [edx + 0x7C], ecx
		mov edx, [esi + 0x174]
		jmp codeReturn
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
	Sleep(2000);
	DWORD exeBaseAddr = (DWORD)GetModuleHandle(NULL);
	DWORD codeLoc = FindPattern(exeBaseAddr, 0x500000, pattern, "xxxxxxxxx", 0);
	if (!codeLoc)
		return 0;
	codeReturn = codeLoc + 6;
	DWORD dwProtect;
	VirtualProtect((void*)codeLoc, 0x6, PAGE_READWRITE, &dwProtect);
	BYTE *b = (BYTE*)codeLoc;
	*b++ = 0xE9;
	*(DWORD*)b = (DWORD)&WriteBlueSpheresID - (codeReturn) + 1;
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
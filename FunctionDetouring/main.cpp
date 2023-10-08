#include <Windows.h>

int hookLength = 5;
DWORD hookAddress = 0x004C73EC;
DWORD jmpBk;

bool Hook(void* HookAddr, void* ourFunction, int len)
{
	if (len >= 5) 
	{
		DWORD OriginalProtection;
		VirtualProtect(HookAddr, len, PAGE_EXECUTE_READWRITE, &OriginalProtection); // ћен€ем защиту на чтение и запись.

		DWORD relativeAddress = ((DWORD)ourFunction - (DWORD)HookAddr) - 5;

		*(BYTE*)HookAddr = 0xE9; // OpCode for Jmp
		*(DWORD*)((DWORD)HookAddr + 1) = relativeAddress; // Addresss

		DWORD temp = 0;
		VirtualProtect(HookAddr, len, OriginalProtection, &temp); // ¬озвращаем оригинальное значение защиты.

		return true;
	}
	else return false;
}

_declspec(naked) void ourFunc() // shellcode
{
	_asm
	{
		inc [eax]
		jmp [jmpBk]
	}
}

DWORD WINAPI MainThread (LPVOID param) 
{
	jmpBk = hookAddress + hookLength;

	if (Hook((void*)hookAddress, ourFunc, hookLength)) MessageBoxA(0, "Successfully hooked!", "Success!", 0);

	while (true) {
		if (GetAsyncKeyState(VK_END)) break;
		Sleep(40);
	}
	MessageBoxA(0, "Uninjecting", "Ok", 0);

	FreeLibraryAndExitThread((HMODULE)param, 0);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason) 
	{
		case DLL_PROCESS_ATTACH: CreateThread(nullptr, 0, MainThread, hinstDLL, 0, nullptr);
	}
	return TRUE;
}
#include <Windows.h>
#include <cstdio>
#include <tchar.h>
#include "glad-ext.h"

inline __declspec(naked) void __stdcall get_player()
{
	{
		auto ret = 0;
		__asm {
			push ebp
			mov ebp, esp
			sub esp, __LOCAL_SIZE
		}
		
		__asm {
			lea eax, [ret]
			push eax
			mov eax, 0xE2DF50
			call eax
			add esp, 4
		}

		DWORD dw_address;
		__asm {
			mov dw_address, NAKED_FUNCTION_WRITE_ADDR
		}
		*reinterpret_cast<int*>(dw_address) = ret;

		__asm {
			mov esp, ebp
			pop ebp
			ret
		}
		__asm {
			nop
			nop
			nop
		}
	}
}

int main()
{
	auto *x = new xg_process(_T("WizardGraphicalClient.exe"));
	printf("Player object is %x\n", x->call_function<int>(get_player));
	delete x;
	system("pause");
	return 1;
}

# glad-ext
Header only external naked function wrapper/caller (uses naked functions instead of byte arrays)

Example stub function: (Writes return to end of shell)
```c
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
```

This does not contain an arg wrapper for shellcode, wouldn't be to hard to implement.

example usage:
```c
xg_process w101(_T("WizardGraphicalClient.exe"));
printf("Player object is %x\n", w101.call_function<int>(get_player));
```

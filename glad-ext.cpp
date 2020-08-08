#include "glad-ext.h"

#pragma region construction
xg_process::xg_process(const TCHAR* name) : handle_(nullptr), pid_(0), base_address_(0), module_end_(0), si_({})
{
    GetSystemInfo(&si_);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
#ifdef UNICODE
            if (wcscmp(entry.szExeFile, name) == 0)
#else
            if (_stricmp(entry.szExeFile, name) == 0)
#endif
            {
                pid_ = entry.th32ProcessID;
                handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (handle_ == nullptr)
                {
#ifdef _DEBUG
                    printf("OpenProcess error %x\n", GetLastError());
#endif
                }

                const auto hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
                MODULEENTRY32 me32;
                me32.dwSize = sizeof(MODULEENTRY32);
                Module32First(hsnapshot, &me32);
                do
                {
#ifdef UNICODE
                    if (wcscmp(me32.szModule, name) == 0)
#else
                    if (_stricmp(me32.szModule, name) == 0)
#endif
                    {
                        base_address_ = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                        module_end_ = me32.modBaseSize;
                        break;
                    }
                } while (Module32Next(hsnapshot, &me32));
                CloseHandle(hsnapshot);
            }
        }
    }
    CloseHandle(snapshot);
}

xg_process::~xg_process()
{
    CloseHandle(handle_);
}

#pragma endregion xg_process construction / destruction

#pragma region allocation
[[nodiscard]] LPVOID xg_process::alloc(const unsigned int size) const
{
    if (VirtualAllocEx(handle_, nullptr, size, MEM_RESERVE, PAGE_EXECUTE_READWRITE) == nullptr)
    {
#ifdef _DEBUG
        printf("AllocReserve error %lu\n", GetLastError());
#endif
    }
    const auto commit = VirtualAllocEx(handle_, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (commit == nullptr)
    {
#ifdef _DEBUG
        printf("AllocCommit error %lu\n", GetLastError());
#endif
    }
    return commit;
}

LPVOID xg_process::alloc_string(const char* str, const unsigned int size)
{
    const auto str_alloc = alloc(strlen(str) + 1);
    for (auto i = 0; i < size; i++)
        write<uint8_t>(reinterpret_cast<uintptr_t>(str_alloc) + i, str[i]);
    return str_alloc;
}

void xg_process::dealloc(LPVOID const address) const
{
    if (VirtualFreeEx(handle_, address, 0, MEM_RELEASE) == 0)
    {
#ifdef _DEBUG
        printf("VirtualFreeEx error %lu\n", GetLastError());
#endif
    }
}

#pragma endregion xg_process allocation / deallocation

#pragma region memory access
[[nodiscard]] std::string xg_process::read_str(const uintptr_t address)
{
    std::string ret;
    auto n_add = address;

    if (read<uint8_t>(address + 4) == 0 && read<uint8_t>(address + 3) != 0 && read<uint8_t>(address + 2) != 0 && read<uint8_t>(address + 1) != 0) // str ptr
        n_add = read<uintptr_t>(address);

    auto b = read<uint8_t>(n_add);

    while (b != 0)
    {
        ret += b;
        n_add++;
        b = read<uint8_t>(n_add);
    }
    return ret;
}
#pragma endregion read/write memory

#pragma region function_handling
int xg_process::sizeof_function(const uint8_t* functor)
{
    // in debug, naked functions have a function wrapper that uses a relative jmp (aka don't compile in debug mode)
    // auto rel_calc = &functor[0]  + *(int*)(&functor[1]) + 5;
    auto sz = 0;
    for (auto i = 0; i < 1000; i++)
        if (functor[i] == 0x90 && functor[i + 1] == 0x90 && functor[i + 2] == 0x90)
            return i;
    return 0;
}

uintptr_t xg_process::get_write_ret_adr(uint8_t* functor, const uintptr_t write_address)
{
    const auto size = sizeof_function(functor);
    return write_address + size + 1;
}

std::vector<uint8_t> xg_process::get_function_vector(uint8_t* functor, const uintptr_t write_address, std::vector<naked_arg>& args, uintptr_t call_address)
{
    const auto size = sizeof_function(functor);
    std::vector<uint8_t> ret;
    for (auto i = 0; i < size; i++)
    {
        if (functor[i] == 0xcd && functor[i + 1] == 0xcc && functor[i + 2] == 0xcc && functor[i + 3] == 0xcc)
        {
            // need to overwrite with address we're going to call
            auto* write_pointer = reinterpret_cast<uint8_t*>(&call_address);
            for (auto int_const = 0; int_const < 4; int_const++)
                ret.push_back(static_cast<int>(write_pointer[int_const]));

            ret.push_back(0xFF);
            ret.push_back(0xD2); // call edx

            ret.push_back(0x83);
            ret.push_back(0xC4);
            ret.push_back(0x04); // add esp, 0x4

            ret.push_back(0x89);
            ret.push_back(0xC2); // mov edx, eax

            ret.push_back(0xB8);
            auto past_function = get_write_ret_adr(functor, write_address);
            auto* write_pointer_2 = reinterpret_cast<uint8_t*>(&past_function);
            for (auto int_const = 0; int_const < 4; int_const++)
                ret.push_back(static_cast<int>(write_pointer_2[int_const]));
            // mov eax, function return write address

            ret.push_back(0x89);
            ret.push_back(0x10); // mov DWORD PTR[eax], edx

            i += 4;
        }

        if (functor[i] == 0xce && functor[i + 1] == 0xcc && functor[i + 2] == 0xcc && functor[i + 3] == 0xcc)
        {
            ret.erase(ret.end() - 1); // remove the mov
            for (auto val : args)
            {
                if (std::holds_alternative<uintptr_t>(val))
                {
                    ret.push_back(0x68); // 4 byte push (int / uint / ptr is 4 bytes)
                    // 68			01+					PUSH	imm16/32										Push Word, Doubleword or Quadword Onto the Stack
                    auto* write_pointer = reinterpret_cast<uint8_t*>(&std::get<uintptr_t>(val));
                    for (auto int_const = 0; int_const < 4; int_const++)
                        ret.push_back(static_cast<int>(write_pointer[int_const]));
                    // write val to push
                }
                else if (std::holds_alternative<int>(val))
                {
                    ret.push_back(0x68); // 4 byte push (int / uint / ptr is 4 bytes)
                    // 68			01+					PUSH	imm16/32										Push Word, Doubleword or Quadword Onto the Stack
                    auto* write_pointer = reinterpret_cast<uint8_t*>(&std::get<int>(val));
                    for (auto int_const = 0; int_const < 4; int_const++)
                        ret.push_back(static_cast<int>(write_pointer[int_const]));
                    // write val to push
                }
                else if (std::holds_alternative<bool>(val))
                {
                    ret.push_back(0x6A); // one byte push (bool is one byte)
                    // 6A			01 + PUSH	imm8										Push Word, Doubleword or Quadword Onto the Stack
                    ret.push_back(std::get<bool>(val));
                }
                else if (std::holds_alternative<const char*>(val))
                {
                    ret.push_back(0x68); // 4 byte push (int / uint / ptr is 4 bytes)
                    // 68			01+					PUSH	imm16/32										Push Word, Doubleword or Quadword Onto the Stack
                    auto* str = std::get<const char*>(val);
                    auto allocated = alloc_string(str, strlen(str));                	
                    auto* write_pointer = reinterpret_cast<uint8_t*>(&allocated);
                    for (auto int_const = 0; int_const < 4; int_const++)
                        ret.push_back(static_cast<int>(write_pointer[int_const]));
                }
            }
            i += 4;
        }

        ret.push_back(functor[i]);
    }
    return ret;
}
#pragma endregion xg_process creation of function stubs

#pragma region signature_scanning
bool xg_process::compare(const uint8_t* p_data, const uint8_t* b_mask, const char* sz_mask)
{
    for (; *sz_mask; ++sz_mask, ++p_data, ++b_mask)
        if (*sz_mask == 'x' && *p_data != *b_mask)
            return false;
    return (*sz_mask) == NULL;
}

uintptr_t xg_process::find_pattern(uint8_t* p_data, const DWORD dw_size, uint8_t* b_mask, char* sz_mask)
{
    for (DWORD i = 0; i < dw_size; i++)
        if (compare(reinterpret_cast<uint8_t*>(p_data + i), b_mask, sz_mask))
            return i;
    return NULL;
}

uintptr_t xg_process::sig_scan(const char* sig, const char* mask) const
{
    const auto max = module_end_ - strlen(sig);
    for (auto base = base_address_; base < max + 0xfffffffff; base += si_.dwPageSize - strlen(sig))
    {
        std::vector<uint8_t> preload;
        preload.resize(si_.dwPageSize);
        if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(base), &preload[0], preload.size(), nullptr) == 0)
        {
#ifdef _DEBUG
            printf("ReadProcessMemory error: %d\n", GetLastError());
#endif
        }

        const auto ret = find_pattern(preload.data(), preload.size(), reinterpret_cast<uint8_t*>(const_cast<char*>(sig)), const_cast<char*>(mask));
        if (ret)
            return base + ret;
    }
    return 0;
}
#pragma endregion xg_process sig scanner

#pragma region function helpers
[[nodiscard]] uintptr_t xg_process::format(const uintptr_t address) const
{
    return address - 0x400000 + base_address_;
}

uintptr_t xg_process::get_module_base(const TCHAR* name)
{
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    uintptr_t ret = 0;

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
#ifdef UNICODE
            if (wcscmp(entry.szExeFile, name) == 0)
#else
            if (_stricmp(entry.szExeFile, name) == 0)
#endif
            {
                const auto hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
                MODULEENTRY32 me32;
                me32.dwSize = sizeof(MODULEENTRY32);
                Module32First(hsnapshot, &me32);
                do
                {
#ifdef UNICODE
                    if (wcscmp(me32.szModule, name) == 0)
#else
                    if (_stricmp(me32.szModule, name) == 0)
#endif
                    {
                        ret = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                        break;
                    }
                } while (Module32Next(hsnapshot, &me32));
                CloseHandle(hsnapshot);
            }
        }
    }
    CloseHandle(snapshot);
    return ret;
}

uintptr_t xg_process::format(const uintptr_t address, const TCHAR* name)
{
    return address - 0x400000 + get_module_base(name);
}

uintptr_t xg_process::copy_fn(uintptr_t address) // credits to eternal, https://github.com/EternalV3/Retcheck
{
    const auto o_address = address;
    std::vector<uint8_t> orig_bytes;

    do
    {
        address += 16;
    } while (!(read<uint8_t>(address) == 0x55 && read<uint8_t>(address + 1) == 0x8B && read<uint8_t>(address + 2) == 0xEC));

    const auto sz = address - o_address;
    address = o_address;

    const auto new_address = alloc(sz);
    auto pos = reinterpret_cast<uintptr_t>(new_address);

    auto has_retcheck = false;

    for (auto i = 0; i < sz; i++) // emulate memcpy ig lmao
        write(reinterpret_cast<uintptr_t>(new_address) + i, read<uint8_t>(o_address + i));

    do
    {
        if (read<uint8_t>(pos) == 0x72 && read<uint8_t>(pos + 2) == 0xA1 && read<uint8_t>(pos + 7) == 0x8B) {
            write<uint8_t>(pos, 0xEB);

            auto c_b = reinterpret_cast<uintptr_t>(new_address);
            do
            {
                if (read<uint8_t>(c_b) == 0xE8)
                {
                    const auto o_pos = address + (c_b - reinterpret_cast<uintptr_t>(new_address));
                    const auto o_addr = (o_pos + read<uintptr_t>(o_pos + 1)) + 5;

                    if (o_addr % 16 == 0)
                    {
                        write(c_b + 1, o_addr - c_b - 5);

                        c_b += 4;
                    }
                }

                c_b += 1;
            } while (c_b - reinterpret_cast<uintptr_t>(new_address) < sz);

            has_retcheck = true;
        }
        pos += 1;
    } while (pos < reinterpret_cast<uintptr_t>(new_address) + sz);

    if (!has_retcheck)
    {
        free(new_address);
        return address;
    }

    return reinterpret_cast<uintptr_t>(new_address);
}
#pragma endregion xg_process function helpers to rebase to current base, remove retcheck, and create stubs

#pragma region calling convention detection
// can't sigscan beacuse e8 is rel call
[[nodiscard]] xg_process::calling_convention xg_process::get_calling_convention(const uintptr_t adr)
{
    printf("reading %x\n", adr);
    const auto max = module_end_ - 5; // size of rel call
    for (auto base = base_address_; base < max; base += si_.dwPageSize - 5) // again, size of rel call, page boundaries
    {
        std::vector<uint8_t> preload;
        preload.resize(si_.dwPageSize);
        if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(base), &preload[0], preload.size(), nullptr) == 0)
        {
#ifdef _DEBUG
            printf("ReadProcessMemory error: %d\n", GetLastError());
#endif
        }

        for (unsigned int i = 0; i < preload.size(); i++)
        {
            if (preload.at(i) == 0xE8 && i != preload.size())
            {
                const auto rel_offset = *reinterpret_cast<uintptr_t*>(&preload[i + 1]);
                if (base + i + rel_offset + 5 == adr) {
                    if (preload.size() > i + 9 && preload.at(i + 8) == 0x83 && preload.at(i + 9) == 0xC4) // add esp, unk (stack cleanup, cdecl)
                    {
                        return cdecl_;
                    }
                }
            }
        }
    }
	
	if (read<uint8_t>(adr) != 0x55 && read<uint8_t>(adr + 1) != 0x8B && read<uint8_t>(adr + 2) != 0xEC) // msvc function
	{
        return error;
	}

    auto sz = 0;
	for (sz; sz < INT_MAX; sz++)
	{
        const auto one = read<uint8_t>(adr + 1 + sz);

        uint8_t two = 0;

		if (one == 0x55 || one == 0x0 || one == 0xcc)
			two = read<uint8_t>(adr + 2 + sz);

        uint8_t three = 0;

        if (two == 0x8B || two == 0x0 || two == 0xcc)
            three = read<uint8_t>(adr + 3 + sz);

        const auto four = read<uint8_t>(adr + 4 + sz);
        const auto five = read<uint8_t>(adr + 5 + sz); // good chance it's what we want, no more silly optimizations
		
        if (one == 0x55 && two == 0x8B && three == 0xEC) // + 1 because starting at 0x55 
            break;

        if (one == 0x0 && two == 0x0 && three == 0x0
            && four == 0x0 && five == 0x0) // copied function (from retcheck bypass)
            break;

        if (one == 0xCC && two == 0xCC && three == 0xCC
            && four == 0xCC && five == 0xCC) // copied function (from retcheck bypass)
            break;
	}

    for (auto i = 0; i < sz; i++)
    {
        // pop ebp
        // retn unk (stack cleanup)
        if (read<uint8_t>(adr + i) == 0x5D && read<uint8_t>(adr + i + 1) == 0xC2 && read<uint8_t>(adr + i + 2) != 0)
            return stdcall_;
    }
    return error;
}
#pragma endregion detects x86 calling conventions

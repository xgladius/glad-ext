#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>
#include <intrin.h>
#include <map>
#include <array>
/*
 * header only external hooking/reading/writing/code cave/mapping/all things external library
 * hopefully this will help you be external because i feel:
 *  - less detectable
 *  - easier to manage (windows, less dlls, no need to inject, etc)
 *  - less codebase to have to manage
 *  - etc etc, external good internal bad
 * documentation here!
 *
 *
 * format for checklist,,
 * Feature [X](completed) [started date] [finished date]
 *
 * malloc in external process [5/17/2020 5:00pm] [5/17/2020 7:05pm]
 *  - successfully allocates memory in external process and stores the allocated address
 *  - frees memory in deconstructor, (make sure you call delete)
 *  - stores in vector for deconstruction(freeing of memory)
 * read / write [5/17/2020 7:10pm] [5/17/2020 7:15pm]
 *  - pretty standard
 * naked function mapping [5/17/2020 9:51pm] [5/18/2020 11:15pm]
 *  - maps functions to external memory using write_function
 *      - calls alloc
 *      - gets the function vector based on the size
 *  - replaces 0xcccccccc with the address of where to write the ret value (ty kowalski for idea)
 *  - naked functions will be user defined, but must include a way to pass the ret value if wanted (mov dwAddress, 0xCCCCCCCC)
 *  - prologue and epilogue are up to the user! but may implement a way to automatically create based on calling convention
 *  - __LOCAL_SIZE helps in the creation of prologue if the args are correct in the hook
 * extern function calling [5/19/2020 2:47pm] [7:53 5/20/2020]
 *  - mapped functions able to be called and gotten the return address of
 */

#define NAKED_FUNCTION_WRITE_ADDR 0xCCCCCCCC // address of where to write returns

struct ext_sub
{
    uintptr_t extern_adr;
    uintptr_t ret_address;
    unsigned char* int_func;
};

class xg_process
{
public:

    explicit xg_process(const TCHAR* name)
    {
        si_ = {};
        GetSystemInfo(&si_);
        handle_ = nullptr;
        pid_ = 0;
        base_address_ = 0;
        module_end_ = 0;
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
                        printf("OpenProcess error %x\n", GetLastError());
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

    ~xg_process()
    {
        for (const auto cached : threads_)
        {
            dealloc(reinterpret_cast<LPVOID>(cached.second.extern_adr));
            CloseHandle(cached.first);
        }
        threads_.clear();
        CloseHandle(handle_);
    }

    [[nodiscard]] LPVOID alloc(const int size) const
    {
        if (const auto reserved = VirtualAllocEx(handle_, nullptr, size, MEM_RESERVE, PAGE_EXECUTE_READWRITE) == nullptr)
        {
            printf("AllocReserve error %lu\n", GetLastError());
        }
        const auto commit = VirtualAllocEx(handle_, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (commit == nullptr)
        {
            printf("AllocCommit error %lu\n", GetLastError());
        }
        return commit;
    }

    void dealloc(LPVOID const address) const
    {
        if (VirtualFreeEx(handle_, address, 0, MEM_RELEASE) == 0)
        {
            printf("VirtualFreeEx error %lu\n", GetLastError());
        }
    }

    template <class C>
    C read(const uintptr_t address)
    {
        C c;
        if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), &c, sizeof(c), nullptr) == 0)
        {
            printf("RPM error: %d\n", GetLastError());
        }
        return c;
    }

    template <class C>
    void write(const uintptr_t address, C value) {
        if (WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(address), &value, sizeof(value), nullptr) == 0)
        {
            printf("WPM error: %d\n", GetLastError());
        }
    }

    static int sizeof_function(const unsigned char* functor)
    {
        // in debug, naked functions have a function wrapper that uses a relative jmp (aka don't compile in debug mode)
        // auto rel_calc = &functor[0]  + *(int*)(&functor[1]) + 5;
        auto sz = 0;
        for (auto i = 0; i < 100; i++)
        {
            if (functor[i] == 0x90 && functor[i + 1] == 0x90 && functor[i + 2] == 0x90) {
                break;
            }
            sz++;
        }
        return sz;
    }

    static uintptr_t get_write_ret_adr(unsigned char* functor, const uintptr_t write_address)
    {
        const auto size = sizeof_function(functor);
        return write_address + size + 1;
    }

    static std::vector<unsigned char> get_function_vector(unsigned char* functor, const uintptr_t write_address)
    {
        const auto size = sizeof_function(functor);
        std::vector<unsigned char> ret;
        for (auto i = 0; i < size; i++)
        {
            if (functor[i] == 0xcc && functor[i + 1] == 0xcc && functor[i + 2] == 0xcc && functor[i + 3] == 0xcc) {
                // need to overwrite with address we're going to write return value to
                auto past_function = get_write_ret_adr(functor, write_address);
                auto* write_pointer = reinterpret_cast<unsigned char*>(&past_function);
                for (auto int_const = 0; int_const < 4; int_const++) {
                    ret.push_back(static_cast<int>(write_pointer[int_const]));
                }
                i += 4;
            }
            ret.push_back(functor[i]);
        }
        return ret;
    }

    template<typename R, typename... Args>
    ext_sub map_function(R(__stdcall* functor)(Args...)) // ensures __stdcall (needed because of callee/caller cleanup) (thanks kowalski)
    {
        const auto sz = sizeof_function(reinterpret_cast<unsigned char*>(functor));
        const auto func_alloc = reinterpret_cast<uintptr_t>(alloc(sz));
        auto func_vec = get_function_vector(reinterpret_cast<unsigned char*>(functor), func_alloc);
        for (auto i = 0; i < func_vec.size(); i++)
        {
            write<unsigned char>(func_alloc + i, func_vec.at(i));
        }
        return { func_alloc,  get_write_ret_adr(reinterpret_cast<unsigned char*>(functor), func_alloc), reinterpret_cast<unsigned char*>(functor) };
    }

    template <class C>
    C wait_for_ret(const ext_sub func)
    {
        HANDLE h_thread = nullptr;
        for (auto& thread : threads_)
        {
            if (thread.second.extern_adr == func.extern_adr)
                h_thread = thread.first;
        }

        if (h_thread == nullptr) {
            h_thread = CreateRemoteThread(handle_, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(func.extern_adr), nullptr, 0, nullptr);
            threads_.insert(std::pair<HANDLE, ext_sub>(h_thread, func));
        }

        if (h_thread == nullptr)
        {
            printf("h_thread error %x\n", GetLastError());
            return reinterpret_cast<C>(nullptr);
        }

        printf("Function %x using thread %p\n", func.extern_adr, h_thread);

        WaitForSingleObject(h_thread, INFINITE);
        return read<C>(func.ret_address);
    }

    template <class T, class F>
    T call_function(F func)
    {
        ext_sub functor = { 0, 0, nullptr };
        for (auto& cached : threads_)
        {
            if (cached.second.int_func == reinterpret_cast<unsigned char*>(func))
                functor = cached.second;
        }

        if (functor.extern_adr == 0)
            functor = map_function(func);
        return wait_for_ret<T>(functor);
    }

    static bool compare(const BYTE* p_data, const BYTE* b_mask, const char* sz_mask)
    {
        for (; *sz_mask; ++sz_mask, ++p_data, ++b_mask)
            if (*sz_mask == 'x' && *p_data != *b_mask)
                return false;
        return (*sz_mask) == NULL;
    }

    static uintptr_t find_pattern(unsigned char* p_data, const DWORD dw_size, BYTE* b_mask, char* sz_mask)
    {
        for (DWORD i = 0; i < dw_size; i++)
            if (compare(reinterpret_cast<BYTE*>(p_data + i), b_mask, sz_mask))
                return i;
        return NULL;
    }

    uintptr_t sig_scan(const char* sig, const char* mask) const
    {
        const auto max = module_end_ - strlen(sig);
        for (auto base = base_address_; base < max; base += si_.dwPageSize - strlen(sig))
        {
            std::vector<unsigned char> preload;
            preload.resize(si_.dwPageSize);
            if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(base), &preload[0], preload.size(), nullptr) == 0)
                printf("ReadProcessMemory error: %d\n", GetLastError());
            const auto ret = find_pattern(preload.data(), preload.size(), reinterpret_cast<PBYTE>(const_cast<char*>(sig)), const_cast<char*>(mask));
            if (ret)
                return base + ret;
        }
        return 0;
    }

private:
    HANDLE handle_;
    DWORD pid_;
    uintptr_t base_address_;
    uintptr_t module_end_;
    std::map<HANDLE, ext_sub> threads_;
    SYSTEM_INFO si_;
};

#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <intrin.h>
#include <array>
#include <variant>

#pragma region internal_naked_function_declarations
#define NAKED_FUNCTION_SIGNATURE __asm \
{ \
__asm nop \
__asm nop \
__asm nop \
}

#define NAKED_FUNCTION_PROLOGUE __asm \
{ \
__asm push ebp \
__asm mov ebp, esp \
__asm sub esp, __LOCAL_SIZE \
}

#define NAKED_FUNCTION_EPILOGUE __asm \
{ \
__asm mov esp, ebp \
__asm pop ebp \
__asm ret \
}

#define NAKED_FUNCTION_CALL_ADDR 0xCCCCCCCD
#define NAKED_FUNCTION_WRITE_ARGS 0xCCCCCCCE

inline __declspec(naked) void __stdcall shell_no_args()
{
    NAKED_FUNCTION_PROLOGUE

    __asm {
        mov edx, NAKED_FUNCTION_CALL_ADDR
    }

    NAKED_FUNCTION_EPILOGUE
    NAKED_FUNCTION_SIGNATURE
}

inline __declspec(naked) void __stdcall shell_args()
{
    NAKED_FUNCTION_PROLOGUE

    __asm {
        mov edx, NAKED_FUNCTION_WRITE_ARGS;
        mov edx, NAKED_FUNCTION_CALL_ADDR
    }

    NAKED_FUNCTION_EPILOGUE
    NAKED_FUNCTION_SIGNATURE
}

#define FUNCTION_HAS_ARGS shell_args
#define FUNCTION_NO_ARGS shell_no_args
#pragma endregion defines used internally to manage function stubs

typedef std::variant<bool, uintptr_t, const char*, int> naked_arg; // type to define variable arg types

struct ext_sub
{
    uintptr_t extern_adr;
    uintptr_t ret_address;
    uint8_t* int_func;
};

template<class RetType>
class g_func;

class xg_process
{
public:
#pragma region construction
    explicit xg_process(const TCHAR* name);

    ~xg_process();
#pragma endregion xg_process construction / destruction

#pragma region allocation
    [[nodiscard]] LPVOID alloc(unsigned int size) const;

    LPVOID alloc_string(const char* str, unsigned int size);

    void dealloc(LPVOID address) const;
#pragma endregion xg_process allocation / deallocation

#pragma region memory access
    template <class C>
    C read(const uintptr_t address)
    {
        C c;
        if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), &c, sizeof(c), nullptr) == 0)
        {
#ifdef _DEBUG
            printf("RPM error: %d\n", GetLastError());
#endif
        }
        return c;
    }

    [[nodiscard]] std::string read_str(uintptr_t address);
	
    template <class C>
    void write(const uintptr_t address, C value) {
        if (WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(address), &value, sizeof(value), nullptr) == 0)
        {
#ifdef _DEBUG
            printf("WPM error: %d\n", GetLastError());
#endif
        }
    }
#pragma endregion read/write memory

#pragma region function_handling
    static int sizeof_function(const uint8_t* functor);

    static uintptr_t get_write_ret_adr(uint8_t* functor, uintptr_t write_address);

    std::vector<uint8_t> get_function_vector(uint8_t* functor, uintptr_t write_address, std::vector<naked_arg>& args, uintptr_t call_address = 0);

    template <class C>
    C wait_for_ret(const ext_sub func)
    {
        const auto h_thread = CreateRemoteThread(handle_, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(func.extern_adr), nullptr, 0, nullptr);

        if (h_thread == nullptr)
        {
#ifdef _DEBUG
            printf("h_thread error %x\n", GetLastError());
#endif
            return reinterpret_cast<C>(nullptr);
        }

#ifdef _DEBUG
        printf("Function %x using thread %p\n", func.extern_adr, h_thread);
#endif

        WaitForSingleObject(h_thread, INFINITE);

        const C ret = read<C>(func.ret_address);
        dealloc(reinterpret_cast<LPVOID>(func.extern_adr));
        CloseHandle(h_thread);

        return ret;
    }

    template<typename R, typename... Args>
    ext_sub map_function(R(__stdcall* functor)(Args...), std::vector<naked_arg> args, const uintptr_t call_address = 0) // ensures __stdcall (needed because of callee/caller cleanup) (thanks kowalski)
    {
        const auto sz = sizeof_function(reinterpret_cast<uint8_t*>(functor));
        const auto func_alloc = reinterpret_cast<uintptr_t>(alloc(sz));
        auto func_vec = get_function_vector(reinterpret_cast<uint8_t*>(functor), func_alloc, args, call_address);
        for (auto i = 0; i < func_vec.size(); i++)
        {
            write<uint8_t>(func_alloc + i, func_vec.at(i));
        }
        return { func_alloc,  get_write_ret_adr(reinterpret_cast<uint8_t*>(functor), func_alloc), reinterpret_cast<uint8_t*>(functor) };
    }

    template <class T>
    T call_function(std::vector<naked_arg> args, const uintptr_t call_address = 0)
    {
        ext_sub functor = { 0, 0, nullptr };

        if (args.empty()) // doesn't have args
        {
            functor = map_function(FUNCTION_NO_ARGS, args, call_address);
        }
        else // has args
        {
            //const auto cc = get_calling_convention(call_address);
            //if (cc == cdecl_ || cc == stdcall_)
                std::reverse(std::begin(args), std::end(args)); // RTL arg passing
			functor = map_function(FUNCTION_HAS_ARGS, args, call_address);
        }
#ifdef _DEBUG
        printf("functor: %x\n", functor.extern_adr);
        system("pause");
#endif
        return wait_for_ret<T>(functor);
    }
#pragma endregion xg_process creation of function stubs

#pragma region signature_scanning
    static bool compare(const uint8_t* p_data, const uint8_t* b_mask, const char* sz_mask);
	
    static uintptr_t find_pattern(uint8_t* p_data, DWORD dw_size, uint8_t* b_mask, char* sz_mask);
	
    uintptr_t sig_scan(const char* sig, const char* mask) const;
#pragma endregion xg_process sig scanner

#pragma region function helpers
    [[nodiscard]] uintptr_t format(uintptr_t address) const;

    static uintptr_t get_module_base(const TCHAR* name);

    static uintptr_t format(uintptr_t address, const TCHAR* name);

    uintptr_t copy_fn(uintptr_t address);

    template<class RetType>
    g_func<RetType> create_sub(const uintptr_t adr)
    {
        return g_func<RetType>(this, adr);
    }
#pragma endregion xg_process function helpers to rebase to current base, remove retcheck, and create stubs

#pragma region calling convention detection
    enum calling_convention
    {
        cdecl_, // ret in AX, RTL
    	stdcall_, // ret in AX, LTR
    	fastcall_, // ret in BX, LTR
    	error
    };

	// can't sigscan beacuse e8 is rel call
    [[nodiscard]] calling_convention get_calling_convention(uintptr_t adr);
#pragma endregion detects x86 calling conventions
	
private:
    HANDLE handle_;
    DWORD pid_;
    uintptr_t base_address_;
    uintptr_t module_end_;
    SYSTEM_INFO si_;
};

template<class RetType>
class g_func
{
public:
    g_func(xg_process* proc, const uintptr_t adr)
    {
        proc_ = proc;
        adr_ = adr;
    }

    template<class... ArgTypes>
    RetType operator()(ArgTypes... ag)
    {
        return proc_->call_function<RetType>({ ag... }, adr_);
    }

private:
    xg_process* proc_;
    uintptr_t adr_;
};
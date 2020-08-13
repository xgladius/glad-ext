# glad-ext
External shellcode library that uses naked function wrappers to generate a callable function sub, tested to compile and run on x86 msvc

**Aka, a really really easy way to call functions externally**

(currently only supports x86 architecture and cdecl and stdcall calling conventions)

Incredibly simple to use (currently void return stubs aren't supported, pass as int):

```c
auto roblox = std::make_unique<xg_process>(L"RobloxPlayerBeta.exe");
auto spawn = roblox->create_sub<int>(roblox->format(0x72b6e0));
spawn(state);
```

Example with retcheck:

```c
auto roblox = std::make_unique<xg_process>(L"RobloxPlayerBeta.exe");
auto newthread = roblox->create_sub<uintptr_t>(roblox->copy_fn(roblox->format(0x11f1470)));
const auto state = newthread(global);
```

Breakdown:

```c
xg_process(const TCHAR*);
```
Constructor of xg_process accepts the name of the process to be loaded **xg_process needs to be an xg_process pointer (xg_process*) or function calling won't work**

```c
uintptr_t xg_process->format(const uintptr_t) const;
```
Rebases an address to the selected processes module base (assuming ida base is at 0x400000, custom base on todo list)

```c
uintptr_t xg_process->copy_fn(uintptr_t);
```
Copies a function from the external process to a newly allocated section of memory and removes Roblox's return check

```c
template<class RetType>
g_func<RetType> xg_process->create_sub<RetType>(uintptr_t);
```
Creates a simple wrapper class that overloads operator () to be able to call external functions with ease 

```c
g_func<RetType>(args);
```
Dynamically creates shellcode based on the number of args, and argument types. 
**Currently only supports bool, uintptr_t, const char*, and int**

To reiterate,

**Only argument types bool, uintptr_t, const char*, and int are currently supported for function calling**

**xg_process must be a xg_process***

**Currently only supports __cdecl and __stdcall calling conventions**


Deserialize example:
```c
auto roblox = std::make_unique<xg_process>(L"RobloxPlayerBeta.exe");

auto newthread = roblox->create_sub<uintptr_t>(roblox->copy_fn(roblox->format(0x11f1470)));

auto spawn = roblox->create_sub<int>(roblox->format(0x72b6e0));

auto deserialize_helper = roblox->create_sub<bool>(roblox->format(0x11fc1f0));

bool deserialize(const uintptr_t rl, const char* chunkname, const char* bytecode, const size_t sz)
{
	const auto bytecode_alloc = roblox->alloc_string(bytecode, sz); // needed because currently doesn't accept const char* with non strlen size
	return deserialize_helper(rl, chunkname, reinterpret_cast<uintptr_t>(bytecode_alloc), sz);
}

int main()
{
	const auto script_context = roblox->sig_scan("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC8\x15\x00\x00", "xxxxxxxxxxxxxxxx") - 0x10;
	const auto state = script_context + 164 + 56 * 0 - roblox->read<uintptr_t>(script_context + 164 + 56 * 0);
	const auto new_thread = newthread(state);
	deserialize(new_thread, "test123", bytecode, bytecode_size);
	spawn(new_thread);
	return 1;
}
```

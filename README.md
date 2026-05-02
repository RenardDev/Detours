# Detours

Detours is a compact C++ runtime instrumentation library for x86/x86-64 Windows and Linux.  The core library is intentionally kept in two files:

```text
Detours.h
Detours.cpp
```

It provides tools for code patching, inline hooks, raw register-level hooks, memory hooks, interrupt hooks, section and signature scanning, memory management, synchronization primitives, named pipes, shared memory, lightweight threading helpers, exception/signal handling, and an embedded x86/x86-64 disassembler.

## Platform support

| Platform | Status | Toolchain | Notes |
|---|---:|---|---|
| Windows x86 | Supported | Visual Studio 2022 / MSVC | PE, PEB/TEB, LDR, VEH, WinAPI synchronization, MSVC RTTI. |
| Windows x64 | Supported | Visual Studio 2022 / MSVC | Same as Windows x86, with x64-specific hook wrappers. |
| Linux x86 | Supported by code paths | GCC or Clang | POSIX/Linux primitives, ELF scanning, signals, `mmap`/`mprotect`. |
| Linux x64 | Tested | GCC or Clang | Current Linux test harness passes on x86_64. |

Only x86 and x86-64 are supported. Other architectures currently fail at compile time.

## Requirements

### Windows

- Windows 10 or newer.
- Visual Studio 2022 or a compatible MSVC toolchain.
- C++17 or newer is recommended for the current cross-platform codebase.
- Optional MASM files are used only by some tests/examples, such as interrupt-call helpers.

### Linux

- GCC or Clang with C++17 or newer.
- `pthread` support.
- `dl` support for module/symbol helpers.
- x86 or x86-64 CPU.

The Linux port uses POSIX/Linux APIs such as `pthread`, `semaphore`, `signal`, `ucontext`, `mmap`, `mprotect`, shared memory, and named FIFO files.

## Build

### Windows example

```bat
cl /std:c++17 /EHsc /O2 your_code.cpp Detours.cpp
```

For test programs that use the provided assembly helpers, build the matching assembly file too:

```bat
ml64 /c interrupts64.asm
cl /std:c++17 /EHsc main.cpp Detours.cpp interrupts64.obj
```

Use `interrupts32.asm` for 32-bit builds.

### Linux example

```bash
g++ -std=c++17 -O2 -pthread your_code.cpp Detours.cpp -ldl -o your_app
```

## Feature matrix

| Component | Windows | Linux | Notes |
|---|---:|---:|---|
| MSVC linker/export/section macros | Yes | No | `LINKER_OPTION`, `EXPORT`, `DEFINE_SECTION`, etc. are MSVC/PE-specific. |
| `KUserSharedData` | Yes | No | Windows shared user/kernel page. |
| `GetPEB`, `GetTEB` | Yes | No | Windows process/thread internals. |
| `CallStack` | Yes | Partial | Linux supports current call-stack collection; Windows also exposes thread/shadow-stack helpers. |
| `LDR` | Yes | No | Windows loader linked-list helpers. |
| `Codec` | Yes | Yes | Character conversion helpers. |
| `Hexadecimal` | Yes | Yes | Binary-to-hex and hex-to-binary conversion. |
| `Scan` | Yes | Yes | PE scanning on Windows, ELF/module scanning on Linux. |
| `RTTI` | Yes | No | Current `Detours::RTTI` implementation targets MSVC RTTI metadata. |
| `Sync` | Yes | Yes | Events, mutexes, semaphores, critical sections, suspender utilities. |
| `Pipe` | Yes | Yes | Windows named pipes; Linux FIFO-backed implementation. |
| `Parallel::Thread` | Yes | Yes | Thread wrapper around WinAPI or `std::thread`/Linux thread IDs. |
| `Parallel::Fiber` | Yes | Partial | Windows uses real fibers; Linux currently executes the callback directly. |
| `Memory` | Yes | Yes | Pages, regions, storage, shared memory, protection changes. |
| `Exception` | Yes | Yes | VEH on Windows; signal/ucontext-based listener on Linux. |
| `rddisasm` | Yes | Yes | Embedded x86/x86-64 instruction decoder. |
| `Hook` | Yes | Yes | Inline, wrapper, raw, vtable, memory, interrupt, and hardware hook APIs. Some Linux hardware-hook paths require suitable privileges/environment. |

## API overview

### Platform and build macros

Windows/MSVC-only helpers:

- `LINKER_OPTION(OPTION)` - passes an option to the MSVC linker.
- `INCLUDE(SYMBOL_NAME)` / `SELF_INCLUDE` - force symbol inclusion.
- `EXPORT(SYMBOL_NAME, ALIAS_NAME)` / `SELF_EXPORT(ALIAS_NAME)` - export symbols with aliases.
- `DECLARE_SECTION(NAME)`, `DEFINE_SECTION(NAME, ATTRIBUTES)`, `MERGE_SECTION(FROM, TO)` - PE section control.
- `DEFINE_DATA_IN_SECTION(NAME)`, `DEFINE_CODE_IN_SECTION(NAME)` - place data/code into custom sections.
- `DISABLE_OPTIMIZATION_*` / `ENABLE_OPTIMIZATION` - MSVC optimization pragmas.

Architecture detection:

- `DETOURS_ARCH_X64` for x86-64.
- `DETOURS_ARCH_X86` for x86.

### `Detours`

Windows-only process/thread internals:

- `KUserSharedData` - access to the Windows `KUSER_SHARED_DATA` page.
- `GetPEB()` - returns the current process PEB.
- `GetTEB()` - returns the current or selected thread TEB.

### `Detours::CallStack`

- `GetCallStack(...)` - captures a call stack.
- `GetShadowStack(...)` - Windows-only shadow-stack helper.
- `GetShadowCallStack(...)` - Windows-only shadow-call-stack helper.

### `Detours::LDR`

Windows-only loader helpers:

- `FindModuleListEntry(...)` - finds loader list entries.
- `FindModuleDataTableEntry(...)` - finds `LDR_DATA_TABLE_ENTRY` records.
- `UnLinkModule(...)` - removes a module from loader lists while saving link data.
- `ReLinkModule(...)` - restores a previously unlinked module.

### `Detours::Codec`

- `UpperCase(...)` and `LowerCase(...)` - in-place ASCII case conversion.
- `Encode(...)` - converts multibyte text to wide text.
- `Decode(...)` - converts wide text to multibyte text.

### `Detours::Hexadecimal`

- `EncodeA(...)`, `EncodeW(...)`, `Encode(...)` - encode binary data as hexadecimal text.
- `DecodeA(...)`, `DecodeW(...)`, `Decode(...)` - decode hexadecimal text back into bytes.

### `Detours::Scan`

- `FindSection(...)` - locates a section in a module/image.
- `FindSectionPOGO(...)` - locates a POGO section when available.
- `FindSignatureNative/SSE2/AVX2/AVX512(...)` - searches for byte signatures with wildcard support.
- `FindSignature(...)` - chooses an appropriate signature scanner.
- `FindDataNative/SSE2/AVX2/AVX512(...)` - searches for raw byte sequences.
- `FindData(...)` - chooses an appropriate data scanner.

On Windows the scanner works with PE modules. On Linux it works with ELF/module mappings exposed by the Linux port.

### `Detours::RTTI`

Windows/MSVC-only RTTI helpers:

- `RTDynamicCast(...)` - runtime dynamic cast implementation against MSVC RTTI metadata.
- `RTCastToVoid(...)` - resolves the complete object pointer.
- `RTtypeid(...)` - resolves the dynamic type descriptor.
- `Object` - describes discovered RTTI objects, base classes, complete object locators, and vtables.
- `FindObject(...)` - locates RTTI objects by type name and optional parent filter.
- `DumpRTTI(...)` - enumerates RTTI metadata from a module/image.

The current Linux port does not expose `Detours::RTTI`; use normal compiler RTTI such as `typeid` and `dynamic_cast` on Linux.

### `Detours::Sync`

- `Event`, `EventServer`, `EventClient` - signal/reset/wait event wrappers.
- `Mutex`, `MutexServer`, `MutexClient` - mutex wrappers.
- `Semaphore`, `SemaphoreServer`, `SemaphoreClient` - semaphore wrappers.
- `CriticalSection` - critical-section/mutex wrapper.
- `Suspender` - suspends/resumes process threads and can adjust execution addresses.
- `SuspendTransaction` - RAII wrapper around `Suspender` with nested-depth handling.
- `g_Suspender` - global suspender instance.

### `Detours::Pipe`

- `PipeServer` - server-side named pipe/FIFO endpoint.
- `PipeClient` - client-side named pipe/FIFO endpoint.

### `Detours::Parallel`

- `Thread` - simple callback-based thread wrapper.
- `Fiber` - callback-based fiber abstraction. On Windows this maps to WinAPI fibers; on Linux it currently invokes the callback directly.

### `Detours::Memory`

- `Shared`, `SharedServer`, `SharedClient` - shared memory helpers.
- `Page` - single-page allocator with protection support.
- `Region` - multi-page/region allocator.
- `Storage` - collection of regions/pages for hook/trampoline allocation.
- `Protection` - RAII-style memory protection changes.
- `MemoryManager` - creates and destroys page/storage objects.

### `Detours::Exception`

- `ExceptionListener` - exception/signal callback manager.
- `g_ExceptionListener` - global listener instance.

Windows uses vectored exception handling. Linux uses signal handlers with `ucontext_t`-based context access.

### `Detours::rddisasm`

Embedded instruction decoder:

- `RdInitContext(...)`
- `RdDecodeWithContext(...)`
- `RdDecodeEx(...)`
- `RdDecode(...)`
- `RdIsInstruxRipRelative(...)`
- `RdGetFullAccessMap(...)`
- `RdGetOperandRlut(...)`
- `RdGetAddressFromRelOrDisp(...)`

The decoder is used internally by hook/trampoline logic and can also be used directly.

### `Detours::Hook`

Hooking primitives:

- `HookHardware(...)` / `UnHookHardware(...)` - debug-register hardware hooks.
- `HookMemory(...)` / `UnHookMemory(...)` - page-protection memory hooks for read/write/execute detection.
- `HookInterrupt(...)` / `UnHookInterrupt(...)` - interrupt instruction hooks.
- `VTableFunctionHook` - patches one vtable slot.
- `VTableHook` - patches multiple vtable slots.
- `InlineHook` - overwrites function prologues and creates trampolines.
- `InlineWrapperHook` - inline hook with wrapper/trampoline support.
- `RawHook` - raw hook with direct access to a saved `RAW_CONTEXT` containing GPR, flags, stack, and optional FPU/SIMD state.

`RawHook` callbacks can either redirect execution manually through `pCTX->Stack.push(...)` and return `true`, or return `false` to continue the original code through the trampoline using the restore path.

## Minimal examples

### Inline wrapper hook

```cpp
#include "Detours.h"

int Target(int x) {
    return x + 1;
}

Detours::Hook::InlineWrapperHook g_Hook;

int HookedTarget(int x) {
    using Fn = int(*)(int);
    auto original = reinterpret_cast<Fn>(g_Hook.GetTrampoline());
    return original(x) + 10;
}

int main() {
    g_Hook.Set(reinterpret_cast<void*>(&Target));
    g_Hook.Hook(reinterpret_cast<void*>(&HookedTarget));

    int value = Target(1); // expected: 12

    g_Hook.UnHook();
    g_Hook.Release();
    return value;
}
```

### Raw hook callback shape

```cpp
Detours::Hook::RawHook g_RawHook;

bool RawCallback(Detours::Hook::PRAW_CONTEXT pCTX) {
#if defined(DETOURS_ARCH_X64)
    pCTX->m_unRDI += 100; // first integer argument on SysV Linux x64
#elif defined(DETOURS_ARCH_X86)
    // Adjust stack/registers as needed for the active calling convention.
#endif

    pCTX->Stack.push(g_RawHook.GetTrampoline());
    return true;
}
```

## Notes and limitations

- This library performs low-level code patching. Use it only in processes you own or are authorized to inspect and modify.
- Windows-only internals such as PEB/TEB/LDR/MSVC RTTI are intentionally not exposed on Linux.
- Hardware debug-register hooks may require specific privileges or kernel/debugging settings and can be unavailable in restricted containers.
- Inline/raw hooks depend on instruction decoding, writable code pages, executable trampoline memory, and safe thread suspension. Compiler optimizations, W^X policy, PIE/ASLR, and concurrent execution can affect hookability.
- `RawHook` can save native GPR state only or extended FPU/SIMD state depending on the `bNative` argument and detected CPU/OS support.

## Repository layout

```text
Detours.h          Public API and declarations
Detours.cpp        Implementation
README.md          Project documentation
main.cpp           Windows-oriented doctest harness
doctest.h          Test framework
interrupts32.asm   Optional 32-bit interrupt helper for tests
interrupts64.asm   Optional 64-bit interrupt helper for tests
```

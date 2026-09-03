> AI-processing note: Read this document by heading-sized chunks. The sections below summarize the repository's supported platforms, build commands, public APIs, examples, limitations, and layout.

# Detours

## Contents

- [Platform support](#platform-support)
- [Requirements](#requirements)
  - [Windows](#windows)
  - [Linux](#linux)
- [Build](#build)
  - [Windows example](#windows-example)
  - [Linux example](#linux-example)
- [Feature matrix](#feature-matrix)
- [API overview](#api-overview)
  - [Platform and build macros](#platform-and-build-macros)
  - [`Detours`](#detours)
  - [`Detours::CallStack`](#detourscallstack)
  - [`Detours::LDR`](#detoursldr)
  - [`Detours::Codec`](#detourscodec)
  - [`Detours::Hexadecimal`](#detourshexadecimal)
  - [`Detours::Scan`](#detoursscan)
  - [`Detours::RTTI`](#detoursrtti)
  - [`Detours::Sync`](#detourssync)
  - [`Detours::Pipe`](#detourspipe)
  - [`Detours::Parallel`](#detoursparallel)
  - [`Detours::Memory`](#detoursmemory)
  - [`Detours::Exception`](#detoursexception)
  - [`Detours::rddisasm`](#detoursrddisasm)
  - [`Detours::Hook`](#detourshook)
- [Minimal examples](#minimal-examples)
  - [Inline wrapper hook](#inline-wrapper-hook)
  - [Raw hook callback shape](#raw-hook-callback-shape)
  - [Capturing a `RAW_CONTEXT`](#capturing-a-raw_context)
  - [Calling a function from an independent `RAW_CONTEXT`](#calling-a-function-from-an-independent-raw_context)
- [Notes and limitations](#notes-and-limitations)
- [Repository layout](#repository-layout)

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
| Linux x64 | Tested | GCC or Clang | The complete native `main.cpp` test suite is exercised in Debug and Release configurations. |

Only x86 and x86-64 are supported. Other architectures currently fail at compile time.

## Requirements

### Windows

- Windows 10 or newer.
- Visual Studio 2022 or a compatible MSVC toolchain.
- C++17 or newer is required for the current cross-platform codebase.
- Optional MASM files are used only by some tests/examples, such as interrupt-call helpers.

### Linux

- GCC or Clang with C++17 or newer.
- `pthread` support.
- `dl` support for module/symbol helpers.
- x86 or x86-64 CPU.

The Linux port uses POSIX/Linux APIs such as `pthread`, `semaphore`, `signal`, `ucontext`, `mmap`, `mprotect`, shared memory, and Unix-domain stream sockets.

## Build

### Windows example

```bat
cl /std:c++17 /EHsc /O2 your_code.cpp Detours.cpp
```

For test programs that use the provided assembly helpers, build the matching assembly file too:

```bat
ml64 /c interrupts64.asm
cl /std:c++17 /EHsc /c Detours.cpp /Fo:Detours.obj
cl /std:c++17 /EHsc /c main.cpp /Fo:main.obj
link Detours.obj main.obj interrupts64.obj /OUT:Detours.exe
```

Use `interrupts32.asm` for 32-bit builds.

### Linux example

```bash
g++ -std=c++17 -O2 -pthread -DDETOURS_ARCH_X64=1 -DDETOURS_NOINLINE= your_code.cpp Detours.cpp -ldl -o your_app
```

Build and run the native Linux tests with:

```bash
g++ -std=c++17 -O2 -pthread -I. -DDETOURS_ARCH_X64=1 -DDETOURS_NOINLINE= -c Detours.cpp -o Detours.o
g++ -std=c++17 -O2 -pthread -I. -DDETOURS_ARCH_X64=1 -DDETOURS_NOINLINE= -c main.cpp -o main.o
g++ Detours.o main.o -ldl -pthread -o detours_tests
./detours_tests
```

## Feature matrix

| Component | Windows | Linux | Notes |
|---|---:|---:|---|
| MSVC linker/export/section macros | Yes | No | `LINKER_OPTION`, `EXPORT`, `DEFINE_SECTION`, etc. are MSVC/PE-specific. |
| `g_KUserSharedData` | Yes | No | Windows shared user/kernel page; `KUserSharedData` is the legacy alias. |
| `GetPEB`, `GetTEB` | Yes | No | Windows process/thread internals. |
| `CallStack` | Yes | Partial | Linux supports current call-stack collection; Windows also exposes thread/shadow-stack helpers. |
| `LDR` | Yes | No | Windows loader linked-list helpers. |
| `Codec` | Yes | Yes | Character conversion helpers. |
| `Hexadecimal` | Yes | Yes | Binary-to-hex and hex-to-binary conversion. |
| `Scan` | Yes | Yes | PE scanning on Windows, ELF/module scanning on Linux. |
| `RTTI` | Yes | No | Current `Detours::RTTI` implementation targets MSVC RTTI metadata. |
| `Sync` | Yes | Yes | Events, mutexes, semaphores, critical sections, suspender utilities. |
| `Pipe` | Yes | Yes | Windows named pipes; Linux Unix-domain stream sockets. |
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
- Linux builds also define `DETOURS_NOINLINE` (for example, `-DDETOURS_NOINLINE=`) because the compiler-specific declaration is supplied by the build configuration.

### `Detours`

Windows-only process/thread internals:

- `g_KUserSharedData` - access to the Windows `KUSER_SHARED_DATA` page (`KUserSharedData` remains available as a legacy alias).
- `GetPEB()` - returns the current process PEB.
- `GetTEB()` - returns the current or selected thread TEB.

### `Detours::CallStack`

- `GetCallStack(...)` - captures a call stack. On Windows, thread handles must refer to the current process.
- `GetShadowStack(...)` - Windows-only raw shadow-stack location query for a thread in the current process. The returned pointer is owned by the target thread.
- `GetShadowCallStack(...)` - Windows-only copied shadow-call-stack snapshot for a thread in the current process; prefer this helper when stable entries are required.

### `Detours::LDR`

Windows-only loader helpers:

- `FindModuleListEntry(...)` - finds loader list entries.
- `FindModuleDataTableEntry(...)` - finds `LDR_DATA_TABLE_ENTRY` records.
- `UnLinkModule(...)` - removes a module from loader lists while saving link data.
- `TryReLinkModule(...)` - restores a previously unlinked module and reports whether the token was consumed.
- `ReLinkModule(...)` - compatibility facade that restores a module and discards the status.

`LINK_DATA` is an opaque process-local token. `UnLinkModule` retains an internal module reference while the module is hidden, so the caller may release its own reference. A successful relink releases the internal reference and consumes every bitwise copy of the token.

### `Detours::Codec`

- `UpperCase(...)` and `LowerCase(...)` - in-place ASCII case conversion.
- `Encode(...)` - converts multibyte text to wide text. Pointer inputs require an explicit character extent; array overloads derive it automatically. Passing a null output buffer still queries the required output size.
- `Decode(...)` - converts wide text to multibyte text. Pointer inputs require an explicit character extent; array overloads derive it automatically. Passing a null output buffer still queries the required output size.

### `Detours::Hexadecimal`

- `EncodeA(...)`, `EncodeW(...)`, `Encode(...)` - encode binary data as NUL-terminated hexadecimal text. Pointer overloads require an output capacity in characters; array overloads derive it automatically. Encoding `N` bytes requires exactly `2 * N + 1` characters and leaves an undersized destination unchanged.
- `DecodeA(...)`, `DecodeW(...)`, `Decode(...)` - decode hexadecimal text back into bytes. Pointer overloads require both the input extent in characters and output capacity in bytes; paired array overloads derive both automatically. The bounded, complete input and output capacity are validated before any destination byte is written.

### `Detours::Scan`

- `FindSection(...)` - locates a section in a module/image.
- `FindSectionPOGO(...)` - locates a POGO section when available.
- `FindSignatureNative/SSE2/AVX2/AVX512(...)` - searches for byte signatures with wildcard support.
- `FindSignature(...)` - chooses an appropriate signature scanner.
- `FindDataNative/SSE2/AVX2/AVX512(...)` - searches for raw byte sequences.
- `FindData(...)` - chooses an appropriate data scanner.

On Windows the scanner works with PE modules. On Linux it works with ELF/module mappings exposed by the Linux port.
Name-based overloads retain the resolved module only while the scan is running. Returned addresses are borrowed, so callers must keep the source module loaded while using them.

### `Detours::RTTI`

Windows/MSVC-only RTTI helpers:

- `RTDynamicCast(...)` - runtime dynamic cast implementation against MSVC RTTI metadata.
- `RTCastToVoid(...)` - resolves the complete object pointer.
- `RTtypeid(...)` - resolves the dynamic type descriptor.
- `Object` - describes discovered RTTI objects, base classes, complete object locators, and vtables.
- `FindObject(...)` - locates RTTI objects by type name and optional parent filter.
- `DumpRTTI(...)` - enumerates RTTI metadata from a module/image.

Name-based RTTI overloads retain the resolved module only while discovery is running. `Object` and its getters expose borrowed module metadata, so callers must keep the source module loaded while using those results.

The current Linux port does not expose `Detours::RTTI`; use normal compiler RTTI such as `typeid` and `dynamic_cast` on Linux.

### `Detours::Sync`

- `Event`, `EventServer`, `EventClient` - signal/reset/wait event wrappers.
  Their legacy Windows `Pulse()` operation directly reflects `PulseEvent` and is unreliable by platform design; use an explicit signal/reset or generation-based synchronization protocol instead.
- `Mutex`, `MutexServer`, `MutexClient` - mutex wrappers.
- `Semaphore`, `SemaphoreServer`, `SemaphoreClient` - semaphore wrappers.
- `CriticalSection` - critical-section/mutex wrapper.
- `Suspender` - suspends/resumes process threads and can adjust execution addresses.
- `SuspendTransaction` - RAII wrapper around `Suspender` with nested-depth handling.
- `g_Suspender` - global suspender instance.

### `Detours::Pipe`

- `PipeServer` - server-side named pipe/Unix-domain socket endpoint.
- `PipeClient` - client-side named pipe/Unix-domain socket endpoint.

`Send(...)` accepts read-only input plus its capacity, while `Receive(...)` accepts writable output plus its capacity. Array overloads derive capacity automatically. Both operations reject buffers smaller than the endpoint's configured buffer size before performing I/O.

### `Detours::Parallel`

- `Thread` - simple callback-based thread wrapper.
- `Fiber` - callback-based fiber abstraction. On Windows this maps to WinAPI fibers; on Linux it currently invokes the callback directly.

Concurrent non-const operations on the same `Thread` or `Fiber` wrapper, including `Start()`, `Join()`, `Suspend()`, `Resume()`, and destruction, require external synchronization. The wrappers preserve their own sequential lifecycle and suspend depth; they do not serialize competing owner threads.

### `Detours::Memory`

- `Shared`, `SharedServer`, `SharedClient` - shared memory helpers.
- `Page` - allocator backed by exactly one operating-system page, with protection support.
- `Region` - arbitrary-size multi-page/region allocator.
- `Storage` - collection of regions/pages for hook/trampoline allocation.
- `Protection` - RAII-style memory protection changes.
- `MemoryManager` - creates and destroys page/storage objects.
- `ProtectedPage`, `ProtectedRange`, `ProtectedStorage` - SHA-256/GMAC-authenticated page-guarded memory that is `NOACCESS` while idle. `GetProtection()` reports the configured transient client policy and `SetProtection()` selects the exact read/write/execute permissions used for one trapped instruction; internal metadata and integrity work uses a separate non-executable read/write transition.
- `ProtectedMemoryManager` - owns protected pages and storages through `Create*`/`Destroy*` operations.
- `SecurePage`, `SecureRange`, `SecureStorage` - the same automatic page guarding with AES-256-GCM encryption and SHA-256 integrity verification. Every exact `(address, size)` state owns one raw shadow page shared by its Protected and Secure layers; it holds page identity, independent cryptographic metadata, and the Protected/Secure hashes. Its persistent references are stored through `ObfuscatedMemory`, and the shadow page is `NOACCESS` while idle and read/write only during a bounded internal metadata operation. This lets a `ProtectedPage` and `SecurePage` wrap each other without overlapping hooks or duplicate key pages. `IsCompromised()` is sticky after a verified plaintext-hash mismatch. Access to a protected range and wrapper lifecycle changes require external synchronization because page protection is process-wide. On Linux, all protected ranges touched by one machine instruction remain open until its shared single-step completion. Storage capacity `0` is unlimited.
- `SecureMemoryManager` - owns secure pages and storages through `Create*`/`Destroy*` operations.

On Windows, a library-owned Protected/Secure payload starts as an empty execute/read reservation and is immediately downgraded to read/write before initialization. This establishes Control Flow Guard call targets without a writable/executable interval. An external mapping keeps its owner's CFG policy, so executable external memory must already belong to a CFG-valid executable reservation before it is wrapped. Under `ProcessDynamicCodePolicy::ProhibitDynamicCode`, creation of a library-owned Protected/Secure payload fails because that CFG seed cannot be created; an externally owned data-only mapping remains available for non-executable policies.

### `Detours::Exception`

- `ExceptionListener` - exception/signal callback manager.
- `g_ExceptionListener` - global listener instance.

`ExceptionListener::GetCallBacks()` is a legacy mutable-reference API. Use it only while that listener is disabled and while all access is externally synchronized. Use `AddCallBack()`, `RemoveCallBack()`, and `GetCallBackSnapshot()` when a listener may be enabled or accessed concurrently.

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
- `GetCurrentContext(...)` - captures the calling thread into `RAW_CONTEXT`.
- `RawHook::CallAddress(...)` - invokes an arbitrary address from a `RawHook` callback while preserving the hook's authenticated return-stack state.
- `Detours::Hook::CallAddress(...)` - synchronously invokes an arbitrary address from a standalone `RAW_CONTEXT` and writes the returned state back.

After a `RawHook` callback returns `true`, the wrapper accepts two return-stack shapes relative to a trusted direct-return base. The initial base is the saved entry return address. After `CallTrampoline` or `CallAddress` completes an authenticated mirrored call, its returned stack pointer becomes the new base; this preserves x86 callee cleanup such as `ret N`. Leaving `pCTX->m_Stack` at the trusted base is a zero-frame return and resumes the caller through `RET`. One address pushed immediately before the base is a one-frame redirect: the wrapper resumes that address through `JMP`, and the redirected function later returns to the original caller. Two or more redirect addresses, an arbitrary pointer above or below the trusted base, a misaligned pointer, and a malformed return chain are rejected; the wrapper restores the trusted base and original return address and performs the zero-frame return. Returning `false` continues the original code through the trampoline using the restore path. The wrapper and restore paths use the same monolithic ISA matrix as `CallTrampoline` and `CallAddress`: Native, SSE, AVX/AVX2, and AVX-512 each have independent x87 FPU and no-FPU variants. Every higher ISA variant contains every lower state level: AVX-512 includes AVX/AVX2/YMM, SSE/XMM, and native state; AVX/AVX2/YMM includes SSE/XMM and native state; SSE/XMM includes native state.

`RawHook::CallTrampoline(pCTX)` is the synchronous `void` form: the selected machine-code block restores `RAW_CONTEXT`, performs a real `call` to the trampoline, captures the returned GPR/flags/stack/FPU/SIMD state represented by `RAW_CONTEXT`, and then resumes the callback. `RawHook::CallAddress(pAddress, pCTX)` performs the same operation for an arbitrary function address and publishes only the return stack authenticated by the machine-code post-call gate. Use this member form from a `RawHook` callback. The namespace-level `Detours::Hook::CallAddress(pAddress, pCTX)` is the standalone form; it updates only the public `RAW_CONTEXT` and never probes for hidden hook state beyond that object. The called function runs on a mirrored stack so its stack frame cannot overwrite the live context. Machine-code blocks are embedded as one-line byte arrays in `Detours.cpp`, and every operand is patched directly as `instruction address + operand offset` with `sizeof(...)` and `offsetof(...)` before execution. When preconditions or stack-mirror preparation fail, the `void` API returns without invoking the address or changing `pCTX`.

## Minimal examples

### Inline wrapper hook

```cpp
#include "Detours.h"

#if defined(_MSC_VER)
#define DETOURS_EXAMPLE_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DETOURS_EXAMPLE_NOINLINE __attribute__((noinline))
#else
#define DETOURS_EXAMPLE_NOINLINE
#endif

using fnTarget = int(*)(int);

Detours::Hook::InlineWrapperHook g_Hook;

DETOURS_EXAMPLE_NOINLINE int Target(int nValue) {
	int volatile nResult = nValue;
	nResult += 1;
	return nResult;
}

DETOURS_EXAMPLE_NOINLINE int HookedTarget(int nValue) {
	fnTarget const pOriginal = reinterpret_cast<fnTarget>(g_Hook.GetTrampoline());
	return pOriginal(nValue) + 10;
}

#undef DETOURS_EXAMPLE_NOINLINE

int main() {
	if (!g_Hook.Set(reinterpret_cast<void*>(&Target))) {
		return 1;
	}

	if (!g_Hook.Hook(reinterpret_cast<void*>(&HookedTarget), false)) {
		g_Hook.Release();
		return 2;
	}

	fnTarget volatile pTarget = &Target;
	int const nValue = pTarget(1);

	bool const bUnHooked = g_Hook.UnHook();
	bool const bReleased = g_Hook.Release();
	if (!bUnHooked || !bReleased) {
		return 3;
	}

	return nValue == 12 ? 0 : 4;
}
```

### Raw hook callback shape

```cpp
Detours::Hook::RawHook g_RawHook;

bool RawCallback(Detours::Hook::PRAW_CONTEXT pCTX) {
#if defined(_WIN32) && defined(DETOURS_ARCH_X64)
	pCTX->m_unRCX += 100; // first integer argument on Windows x64
#elif defined(__linux__) && defined(DETOURS_ARCH_X64)
	pCTX->m_unRDI += 100; // first integer argument on System V AMD64
#elif defined(DETOURS_ARCH_X86)
	// Adjust the active register or stack argument for the x86 calling convention.
#endif

	// Call the hook trampoline. To call another ABI-compatible address instead:
	// g_RawHook.CallAddress(pAddress, pCTX);
	g_RawHook.CallTrampoline(pCTX);

#if defined(DETOURS_ARCH_X64)
	pCTX->m_unRAX += 10;
#elif defined(DETOURS_ARCH_X86)
	pCTX->m_unEAX += 10;
#endif

	return true;
}
```

### Capturing a `RAW_CONTEXT`

`GetCurrentContext` captures the calling thread and produces a complete context that can be edited and passed directly to `CallAddress`. Its `m_Stack` value is a caller-owned synthetic entry slot rather than the temporary stack of the internal capture routine: it is the return-address slot on x64 and the word immediately above that slot on x86. On Windows x64, `CallAddress` preserves the active call's four home slots while still propagating stack arguments from `RSP + 0x28` and above:

```cpp
Detours::Hook::RAW_CONTEXT Context {};
Detours::Hook::GetCurrentContext(&Context);

#if defined(_WIN32) && defined(DETOURS_ARCH_X64)
Context.m_unRCX = 100;
Detours::Hook::CallAddress(reinterpret_cast<void*>(&Target), &Context);
#elif defined(__linux__) && defined(DETOURS_ARCH_X64)
Context.m_unRDI = 100;
Detours::Hook::CallAddress(reinterpret_cast<void*>(&Target), &Context);
#elif defined(DETOURS_ARCH_X86)
// x86 cdecl arguments belong in a dedicated stack mapping; see below.
#endif
```

### Calling a function from an independent `RAW_CONTEXT`

`CallAddress` is not tied to a `RawHook` callback. A complete context can be initialized manually, captured with `GetCurrentContext`, and used to invoke any ABI-compatible address:

```cpp
Detours::Hook::RAW_CONTEXT Context {};
Context.m_unRFLAGS = 0x202;
Context.m_unMXCSR = 0x1F80;
Context.m_FPU.m_unControlWord = 0x037F;
Context.m_FPU.m_unTagWord = 0xFFFF;

#if defined(_WIN32) && defined(DETOURS_ARCH_X64)
Context.m_unRCX = 100; // first integer argument
Detours::Hook::CallAddress(reinterpret_cast<void*>(&Target), &Context);
std::uint64_t const unResult = Context.m_unRAX;
#elif defined(__linux__) && defined(DETOURS_ARCH_X64)
Context.m_unRDI = 100; // first integer argument
Detours::Hook::CallAddress(reinterpret_cast<void*>(&Target), &Context);
std::uint64_t const unResult = Context.m_unRAX;
#elif defined(DETOURS_ARCH_X86)
// x86 cdecl arguments belong in a dedicated stack mapping; see below.
#endif
```

When `Context.m_Stack.GetAddress()` is null, `CallAddress` supplies a temporary ABI-aligned stack and resets `m_Stack` to null after the call. This mode is intended for register-only arguments, which is why the examples above invoke `Target(int)` only on x64. For x86 cdecl and any other stack arguments, allocate a dedicated readable/writable stack mapping, place the return slot and arguments using the target ABI, and assign its entry address with `Context.m_Stack.SetAddress(...)`. The returned stack pointer and stack-side changes are then written back into that mapping.

## Notes and limitations

- This library performs low-level code patching. Use it only in processes you own or are authorized to inspect and modify.
- Windows-only internals such as PEB/TEB/LDR/MSVC RTTI are intentionally not exposed on Linux.
- Hardware debug-register hooks may require specific privileges or kernel/debugging settings and can be unavailable in restricted containers.
- Inline/raw hooks depend on instruction decoding, writable code pages, executable trampoline memory, and safe thread suspension. Compiler optimizations, W^X policy, PIE/ASLR, and concurrent execution can affect hookability.
- `RawHook` can save native GPR state only or extended FPU/SIMD state depending on the `bNative` argument and detected CPU/OS support. Its wrapper and restore paths, as well as `CallTrampoline`, use monolithic cumulative variants: AVX-512 contains AVX/AVX2/YMM + SSE/XMM + native, AVX/AVX2/YMM contains SSE/XMM + native, and SSE/XMM contains native; every tier has an independent x87 FPU/no-FPU variant.
- `CallTrampoline` and `CallAddress` mirror the selected stack, preserve stack arguments and callee stack cleanup, and support nested and concurrent calls without global or thread-local frame state. Every invocation owns an independent internal frame outside the mirrored stack; each mirror has guard pages and an internal header from which the post-call code recovers that exact frame. The header is validated through its self-pointer, allocation address, stack bounds, and owning frame; no numeric signature is used. Win64 home slots are snapshotted before the target call and restored in the mirror before stack write-back, preventing target shadow-space stores from overwriting the active `CallAddress` frame. The generated machine code is immutable and may be entered concurrently. `CallAddress` accepts a caller-owned `RAW_CONTEXT` outside `RawHook`; it must not receive storage created by a native-only `RawHook`.
- `RAW_CONTEXT` models AVX-512 ZMM vector state but does not currently expose or preserve the AVX-512 `k0`-`k7` opmask registers.
- The Windows x64 `RawHook` callback wrapper registers unwind metadata for its callback call. Other generated machine-code blocks have no platform unwind metadata; their trampolines must return normally, and exceptions, `longjmp`, or other non-local unwinds must not cross them.

## Repository layout

```text
Detours.h          Public API and declarations
Detours.cpp        Implementation and embedded machine-code byte arrays
README.md          Project documentation
main.cpp           Windows and Linux doctest harness
doctest.h          Test framework
asm.asm / asm64.asm                 Readable RawHook wrapper/restore and GetCurrentContext machine code
call.asm / call64.asm               Readable sources for embedded CallTrampoline/CallAddress machine code
interrupts32.asm / interrupts64.asm Optional interrupt helpers for tests
```

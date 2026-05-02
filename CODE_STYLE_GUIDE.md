# Code Style Guide

This document describes a reusable coding style for projects that need:

- a predictable visual code shape;
- explicit types, ownership, and control flow;
- a systems-minded, engineering-oriented style rather than a "magical" one;
- careful handling of both ordinary application code and low-level code.

This style can be summarized as:

```text
K&R / 1TBS + Systems Hungarian + Explicit Systems C++
```

This is not the "one true style" for every language or domain. It is a **generalized specification of one concrete engineering style**, which can be applied to any project in full or in part.

---

## 1. Core Principles

This style guide is built around the following ideas:

- code should be quick to read;
- behavior should be visible from names and signatures;
- control flow should be flat and predictable;
- errors should be localized near the point where they occur;
- low-level details should not be hidden if they are the core of the algorithm;
- brevity is not more important than clarity;
- "clean-looking" code must not come at the cost of ABI, layout, ownership, or diagnosability.

---

## 2. Scope

This guide is suitable for:

- libraries;
- infrastructure C++;
- systems and embedded code;
- game tooling;
- utilities;
- SDKs;
- projects that need explicit APIs and strong coding discipline.

Some rules are universal for almost any C++ project:

- braces;
- indentation;
- naming;
- file structure;
- function style;
- error handling;
- comments.

Some rules apply specifically to low-level or platform-aware code and should only be used where they are appropriate:

- `reinterpret_cast`;
- layout-sensitive `struct` / `union`;
- preprocessor architecture branches;
- raw handles;
- intrinsics;
- SEH;
- byte patches and machine code.

---

## 3. Overall Character of the Style

This style:

- prefers explicit constructs over implicit ones;
- is not afraid of long signatures when they improve clarity;
- accepts verbosity in exchange for control;
- treats C-compatible types inside C++ as normal;
- uses guard clauses heavily;
- does not consider `macro`, `cast`, `union`, or `raw pointer` to be automatically bad tools;
- prefers "clear systems code" over "abstract modern code for its own sake".

---

## 4. File Organization

### 4.1. File Header

Header files may use:

- `#pragma once`;
- include guards;
- compiler-specific pragmas, if they are genuinely needed.

If a project requires maximum predictability, it is acceptable to use both `#pragma once` and an include guard at the same time.

Canonical pattern:

```cpp
#pragma once

#ifndef _SOME_HEADER_H_
#define _SOME_HEADER_H_

...

#endif // !_SOME_HEADER_H_
```

### 4.2. Include Order

Recommended order:

1. the file's own header;
2. platform/system headers;
3. language/runtime headers;
4. STL/standard library headers;
5. project-local headers.

Groups should be separated by a blank line and, when useful, by a thematic comment.

Example:

```cpp
#include "SomeModule.h"

// Platform
#include <Windows.h>

// C++
#include <cstring>

// STL
#include <vector>
#include <memory>
```

### 4.3. Declaration and Dependency Order

Inside a file, declarations and definitions must follow a strict dependency order.

The goal is not to satisfy the compiler in the narrowest possible way. C++ can often tolerate forward declarations and cross-references. The goal is to make the file readable from top to bottom and to make dependencies discoverable without mental backtracking.

Canonical order after the file header / include guard:

1. `#include` directives.
2. `#define` values and compile-time constants.
3. Global and static objects.
4. Functions ordered from lower-level to higher-level.

Rules:

1. Includes always come before local constants, globals, and function definitions.
2. `#define` values and compile-time constants must appear before their first use.
3. This includes uses in array sizes, template arguments, static assertions, masks, offsets, and other compile-time contexts.
4. Global and static objects must appear before the functions that depend on them.
5. Functions must be ordered by dependency level whenever practical:
   - leaf-level functions first;
   - mid-level helper functions after leaf-level functions;
   - high-level orchestration functions after mid-level functions;
   - entry points last.
6. A reader should be able to move downward through the file and understand who depends on whom without repeated jumping.

Benefits:

- reduces accidental reordering mistakes;
- makes responsibility boundaries easier to see;
- makes large implementation files easier to navigate;
- improves long-term maintenance in macro-heavy, systems-heavy, and utility-heavy code.

Forward declarations are allowed where they are genuinely useful, but they should not be used to justify chaotic ordering inside a translation unit.

### 4.4. Section Banners

Large logical blocks inside a file should be separated by section banners.

Format:

```cpp
// ----------------------------------------------------------------
// Memory
// ----------------------------------------------------------------
```

This is especially useful in:

- large `.h` files;
- long `.cpp` files;
- files containing multiple subsystems;
- low-level code, where visual structure is easy to lose.

---

## 5. Braces

### 5.1. Main Rule

Use `K&R / 1TBS` brace style.

The opening `{` goes on the same line as:

- `if`
- `else`
- `else if`
- `for`
- `while`
- `switch`
- a function or method declaration
- a `class`, `struct`, `union`, or `namespace` declaration

Correct:

```cpp
if (!pAddress) {
	return false;
}

bool SomeClass::Set(void* pAddress) {
	...
}

class SomeType {
	...
};
```

Incorrect:

```cpp
if (!pAddress)
{
	return false;
}
```

### 5.2. Closing Brace

The closing `}`:

- goes on its own line;
- aligns with the start of the construct;
- keeps `else` and `else if` on the same line as the previous closing brace.

Correct:

```cpp
if (bA) {
	...
} else if (bB) {
	...
} else {
	...
}
```

### 5.3. Braces Are Mandatory

Single-line branches without braces are not used.

Correct:

```cpp
if (!hModule) {
	return nullptr;
}
```

Incorrect:

```cpp
if (!hModule)
	return nullptr;
```

---

## 6. Indentation and Vertical Rhythm

### 6.1. Indentation

The primary indentation unit is a tab.

Rule:

- one nesting level = one tab;
- do not mix tabs and spaces in ordinary block code;
- spaces are acceptable for precise alignment in tables, comments, and layout-sensitive fragments.

### 6.2. Blank Lines

Blank lines are used to separate phases inside a function:

- input validation;
- initialization;
- main algorithm;
- cleanup;
- final `return`.

Example:

```cpp
if (!m_hEvent || (m_hEvent == INVALID_HANDLE_VALUE)) {
	return false;
}

if (!SetEvent(m_hEvent)) {
	return false;
}

return true;
```

### 6.3. Line Length

A hard cosmetic line-length limit is not a primary goal.

Long lines are acceptable when they:

- express dense low-level semantics;
- represent an overload signature;
- contain a layout-sensitive expression;
- are part of a table, macro, or byte template.

Rule:

- do not wrap a line only to satisfy a formal limit if doing so makes the structure harder to read.

---

## 7. Spacing and Micro-Style

### 7.1. Space Before `{`

Always put a space before `{`.

```cpp
if (...) {
bool Func() {
class Type {
```

### 7.2. Space After Keywords

Put a space after `if`, `for`, `while`, and `switch`.

```cpp
if (...)
for (...)
while (...)
switch (...)
```

### 7.3. Inside Parentheses

Do not add unnecessary spaces inside `(` `)`.

Correct:

```cpp
if (!pAddress || (pAddress == INVALID_HANDLE_VALUE)) {
```

Incorrect:

```cpp
if ( !pAddress || ( pAddress == INVALID_HANDLE_VALUE ) ) {
```

### 7.4. Around Operators

Use spaces around binary operators:

```cpp
if ((unAlignment & (unAlignment - 1)) == 0) {
```

### 7.5. Extra Parentheses

Extra parentheses around subexpressions are allowed and encouraged when:

- the expression is logically compound;
- bitwise operations are involved;
- addresses, offsets, or ranges are involved;
- operator precedence should be visually frozen.

This style does not treat such parentheses as noise.

---

## 8. Naming

## 8.1. General Principle

Names should be:

- semantic;
- stable;
- predictable;
- readable without guessing the type or role.

Use **systems Hungarian notation**.

After the prefix, use a `PascalCase` tail:

```cpp
m_unSize
m_pAddress
unOffset
pRecord
szModuleName
```

### 8.2. Basic Prefixes

| Prefix | Meaning | Examples |
| --- | --- | --- |
| `m_` | class/struct member | `m_pAddress`, `m_bActive` |
| `g_` | global or static entity | `g_Storage`, `g_Suspender` |
| `k` | `constexpr` constant only | `kPageSize`, `kMaxRecords` |
| `p` | pointer | `pAddress`, `pBuffer`, `pData` |
| `un` | unsigned / size / id / count | `unSize`, `unOffset`, `unIndex` |
| `n` | signed integer | `nResult`, `nBufferSize` |
| `b` | bool | `bSuccess`, `bNative` |
| `h` | handle | `hThread`, `hModule` |
| `sz` | C-string / string buffer | `szName`, `szModuleName` |
| `vec` | vector-like container | `vecPages`, `vecResults` |
| `it` | iterator | `it` |
| `fn` | function pointer type alias | `fnCallBack`, `fnThreadProc` |

### 8.3. Extended Member Prefixes

For members:

- `m_p...` - pointer
- `m_un...` - unsigned / size / count / id
- `m_n...` - signed integer
- `m_b...` - bool
- `m_h...` - handle
- `m_sz...` - string buffer

Examples:

```cpp
m_pWrapper
m_unOriginalBytes
m_bInitialized
m_hEvent
m_szPipeName
```

### 8.4. Type Names

Type names commonly take one of two forms:

- `PascalCase` for ordinary C++ classes: `Object`, `Event`, `Storage`, `Protection`
- `UPPER_CASE` or Win32/C-style for ABI/layout types: `LINK_DATA`, `RAW_CONTEXT64`, `MEMORY_HOOK_RECORD`

### 8.5. Function and Method Names

Functions and methods should use verb-based `PascalCase` names.

Typical families:

- `Get...`
- `Set...`
- `Find...`
- `Encode...`
- `Decode...`
- `Alloc...`
- `DeAlloc...`
- `Open...`
- `Close...`
- `Hook...`
- `UnHook...`
- `Dump...`

Historical forms such as `UnHook`, `UnLock`, `DeAlloc`, and `ReLink` are acceptable if they are part of a project's established convention.

### 8.6. Compile-Time Constants

`constexpr` constants use the `k` prefix with a `PascalCase` tail.

The `k` prefix is reserved only for `constexpr` constants. Do not use `k` for ordinary variables, non-`constexpr` `const` objects, macros, enum values, globals, members, or function parameters.

Correct:

```cpp
constexpr size_t kMaxRecords = 64;
constexpr unsigned int kPageSize = 0x1000;

char szBuffer[kMaxRecords];
```

Incorrect:

```cpp
const size_t kRuntimeSize = GetRuntimeSize();
#define kMaxRecords 64
unsigned int kIndex = 0;
```

### 8.7. Macros

Macros use `UPPER_SNAKE_CASE`.

Examples:

```cpp
DEFINE_SECTION
LINKER_OPTION
DISABLE_OPTIMIZATION_BEGIN
RD_FLAG_MODRM
```

### 8.8. Acronyms

Keep acronyms uppercase where that improves recognizability:

```cpp
GetPEB
GetTEB
DumpRTTI
GetMXCSR
```

---

## 9. Types, Declarations, and Qualifiers

### 9.1. Explicit Types

Signatures should be as explicit as needed.

Do not over-rely on:

- auto return types without a reason;
- non-obvious type deduction;
- "smart" hiding of types where the type matters to understanding the API.

### 9.2. `const` Style

Prefer the "east const" style:

```cpp
void const* const pAddress
char const* const szName
wchar_t const* const szModuleName
```

That means:

- `const` applies to the type on the left;
- constness of the pointer itself is also made explicit.

### 9.3. `const` on Scalar Parameters

`const` on scalar parameters is acceptable and often useful if it makes the signature more declarative:

```cpp
bool SetSize(const unsigned int unSize);
```

### 9.4. `*` and `&` Binding

Declaration style:

```cpp
void* pAddress
Page** pPage
const Block& block
```

Forms like:

```cpp
void * pAddress
```

are not used.

### 9.5. `typedef struct` and `typedef enum`

For C-compatible, ABI-facing, and layout-sensitive data, prefer:

```cpp
typedef struct _SOME_RECORD {
	...
} SOME_RECORD, *PSOME_RECORD;
```

```cpp
typedef enum _SOME_MODE {
	...
} SOME_MODE, *PSOME_MODE;
```

### 9.6. `using` for Function Pointer Aliases

For callbacks and function pointer aliases, prefer:

```cpp
using fnCallBack = bool(*)(void* pData);
```

### 9.7. `noexcept`

Use `noexcept` for:

- query functions;
- search/scanning helpers;
- small low-level utilities;
- APIs that report failure through `bool` / `nullptr` rather than exceptions.

### 9.8. Default Arguments

Default arguments belong in declarations, not definitions:

```cpp
bool Wait(DWORD unMilliseconds = INFINITE);
```

---

## 10. `class` and `struct` Organization

### 10.1. Repeated `public:` / `private:`

A class may have multiple `public:` and `private:` sections.

Use them to group:

- lifecycle;
- core operations;
- getters;
- helper methods;
- data members.

Example:

```cpp
class SomeType {
public:
	SomeType();
	~SomeType();

public:
	bool Set(...);
	bool Release();

public:
	void* GetAddress() const;

private:
	void* m_pAddress;
};
```

### 10.2. Order Inside a Class

Recommended order:

1. constructors/destructor;
2. main operations;
3. accessors/getters;
4. private helpers;
5. fields.

### 10.3. Member Initialization

By default, members may be initialized in the constructor body:

```cpp
SomeType::SomeType() {
	m_pAddress = nullptr;
	m_unSize = 0;
	m_bActive = false;
}
```

If an initializer list is clearly better, it is allowed:

```cpp
SomeType::SomeType(...) : m_pAddress(pAddress), m_unSize(unSize) {
	...
}
```

### 10.4. POD-like Structures with Constructors

Even C-style `typedef struct` may contain a constructor for explicit initialization, as long as it does not interfere with layout and improves reliability.

### 10.5. Special Members

`= delete` and `= default` are allowed and recommended when they clearly express ownership semantics.

Example:

```cpp
SomeGuard(const SomeGuard&) = delete;
SomeGuard& operator=(const SomeGuard&) = delete;
```

---

## 11. Function Body Style

### 11.1. Guard Clauses

Functions should begin with invariant and input validation.

Example:

```cpp
if (!pAddress || !unSize) {
	return false;
}
```

### 11.2. Early Return

The main error-handling style is **early return**.

Do not accumulate deep nesting if the problem can be handled immediately.

### 11.3. Phase-Based Structure

A function body should be organized into phases:

- preconditions;
- setup;
- main logic;
- cleanup;
- final return.

Blank lines between phases are required.

### 11.4. `auto`

Use `auto` selectively:

- for verbose iterator/type-heavy expressions;
- for results of `std::make_unique`;
- for temporary locals where the type is obvious from the right-hand side.

Do not use `auto` as a blanket style for all code.

### 11.5. Explicit `return true;` / `return false;`

Even when the logic is obvious, end the function with an explicit return value.

### 11.6. Cleanup Near the Failure Point

If an error occurs mid-algorithm, cleanup should happen as close as possible to the failure point.

---

## 12. Error Handling

### 12.1. Main Model

Preferred error model:

- `bool` for success/failure;
- `nullptr` for missing results;
- `0` or `-1` for numeric failure, where the API requires it;
- empty containers for collection results.

### 12.2. Exceptions

Standard C++ exceptions should not be the primary control-flow mechanism in systems-oriented code.

Exceptions are acceptable only if:

- the project is built around exception-based APIs as a whole;
- they do not conflict with boundary layers;
- they do not hide cleanup or blur behavior.

### 12.3. SEH and Platform-Specific Error Handling

In platform-aware code, mechanisms such as the following are acceptable:

- `__try / __except`;
- debug-only breakpoints;
- compiler/platform-specific diagnostics.

But only where genuinely justified:

- memory probing;
- walking potentially invalid pointers;
- low-level diagnostics;
- ABI/layout validation.

---

## 13. API Design

### 13.1. Explicit API Families

If a function has multiple kinds of input sources, prefer a family of overloads over a single overloaded "smart" function.

For example:

- by address;
- by module;
- by resource name;
- by section;
- by backend implementation.

### 13.2. ANSI/Wide and Generic Wrapper

For string-based boundary APIs, you may use the pattern:

- `...A(...)`
- `...W(...)`
- a generic wrapper configured by the project

Example:

```cpp
void const* FindThingA(char const* const szModuleName, char const* const szPattern);
void const* FindThingW(wchar_t const* const szModuleName, char const* const szPattern);
```

If a project is platform-independent or uses UTF-8 only, this section may be ignored.

### 13.3. Callback APIs

For low-level callbacks, prefer raw function pointer aliases:

```cpp
using fnCallBack = bool(*)(void* pData);
```

Avoid `std::function` in:

- hot paths;
- boundary APIs;
- ABI-sensitive code;
- hooks and callback chains in systems code.

### 13.4. Getters

Getters should be simple and direct.

If an object truly owns a:

- handle,
- pointer,
- raw context,
- section,
- region,

then the getter may return it directly, without an extra abstraction layer.

---

## 14. Low-Level and Platform-Aware Code

This section applies only where the project genuinely deals with:

- ABI;
- layout;
- memory mapping;
- page protection;
- intrinsics;
- machine code;
- system APIs.

### 14.1. Allowed Tools

For low-level sections, the following are acceptable:

- `reinterpret_cast`
- `static_cast`
- `offsetof`
- `sizeof`
- `alignof`
- `union`
- `bitfield`
- raw pointer arithmetic
- compiler intrinsics
- byte arrays
- architecture-specific `#ifdef`
- macros

### 14.2. Layout-First Structures

If a structure represents a binary layout, layout accuracy takes priority over abstract "OO neatness".

Example:

```cpp
union {
	unsigned int m_unValue;

	struct {
		unsigned int m_unA : 1;
		unsigned int m_unB : 1;
	};
};
```

### 14.3. Byte Templates

Byte arrays, offsets, patching, and direct instruction encoding are allowed when they are part of the problem being solved.

### 14.4. Macros

Macros are allowed if they:

- encapsulate a platform/compiler directive;
- encode flags or tables;
- reduce repetitive low-level patterns;
- provide a predictable compile-time result.

Do not use macros where an ordinary function or `constexpr` mechanism makes the code simpler without losing control.

### 14.5. Architecture Branches

If ABI or layout differs across architectures, branching through the preprocessor should be explicit:

```cpp
#ifdef _M_X64
	...
#elif _M_IX86
	...
#endif
```

---

## 15. Resource Management

### 15.1. RAII-lite

Use RAII where it:

- reduces leak risk;
- makes cleanup automatic;
- does not hide important low-level details.

Typical RAII candidates:

- guard types;
- handle wrappers;
- protection/restoration objects;
- transaction objects.

### 15.2. Manual Lifecycle

Manual lifecycle is acceptable and often preferable when an object needs a precise, controlled lifecycle.

Typical methods:

- `Set`
- `Release`
- `Open`
- `Close`
- `Alloc`
- `DeAlloc`
- `Hook`
- `UnHook`

### 15.3. Smart Pointers

`std::unique_ptr` is the preferred ownership tool.

Use `std::shared_ptr` only when shared ownership is truly unavoidable, not "just in case".

---

## 16. Synchronization

### 16.1. Explicit Primitives

In systems-oriented code, the following are acceptable:

- OS-native locks;
- explicit lock/unlock;
- raw synchronization handles;
- `std::atomic` for flags and counters.

### 16.2. Local Visibility of Lock Ownership

Lock lifetime should be as obvious as possible.

If manual lock/unlock is used:

```cpp
AcquireLock(&g_Lock);
...
ReleaseLock(&g_Lock);
```

then the release should remain visible in the same control-flow region.

### 16.3. RAII Lock Wrappers

RAII lock wrappers are acceptable if:

- they are already standard in the project;
- they do not make lock lifetime harder to see;
- they do not hide platform-specific semantics.

---

## 17. STL Profile

### 17.1. Preferred Containers

Most commonly appropriate:

- `std::array`
- `std::vector`
- `std::deque`
- `std::list`
- `std::set`
- `std::unordered_map`
- `std::unordered_set`
- `std::unique_ptr`
- `std::atomic`

### 17.2. Explicit Loops

If a loop is tied to:

- address arithmetic;
- indexes;
- byte offsets;
- early exits;
- complex low-level logic,

prefer an explicit `for` / `while` instead of abstracting it away through algorithms.

### 17.3. Higher-Level Wrappers

`std::string`, `std::wstring`, `std::function`, lambdas, ranges, and similar higher-level tools are not forbidden, but they should be used only where they genuinely simplify the code and do not hide architecturally important details.

---

## 18. Comments

### 18.1. Banners

Use banners for large sections:

```cpp
// ----------------------------------------------------------------
// Hook
// ----------------------------------------------------------------
```

### 18.2. Phase Comments

Inside large functions, comments should mark stages, not narrate every line.

Example:

```cpp
// Stack Allocation
// Flags
// Registers
// CallBack
```

### 18.3. Layout Comments

If code describes a binary layout, comments should explain bits, fields, offsets, and reserved areas.

Example:

```cpp
unsigned int m_unCF : 1;   // Bit 0: Carry Flag
unsigned int m_unIOPL : 2; // Bit 12-13: I/O Privilege Level
```

### 18.4. Namespace Closing Comments

In long files, closing namespace braces should be commented:

```cpp
} // namespace Memory
} // namespace Project
```

---

## 19. What This Style Dislikes

The following patterns usually clash with this style:

- `Allman` braces
- `snake_case` for functions, methods, and local variables
- exceptions as the primary error model
- blanket use of `auto`
- hiding ownership and cleanup behind too much "magic"
- abstraction for abstraction's sake
- short meaningless names like `x`, `tmp`, `foo`, `bar`, `data2`
- one-line `if` statements without braces
- high-level wrappers inside ABI- and layout-sensitive code

---

## 20. Canonical Templates

### 20.1. Canonical Function

```cpp
bool SomeClass::SomeFunction(void* pAddress, size_t unSize) {
	if (!pAddress || !unSize) {
		return false;
	}

	if (!m_bInitialized) {
		return false;
	}

	auto pByteAddress = reinterpret_cast<unsigned char*>(pAddress);
	if (!pByteAddress) {
		return false;
	}

	for (size_t unIndex = 0; unIndex < unSize; ++unIndex) {
		...
	}

	return true;
}
```

### 20.2. Canonical Class

```cpp
class SomeType {
public:
	SomeType();
	~SomeType();

public:
	bool Set(void* pAddress);
	bool Release();

public:
	void* GetAddress() const;
	size_t GetSize() const;

private:
	void* m_pAddress;
	size_t m_unSize;
	bool m_bInitialized;
};
```

### 20.3. Canonical Overload Family

```cpp
void const* FindThing(void const* const pAddress, const size_t unSize, char const* const szPattern) noexcept;
void const* FindThing(const void* pModuleHandle, char const* const szPattern) noexcept;
void const* FindThingA(char const* const szName, char const* const szPattern) noexcept;
void const* FindThingW(wchar_t const* const szName, char const* const szPattern) noexcept;
```

### 20.4. Canonical Low-Level Record

```cpp
typedef struct _SOME_RECORD {
	_SOME_RECORD() {
		m_pAddress = nullptr;
		m_unSize = 0;
		m_bActive = false;
	}

	void* m_pAddress;
	size_t m_unSize;
	bool m_bActive;
} SOME_RECORD, *PSOME_RECORD;
```

---

## 21. Rules in MUST / SHOULD / MAY Form

### MUST

- Put `{` on the same line as the controlling construct or signature.
- Use braces for all branches.
- Use tabs as the primary indentation unit.
- Use semantic prefixes in names.
- Keep file-level declarations in strict dependency order: includes, constants, globals, leaf-level functions, mid-level functions, high-level functions, entry points.
- Use the `k` prefix only for `constexpr` constants.
- Start functions with guard clauses.
- Return explicit success/failure values.
- Keep cleanup close to the failure point.
- Separate large blocks with banners or at least clear sections.

### SHOULD

- Use east `const`.
- Prefer long but clear signatures over shortened signatures that hide meaning.
- Preserve a phase-based structure inside functions.
- Use `typedef struct` / `using fn...` where that improves a boundary layer.
- Keep platform/ABI branches explicit.
- Prefer `std::unique_ptr` as the main ownership tool.

### MAY

- Use compiler/platform-specific pragmas.
- Use `reinterpret_cast`, `union`, `bitfield`, macros, and byte arrays in low-level sections.
- Use `A/W` API families.
- Use RAII-lite wrappers.
- Use explicit lock/unlock if it fits the domain better.

---

## 22. One-Line Summary

```text
K&R / 1TBS + Systems Hungarian + Explicit Systems C++
```

---

## 23. Final Summary

If code is meant to look natural in this style, it should be:

- visually disciplined;
- semantically explicit;
- predictable in control flow;
- careful about ownership and cleanup;
- honest about low-level details;
- engineering-oriented rather than decorative.

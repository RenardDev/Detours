# Code Style Guide

This document describes a reusable coding style for projects that need:

- a predictable visual code shape;
- explicit types, ownership, and control flow;
- a systems-minded, engineering-oriented style rather than a "magical" one;
- careful handling of both ordinary application code and low-level code;
- good support for header-only, template-heavy, and compile-time utilities.

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
- "clean-looking" code must not come at the cost of ABI, layout, ownership, diagnosability, or compile-time predictability.

---

## 2. Scope

This guide is suitable for:

- libraries;
- infrastructure C++;
- systems and embedded code;
- game tooling;
- utilities;
- SDKs;
- compile-time utilities;
- header-only template utilities;
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
- byte patches and machine code;
- compile-time literal transformation;
- generated lookup tables;
- fixed-size constexpr interpreters/parsers.

---

## 3. Overall Character of the Style

This style:

- prefers explicit constructs over implicit ones;
- is not afraid of long signatures when they improve clarity;
- accepts verbosity in exchange for control;
- treats C-compatible types inside C++ as normal;
- uses guard clauses heavily;
- does not consider `macro`, `cast`, `union`, `raw pointer`, `constexpr table`, or `fixed buffer` to be automatically bad tools;
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

### 4.3. Include-Time Configuration Defines

A dependency may require a feature-selection macro before it is included. This is the only deliberate exception to the simple "all includes first" rule.

Rules:

1. A configuration `#define` for an included header must appear immediately before the `#include` it configures.
2. The configuration define should be visually grouped with that include, usually with a small comment.
3. Do not place unrelated constants, helper macros, globals, or functions between the configuration define and the configured include.
4. If the configuration macro is private to the current header or translation unit, `#undef` it after the last required use.
5. If the configuration macro is part of the public include contract, leave it documented and stable.

Example:

```cpp
// CompileTimeStamp
#define COMPILETIMESTAMP_USE_64BIT
#include "CompileTimeStamp.h"
```

### 4.4. Declaration and Dependency Order

Inside a file, declarations and definitions must follow a strict dependency order.

The goal is not to satisfy the compiler in the narrowest possible way. C++ can often tolerate forward declarations and cross-references. The goal is to make the file readable from top to bottom and to make dependencies discoverable without mental backtracking.

Simple canonical order after the file header / include guard:

1. `#include` directives.
2. `#define` values and compile-time constants.
3. Global and static objects.
4. Functions ordered from lower-level to higher-level.

Expanded dependency-aware order for real C++ files:

1. include block;
2. include-time configuration defines directly next to the include they configure;
3. file-local helper macros and compile-time constants;
4. type aliases, traits, enums, and layout records that later constants/functions depend on;
5. global and static objects;
6. leaf-level functions/helpers;
7. mid-level functions/classes;
8. high-level orchestration functions;
9. entry points;
10. public macro facades, if they depend on implementation above;
11. `#undef` cleanup for temporary helper macros.

Rules:

1. Includes always come before local constants, globals, and function definitions, except for documented pre-include configuration macros.
2. `#define` values and compile-time constants must appear before their first use.
3. This includes uses in array sizes, template arguments, non-type template parameters, static assertions, masks, offsets, and other compile-time contexts.
4. If a type is required to declare a constant or table, define that type immediately before the first dependent constant.
5. If a `constexpr` constant/table is produced by a `constexpr` leaf helper, that leaf helper may appear immediately before the generated constant/table because dependency order wins. Do not use this exception for mid-level or high-level functions.
6. Global and static objects must appear before functions.
7. Functions must be ordered by dependency level whenever practical:
   - leaf-level functions first;
   - mid-level helper functions after leaf-level functions;
   - high-level orchestration functions after mid-level functions;
   - entry points last.
8. Public macros that instantiate or call implementation templates should appear after the namespace/class implementation they depend on.
9. Temporary helper macros should be undefined at the end of the file, after the last use.
10. A reader should be able to move downward through the file and understand who depends on whom without repeated jumping.

Benefits:

- reduces accidental reordering mistakes;
- makes responsibility boundaries easier to see;
- makes large implementation files easier to navigate;
- improves long-term maintenance in macro-heavy, systems-heavy, and utility-heavy code.

Forward declarations are allowed where they are genuinely useful, but they should not be used to justify chaotic ordering inside a translation unit.

### 4.5. Section Banners

Large logical blocks inside a file should be separated by section banners.

Use long `=` banners for top-level file or namespace sections:

```cpp
// ============================================================================
// Parser
// ============================================================================
```

Use shorter `-` banners for ordinary sections inside a file:

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

Banners should describe stable responsibilities, not temporary implementation details.

### 4.6. Header-Only Utility Layout

Header-only utilities may contain full implementations, templates, compile-time tables, macro facades, and small platform/compiler configuration blocks. They still need a predictable top-to-bottom shape.

Recommended order inside a header-only utility:

1. `#pragma once` and/or include guard.
2. Include block.
3. Optional include-configuration macros placed immediately before the include they configure.
4. Temporary compiler/platform helper macros.
5. Namespace with implementation details.
6. Type aliases and fixed-size helper types.
7. Compile-time tables and constants before first use.
8. Leaf helpers.
9. State structs, byte helpers, classes, and mid-level algorithms.
10. High-level wrappers or public compile-time APIs.
11. Public macro facade, if the API intentionally needs macro syntax.
12. `#undef` for temporary helper macros.
13. Closing include guard.

Temporary compiler helper macros should be module-scoped by name and cleaned up before the end of the header:

```cpp
#if defined(_MSC_VER)
#define SOMEUTILITY_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define SOMEUTILITY_FORCE_INLINE __attribute__((always_inline))
#else
#define SOMEUTILITY_FORCE_INLINE inline
#endif

...

#undef SOMEUTILITY_FORCE_INLINE
```

If a header exposes a macro API, keep the real implementation in typed C++ code and make the public macro only a thin facade.

Canonical shape:

```cpp
#pragma once

#ifndef _SOME_UTILITY_H_
#define _SOME_UTILITY_H_

// STL
#include <type_traits>

// DependencyConfig
#define DEPENDENCY_USE_FEATURE
#include "Dependency.h"

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#if defined(_MSC_VER)
#define SOMEUTILITY_FORCE_INLINE __forceinline
#else
#define SOMEUTILITY_FORCE_INLINE inline
#endif

// ----------------------------------------------------------------
// SomeUtility
// ----------------------------------------------------------------

namespace SomeUtility {

	template <typename T>
	using CleanType = std::remove_const_t<std::remove_reference_t<T>>;

	constexpr std::size_t kBlockSize = 16;

	constexpr unsigned int RotateLeft(unsigned int unValue, unsigned int unBits) noexcept {
		return (unValue << unBits) | (unValue >> (32 - unBits));
	}

	class Object {
		...
	};
}

#define SOME_UTILITY(VALUE) ...

#undef SOMEUTILITY_FORCE_INLINE

#endif // !_SOME_UTILITY_H_
```

### 4.7. Preprocessor Hygiene

Macros are acceptable in systems-heavy and header-only code, but they must be controlled.

Rules:

1. Use a module-specific prefix for helper macros.
2. Avoid generic helper names such as `FORCE_INLINE`, `NO_INLINE`, `MIN`, `MAX`, or `HASH`.
3. Parenthesize macro arguments inside expressions.
4. Keep multi-line macros visually aligned and easy to scan.
5. Put public facade macros near the end of the file, after the types/functions they invoke.
6. `#undef` temporary helper macros when they are no longer needed.
7. Feature switches that configure a dependency must be placed immediately before the affected `#include` and should be documented by position or comment.

Correct:

```cpp
#define SOMEUTILITY_VALUE(INDEX) ((INDEX) + 1)

#undef SOMEUTILITY_VALUE
```

Incorrect:

```cpp
#define VALUE(i) i + 1
```

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
- is followed by `else`, `while`, or a semicolon where the syntax requires it.

Correct:

```cpp
if (bReady) {
	DoWork();
} else {
	return false;
}
```

### 5.3. Braces Are Mandatory

Always use braces, even for single-statement branches.

Correct:

```cpp
if (!pData) {
	return false;
}
```

Incorrect:

```cpp
if (!pData)
	return false;
```

---

## 6. Indentation and Vertical Rhythm

### 6.1. Indentation

Use tabs as the primary indentation unit.

Spaces may be used for local visual alignment inside tables, macro blocks, or bit layouts, but indentation itself is tab-based.

### 6.2. Blank Lines

Use blank lines to separate phases:

```cpp
if (!pAddress) {
	return false;
}

void* pBase = ResolveBase(pAddress);
if (!pBase) {
	return false;
}

return Commit(pBase);
```

Avoid dense walls of code. A blank line is useful when the code changes phase, responsibility, or failure mode.

### 6.3. Line Length

There is no tiny hard line limit.

Prefer readable wrapping over forced short lines. Long signatures are acceptable when they make types, ownership, or ABI visible.

Wrap when a line becomes hard to scan, especially in:

- long template expressions;
- macro bodies;
- boolean conditions;
- arithmetic formulas;
- bit manipulation expressions.

---

## 7. Spacing and Micro-Style

### 7.1. Space Before `{`

Use one space before `{`:

```cpp
if (bReady) {
```

### 7.2. Space After Keywords

Use a space after control-flow keywords:

```cpp
if (...)
for (...)
while (...)
switch (...)
```

### 7.3. Inside Parentheses

Do not add extra spaces just inside parentheses:

Correct:

```cpp
if (pAddress && unSize) {
```

Incorrect:

```cpp
if ( pAddress && unSize ) {
```

### 7.4. Around Operators

Use spaces around ordinary binary operators:

```cpp
unOffset = unBase + unIndex * 4;
```

### 7.5. Extra Parentheses

Extra parentheses are allowed and often useful when:

- bitwise logic is involved;
- macro expressions are involved;
- addresses, offsets, or ranges are involved;
- operator precedence should be visually frozen.

This style does not treat such parentheses as noise.

---

## 8. Naming

### 8.1. General Principle

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

The `k` prefix is reserved only for named `constexpr` constants. Do not use `k` for ordinary variables, non-`constexpr` `const` objects, macros, enum values, non-`constexpr` globals, non-`constexpr` members, function parameters, template parameters, `constexpr` functions, or `consteval` functions.

Correct:

```cpp
constexpr std::size_t kMaxRecords = 64;
constexpr unsigned int kPageSize = 0x1000;
constexpr unsigned char kBaseKey[32] = {};

char szBuffer[kMaxRecords];
```

Large compile-time lookup tables, fixed limits, array sizes, masks, and offsets should also use `k` when they are expressed as `constexpr` objects:

```cpp
constexpr unsigned char kSBox[256] = { ... };
constexpr std::size_t kPlainBytes = kLength * sizeof(T);
```

In template-heavy and header-only code, `static constexpr` members follow the same rule:

```cpp
class SomeTable {
private:
	static constexpr std::size_t kBlockSize = 16;
};
```

Incorrect:

```cpp
const std::size_t kRuntimeSize = GetRuntimeSize();
#define kMaxRecords 64
unsigned int kIndex = 0;
constexpr bool kIsSpace(char nChar);
template <std::size_t kN> class Buffer;
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

Macro APIs should be split into two layers when possible:

- a public macro with a clear project/module name;
- a private helper macro or typed implementation detail that does the real work.

For compile-time literal helpers, the macro body may use an immediately invoked lambda to preserve expression-like syntax, but the algorithm itself should live in named C++ types and functions inside a namespace.

Temporary macros for compiler attributes, packing, warnings, or include configuration must have a narrow lifetime. Define them near the top-level section where they are needed and `#undef` them when the section/header is finished.

Macro arguments may use uppercase names to make macro substitution visually distinct:

```cpp
#define HASH_STRING(STRING) ...
#define MAKE_ARRAY(ARRAY) ...
```

### 8.8. Template Parameters and Type Aliases

Template value parameters should use the same semantic prefixes as ordinary variables:

```cpp
template <std::size_t unLength, typename T, unsigned long long unLine, unsigned long long unCounter>
class SomeCompileTimeObject;
```

Type aliases should normally use `PascalCase`:

```cpp
template <typename T>
using CleanType = std::remove_const_t<std::remove_reference_t<T>>;
```

An internal alias may deliberately use an STL-like lower-case name only when it behaves like a tiny type trait and remains inside a narrow implementation namespace:

```cpp
namespace Detail {
	template <typename T>
	using clean_type = std::remove_const_t<std::remove_reference_t<T>>;
}
```

Do not expose STL-like lower-case aliases as broad public project types unless the whole project intentionally follows that convention.

### 8.9. Acronyms, Enums, and State Names

Keep acronyms uppercase where that improves recognizability:

```cpp
GetPEB
GetTEB
DumpRTTI
GetMXCSR
CRC32
AESState
```

Enum types that model machine instructions, stages, CPU operations, or ABI states may use compact uppercase names when that matches the domain:

```cpp
enum class OP : unsigned char {
	ADD,
	SUB,
	INVALID
};
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

Existing code that consistently uses west `const` may be preserved for local consistency.

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
- byte conversion helpers;
- `constexpr` utilities;
- small low-level utilities;
- APIs that report failure through `bool` / `nullptr` rather than exceptions.

### 9.8. Default Arguments

Default arguments belong in declarations, not definitions:

```cpp
bool Wait(DWORD unMilliseconds = INFINITE);
```

### 9.9. Size and Index Types

Use `std::size_t` for sizes, capacities, and array indices unless the ABI or file format requires a fixed-width type.

Use `un...` names for unsigned counts and indexes:

```cpp
std::size_t unIndex = 0;
std::size_t unCount = 0;
```

Use fixed-width integer types when the width is part of the format or algorithm:

```cpp
std::uint32_t unOpcode = 0;
std::uint64_t unHash = 0;
```

### 9.10. Fixed-Size Storage and Limits

When size is part of the contract, make it visible in the type. Prefer array references, `std::array`, template parameters, and `std::string_view` over hidden runtime length conventions.

Examples:

```cpp
template <std::size_t N>
constexpr unsigned int Hash(char const(&szText)[N]) noexcept;

template <std::size_t N>
constexpr void SetDataFromBytes(std::array<unsigned char, N> const& data);
```

Every non-trivial array bound should come from a named `constexpr` constant:

```cpp
struct ParserLimits {
	static constexpr std::size_t kMaxLines = 2048;
	static constexpr std::size_t kMaxTokens = 8;
};

struct Line {
	std::size_t m_unTokenCount = 0;
	Token m_Tokens[ParserLimits::kMaxTokens] {};
};
```

Related capacities should be grouped in a small `Limits` / `...Limits` structure when that improves readability.

Use raw arrays when the code is layout-sensitive, C-compatible, stack-local, or intentionally fixed-buffer oriented. Use `std::array` when value semantics, copying, returning, or STL interop is useful.

### 9.11. `static_assert` for Compile-Time Contracts

Use `static_assert` for programmer-facing compile-time constraints:

- unsupported element size;
- array too large for a fixed-capacity template;
- invalid compile-time configuration;
- ABI/layout assumptions;
- feature switches that must be selected before inclusion.

Example:

```cpp
static_assert((sizeof(T) == 1) || (sizeof(T) == 2) || (sizeof(T) == 4), "Unsupported element size");
static_assert(kBufferBytes <= kMaxBufferBytes, "buffer too large");
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

Default member initializers are also allowed for simple value wrappers and fixed-size structs:

```cpp
struct Error {
	char const* m_pMessage = nullptr;
	int m_nLine = -1;
};
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

### 10.6. Header-Only Value Wrappers

Small fixed-size wrappers such as byte blocks, names, tokens, buffers, or compile-time strings may expose simple methods such as `data()`, `size()`, `operator[]`, and conversion helpers.

Keep these wrappers boring:

- fixed storage;
- explicit size;
- no hidden allocation;
- no surprising ownership;
- `constexpr` and `noexcept` where possible.

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
- for temporary locals where the type is obvious from the right-hand side;
- for local lambda declarations;
- for compile-time result values whose exact type is intentionally generated by a template.

Do not use `auto` as a blanket style for all code.

### 11.5. Explicit `return true;` / `return false;`

Even when the logic is obvious, end the function with an explicit return value.

### 11.6. Cleanup Near the Failure Point

If an error occurs mid-algorithm, cleanup should happen as close as possible to the failure point.

### 11.7. Local Lambdas as Phase Helpers

Local lambdas are allowed when they make a long function flatter and more phase-oriented. They are especially useful for parsers, validators, small emitters, repeated error checks, and tiny local adapters.

Rules:

- give the lambda a semantic `PascalCase` name;
- keep it close to the phase where it is used;
- keep captures obvious and narrow;
- do not hide ownership transfer, allocation, locking, or cleanup inside an innocent-looking helper.

Example:

```cpp
auto NeedRegister = [&](int& nRegisterOut, std::string_view TokenView) -> bool {
	int nRegister = RegisterFrom(TokenView);
	if (nRegister < 0) {
		return false;
	}

	nRegisterOut = nRegister;
	return true;
};
```

### 11.8. `constexpr` and `consteval` Bodies

Compile-time algorithms may use loops, local mutable state, fixed-size arrays, helper structs, and explicit casts. A `constexpr` or `consteval` body should still look like ordinary readable systems code, not template metaprogramming for its own sake.

Rules:

- keep compile-time functions deterministic;
- prefer fixed storage over heap allocation;
- validate template limits with `static_assert`;
- return explicit result objects for multi-stage operations;
- avoid exceptions in compile-time execution paths;
- keep I/O, logging, and platform calls out of `constexpr` / `consteval` code.

---

## 12. Error Handling

### 12.1. Main Model

Prefer explicit status reporting:

- `bool` success/failure;
- `nullptr` failure;
- error object;
- status enum;
- result structure.

### 12.2. Exceptions

Exceptions are allowed only if the project uses them consistently.

In systems-heavy code, low-level code, compile-time code, and ABI-facing code, prefer explicit result reporting over exceptions.

### 12.3. SEH and Platform-Specific Error Handling

SEH and platform-specific mechanisms are allowed when they are the actual tool needed for the platform boundary.

Keep such logic localized and documented by structure rather than long prose.

### 12.4. Compile-Time Error Reporting

For compile-time interpreters, parsers, assemblers, or generators, prefer a result object that carries:

- success/failure;
- stage;
- line/index/offset;
- output data;
- error message or stable error code.

Example:

```cpp
struct Error {
	char const* m_pMessage = nullptr;
	int m_nLine = -1;
};

enum class STAGE : unsigned char {
	OK,
	FIRST_PASS,
	SECOND_PASS,
	RUNTIME
};
```

---

## 13. API Design

### 13.1. Explicit API Families

When an API has several related operations, use explicit names rather than a single overloaded name that hides behavior.

Example:

```cpp
FindByName
FindByAddress
FindByIndex
```

### 13.2. ANSI/Wide and Generic Wrapper

For Windows-style APIs, it is acceptable to expose `A` and `W` variants plus a generic wrapper if that is the domain convention.

Example:

```cpp
OpenFileA
OpenFileW
OpenFile
```

### 13.3. Callback APIs

Callback APIs should expose the callback type clearly:

```cpp
using fnEnumCallback = bool(*)(void* pEntry, void* pUserData);
```

Prefer explicit `pUserData` over hidden captures at ABI boundaries.

### 13.4. Getters

Simple getters may return raw values when the underlying concept is raw:

```cpp
void* GetAddress() const;
std::size_t GetSize() const;
```

If the raw value is the truth of the domain, then the getter may return it directly, without an extra abstraction layer.

---

## 14. Low-Level and Platform-Aware Code

This section applies only where the project genuinely deals with:

- ABI;
- layout;
- memory mapping;
- page protection;
- intrinsics;
- machine code;
- system APIs;
- fixed binary formats;
- compile-time byte generation.

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
- `constexpr` lookup tables
- fixed-size local buffers

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
- provide a predictable compile-time result;
- preserve information that is only available to the preprocessor, such as `__LINE__`, `__COUNTER__`, or string-literal syntax.

Do not use macros where an ordinary function or `constexpr` mechanism makes the code simpler without losing control.

### 14.5. Architecture Branches

If ABI or layout differs across architectures, branching through the preprocessor should be explicit:

```cpp
#ifdef _M_X64
	...
#elif defined(_M_IX86)
	...
#endif
```

### 14.6. Byte, Endian, and Bit-Level Helpers

Byte conversion should be isolated in small helpers instead of being scattered through high-level code.

Recommended patterns:

- use `unsigned char` / `std::uint8_t` style storage for raw bytes;
- make endianness visible in helper names such as `ReadBE32`, `WriteLE32`, `ReadWord`, or `ByteIO`;
- support only the element widths the algorithm actually handles;
- use `static_assert` for unsupported widths;
- use explicit casts around shifts, masks, and sign extension;
- keep aliasing through `unsigned char*` localized and easy to audit.

Example:

```cpp
template <typename T, std::size_t N>
struct ByteIO;

template <typename T>
struct ByteIO<T, 4> {
	static constexpr void To(T Value, unsigned char(&out)[4]) noexcept;
	static constexpr T From(unsigned char const(&in)[4]) noexcept;
};
```

### 14.7. Compile-Time Tables and Algorithms

Large compile-time tables are acceptable when they make the algorithm deterministic, fast, or self-contained.

Rules:

- name table constants with `k`;
- put tables before functions that read them;
- keep table element type explicit;
- group related tables near the algorithm that owns them;
- use `constexpr` when the table is compile-time data;
- avoid global mutable tables unless mutation is part of the design.

### 14.8. Compile-Time Obfuscation, Hashing, and Crypto Utilities

Compile-time hashing, literal transformation, obfuscated variables, stack strings, and encrypted arrays are allowed in low-level or protection-oriented code when they solve a real project problem.

Rules:

- keep the typed implementation inside a namespace;
- expose only a narrow public macro or function facade;
- use `constexpr` / `consteval` where deterministic compile-time generation is the point;
- keep seed, salt, timestamp, line, and counter mixing explicit;
- do not describe build-time variation as true randomness;
- do not treat compile-time obfuscation as a cryptographic security boundary;
- do not claim that embedded literals, generated constants, or embedded keys cannot be recovered;
- wipe temporary plaintext buffers where practical.

These tools are useful for reducing plain static artifacts and for making generated constants less repetitive. They are not a substitute for reviewed cryptography, runtime key management, or a threat model.

---

## 15. Resource Management

### 15.1. RAII-lite

Use small RAII wrappers where ownership is local and obvious.

Example:

```cpp
class HandleGuard {
public:
	~HandleGuard();

private:
	HANDLE m_hValue = nullptr;
};
```

### 15.2. Manual Lifecycle

Manual `Init` / `Release` style is allowed when it fits the domain better than constructor/destructor ownership.

If manual lifecycle is used, make the state visible:

```cpp
bool m_bInitialized = false;
```

### 15.3. Smart Pointers

Prefer `std::unique_ptr` for single-owner heap objects.

Do not force smart pointers into ABI boundaries, raw OS handle APIs, or memory layouts where they do not belong.

### 15.4. Temporary Plaintext and Sensitive Buffers

When a utility materializes plaintext, decrypted data, temporary keys, masks, or other sensitive intermediate data, the lifetime should be explicit and short.

Recommended pattern:

- wrap the temporary buffer in a small owner type;
- delete copy construction and copy assignment;
- allow move only if the moved-from object is cleared;
- clear the buffer in the destructor;
- use a project-approved secure zeroing primitive when available;
- otherwise use a localized volatile-write cleanup helper with a clear comment.

Do not store decrypted literal buffers in global/static objects unless the project explicitly accepts that lifetime.

---

## 16. Synchronization

### 16.1. Explicit Primitives

Use explicit synchronization primitives:

```cpp
std::mutex
CRITICAL_SECTION
SRWLOCK
std::atomic
```

The primitive should match the domain and platform.

### 16.2. Local Visibility of Lock Ownership

Lock acquisition and release should be visible near the protected logic.

Avoid helper functions that make it unclear whether a lock is held.

### 16.3. RAII Lock Wrappers

RAII lock wrappers are preferred when they make ownership clearer.

Manual lock/unlock is allowed when the domain requires it, but it must be structured so that failure paths are obvious.

---

## 17. STL Profile

### 17.1. Preferred Containers

Use STL containers where they are a good fit:

- `std::vector`
- `std::array`
- `std::string`
- `std::wstring`
- `std::string_view`
- `std::unique_ptr`

Do not force STL containers into binary layouts, ABI records, compile-time fixed buffers, or platform structs where raw arrays are more correct.

### 17.2. Explicit Loops

Prefer explicit loops when they improve readability:

```cpp
for (std::size_t i = 0; i < unCount; ++i) {
	...
}
```

Algorithms such as `std::find_if` are allowed when they are genuinely clearer.

### 17.3. Higher-Level Wrappers

Use higher-level STL wrappers when they clarify ownership or lifetime. Do not use them to hide domain-critical details.

---

## 18. Compile-Time and Header-Only Utilities

### 18.1. General Model

Header-only compile-time utilities should be built as typed C++ first and macro syntax second.

Good shape:

1. fixed helper types;
2. constants/tables;
3. leaf algorithms;
4. state/helper classes;
5. high-level `constexpr` / `consteval` entry points;
6. public macro facade, if needed.

### 18.2. Compile-Time Tables

Compile-time tables should be:

- `constexpr`;
- named with `k`;
- placed before use;
- typed explicitly;
- grouped with the algorithm that owns them.

Example:

```cpp
constexpr unsigned int kCRC32Table[256] = {
	...
};
```

### 18.3. Byte Serialization Helpers

For compile-time string, array, hash, VM, or binary-format utilities, byte serialization should be explicit.

Correct pattern:

```cpp
template <typename T, std::size_t N>
struct ByteIO;

template <typename T>
struct ByteIO<T, 2> {
	static constexpr void To(T Value, unsigned char(&out)[2]) noexcept {
		unsigned short const unX = static_cast<unsigned short>(Value);
		out[0] = static_cast<unsigned char>( unX       & 0xFF);
		out[1] = static_cast<unsigned char>((unX >> 8) & 0xFF);
	}
};
```

### 18.4. Public Compile-Time API Macros

A macro is acceptable as a public compile-time API when it preserves syntax or information that a function cannot naturally receive:

- string literal extent;
- array extent;
- `__LINE__`;
- `__COUNTER__`;
- architecture selection;
- expression-like lazy construction.

The macro should delegate to typed implementation code:

```cpp
#define STACK_STRING(STRING) \
	([]() -> auto { \
		constexpr std::size_t kLength = std::extent_v<std::remove_reference_t<decltype(STRING)>>; \
		return Detail::MakeStackString<kLength>(STRING); \
	}())
```

Keep macro bodies as small as practical.

### 18.5. `constexpr` / `consteval` Entry Points

Use `consteval` when the API must run at compile time.

Use `constexpr` when the same code may be useful at compile time or runtime.

For multi-stage compile-time operations, return an explicit result object rather than hiding errors behind template substitution noise.

---

## 19. Comments

### 19.1. Banners

Use banners to divide stable sections.

```cpp
// ----------------------------------------------------------------
// Decoder
// ----------------------------------------------------------------
```

### 19.2. Phase Comments

Short phase comments are useful in long functions:

```cpp
// Validate input
...

// Build table
...

// Commit result
...
```

Do not comment every obvious line.

### 19.3. Layout Comments

For binary layouts, comments should clarify offsets, sizes, flags, and ABI assumptions.

### 19.4. Namespace Closing Comments

For large namespaces, use a closing comment:

```cpp
} // namespace SomeUtility
```

---

## 20. What This Style Dislikes

This style dislikes:

- hidden ownership;
- excessive abstraction around raw facts;
- deep nesting;
- unordered files;
- constants used before declaration;
- globals hidden below functions;
- public macros placed before the implementation they depend on;
- unscoped helper macros that leak across headers;
- `auto` everywhere;
- "modern C++" as a substitute for clear domain logic;
- pretending that compile-time obfuscation is strong runtime security.

---

## 21. Canonical Templates

### 21.1. Canonical Function

```cpp
bool SomeObject::SetBuffer(void* pBuffer, std::size_t unSize) {
	if (!pBuffer || !unSize) {
		return false;
	}

	void* pNewBuffer = AllocBuffer(unSize);
	if (!pNewBuffer) {
		return false;
	}

	CopyBuffer(pNewBuffer, pBuffer, unSize);

	m_pBuffer = pNewBuffer;
	m_unSize = unSize;

	return true;
}
```

### 21.2. Canonical Class

```cpp
class SomeObject {
public:
	SomeObject();
	~SomeObject();

public:
	bool Init();
	void Release();

public:
	void* GetAddress() const;
	std::size_t GetSize() const;

private:
	void* m_pAddress;
	std::size_t m_unSize;
	bool m_bInitialized;
};
```

### 21.3. Canonical Overload Family

```cpp
bool FindByName(char const* const szName);
bool FindByAddress(void const* const pAddress);
bool FindByIndex(std::size_t const unIndex);
```

### 21.4. Canonical Low-Level Record

```cpp
typedef struct _SOME_RECORD {
	void* m_pAddress;
	std::size_t m_unSize;
	bool m_bActive;
} SOME_RECORD, *PSOME_RECORD;
```

### 21.5. Canonical Header-Only Compile-Time Utility

```cpp
#pragma once

#ifndef _COMPILETIMEUTILITY_H_
#define _COMPILETIMEUTILITY_H_

// STL
#include <type_traits>
#include <array>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#if defined(_MSC_VER)
#define COMPILETIMEUTILITY_FORCE_INLINE __forceinline
#else
#define COMPILETIMEUTILITY_FORCE_INLINE inline
#endif

// ----------------------------------------------------------------
// CompileTimeUtility
// ----------------------------------------------------------------

namespace CompileTimeUtility {

	template <typename T>
	using CleanType = std::remove_const_t<std::remove_reference_t<T>>;

	constexpr std::size_t kBlockSize = 16;

	template <typename T, std::size_t N>
	struct ByteIO;

	template <typename T>
	struct ByteIO<T, 1> {
		static constexpr void To(T Value, unsigned char(&out)[1]) noexcept {
			out[0] = static_cast<unsigned char>(Value);
		}
	};

	constexpr unsigned int HashByte(unsigned int unState, unsigned char unByte) noexcept {
		return (unState * 16777619u) ^ unByte;
	}

	template <std::size_t N>
	consteval unsigned int Hash(char const(&szText)[N]) noexcept {
		unsigned int unHash = 2166136261u;

		for (std::size_t i = 0; i < (N - 1); ++i) {
			unHash = HashByte(unHash, static_cast<unsigned char>(szText[i]));
		}

		return unHash;
	}
}

#define COMPILE_TIME_HASH(STRING) CompileTimeUtility::Hash(STRING)

#undef COMPILETIMEUTILITY_FORCE_INLINE

#endif // !_COMPILETIMEUTILITY_H_
```

---

## 22. Rules in MUST / SHOULD / MAY Form

### MUST

- Put `{` on the same line as the controlling construct or signature.
- Use braces for all branches.
- Use tabs as the primary indentation unit.
- Use semantic prefixes in names.
- Keep file-level declarations in strict dependency order: includes, constants, globals, leaf-level functions, mid-level functions, high-level functions, entry points.
- Keep include-configuration macros directly next to the include they configure.
- Put `#define` values and compile-time constants before first use, including array sizes and template arguments.
- Put global and static objects before functions.
- Use the `k` prefix only for named `constexpr` constants.
- Do not use the `k` prefix for macros, enum values, runtime `const` objects, parameters, template parameters, ordinary locals, non-`constexpr` globals, or functions.
- Use `static_assert` for compile-time size, layout, and supported-width constraints.
- Keep temporary compiler/helper macros narrow in scope and `#undef` them after use.
- Start functions with guard clauses.
- Return explicit success/failure values.
- Keep cleanup close to the failure point.
- Separate large blocks with banners or at least clear sections.

### SHOULD

- Use east `const` where local style allows it.
- Prefer long but clear signatures over shortened signatures that hide meaning.
- Preserve a phase-based structure inside functions.
- Use `typedef struct` / `using fn...` where that improves a boundary layer.
- Keep platform/ABI branches explicit.
- Isolate byte, endian, and bit-level conversions in small helpers.
- Use fixed-size APIs, `std::array`, array references, and `std::string_view` when size/lifetime should be visible.
- Keep compile-time obfuscation and hashing claims limited to what the code actually guarantees.
- Clear temporary plaintext or sensitive buffers when practical.
- Prefer `std::unique_ptr` as the main ownership tool.

### MAY

- Use compiler/platform-specific pragmas.
- Use `reinterpret_cast`, `union`, `bitfield`, macros, and byte arrays in low-level sections.
- Use `constexpr`, `consteval`, NTTP strings, and macro facades for compile-time utilities.
- Use compile-time literal hashing, stack strings, and generated arrays when the project needs them.
- Use `A/W` API families.
- Use RAII-lite wrappers.
- Use explicit lock/unlock if it fits the domain better.

---

## 23. One-Line Summary

Write code so that a systems programmer can read it top-to-bottom, see ownership and dependencies immediately, and trust that names, constants, macros, buffers, and control flow mean exactly what they say.

---

## 24. Final Summary

This style is explicit, dependency-ordered, macro-aware, low-level friendly, and suitable for both ordinary C++ and header-only compile-time utilities. It values predictable structure over cleverness, strict declaration order over cross-file guessing, and clear systems behavior over fashionable abstraction.

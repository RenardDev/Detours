# Code Style Guide

> Warning: this file is large for AI-agent processing. Read it by section, prefer targeted searches, and use the numbered headings as navigation anchors.

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

## Quick reference for AI agents

If you only have time for the essentials, follow these. The detailed numbered rule takes precedence over this summary, and language, ABI, security, and toolchain correctness take precedence over presentation rules.

A project that adopts this guide should enforce the mechanically checkable parts with a formatter, linter, style-audit script, review checklist, or a combination of those tools:

- Indent code with **tabs**, never spaces. In Markdown, indent prose with spaces and fenced code blocks according to the target language style.
- Use K&R / 1TBS braces on the same line and braces around every `if` / `for` / `while` / `else` body.
- Use **west const** for simple scalar types: `const int nA`, `const float flB`, `const std::size_t unSize`. For compound declarations, keep `const` adjacent to the qualified type or pointer/reference as required by the declaration.
- Use systems Hungarian names for scalar, pointer, handle, buffer, and common container categories; use semantic PascalCase role names for domain value objects. A pointer to a primitive scalar or C string combines `p` with the value prefix (`pn`, `pun`, `pb`, `pfl`, `pdbl`, `pch`, `pwch`, `psz`); every additional pointer level adds another leading `p` (`ppn`, `ppun`, `ppb`, `ppfl`, `ppdbl`, `ppch`, `ppwch`, `ppsz`). A pointer to an object, user-defined/non-primitive type, opaque value, or `void` uses only the required number of `p` characters.
- Reserve `k`-prefixed names for named `constexpr` constants. Macros use a module-specific `UPPER_SNAKE_CASE` name.
- Use `auto` for iterators and range-loop elements, and for local domain values returned directly by a project function when repeating the return type adds no ownership or ABI information. Prefer an explicit type for ownership-bearing allocations and ABI/system records. For simple scalar values, write the type explicitly with leading `const` when the value is const; for complex pointers, prefer a `P*` alias or `auto*` as described below.
- When a declaration can copy- or conversion-initialize a value from an expression without changing semantics, use `Type Name = Expression;`. Do not spell that copy as `Type Name { Expression };` or `Type Name(Expression);`. Keep `{}` for value/default initialization and use direct or list initialization only when the language or intended constructor semantics require it.
- In a function with an explicit return type, return an empty value-initialized result as `return {};`. Do not repeat the return type as `return Type {};` or `return Type();`.
- Keep control flow flat with guard clauses, explicit success/failure returns, and cleanup close to ownership.
- Make ownership, nullability, buffer extent, and lifetime visible in the type, signature, or immediately adjacent documentation.
- Validate ranges before pointer arithmetic, validate integer operations before overflow, and verify ABI layouts with `static_assert`.
- Do not use C-style casts, reserved project identifiers outside documented compatibility exceptions, hidden dynamic global initialization, or `volatile` as synchronization.
- Keep one blank line between completed phases. A standalone closing `}` followed by an ordinary statement/declaration must have one blank line after it, except before another `}`, `else`, `catch`, `while`, a required semicolon, a preprocessor directive, or an already blank line. Do not use trailing whitespace or two consecutive blank lines. Keep `#elif`, `#else`, and `#endif` directly adjacent to the preceding line of their preprocessor branch; do not insert a blank line before these directives.
- Inside an early-exit branch, keep its one final call, assignment, declaration, or other single action directly adjacent to the simple one-line `return` that completes that branch. Do not insert a blank line between the action and the early return. On the main path, keep a final output/result commit and the final success return as separate phases with one blank line between them.
- Call qualified standard algorithms directly: use `std::max(...)` and `std::min(...)`, never `(std::max)(...)` or `(std::min)(...)`. Resolve platform macro collisions at the include boundary or by the documented preprocessor rules.
- Do not use integer-literal suffixes such as `U`, `UL`, `ULL`, `L`, `u`, `ul`, `ull`, or `l` unless the code materially requires the literal type, range, overload, shift, ABI, or constant-evaluation behavior.

The numbered sections below are the full specification; use their headings as search anchors.

---

## Table of contents

- [Quick reference for AI agents](#quick-reference-for-ai-agents)
- [1. Core Principles](#1-core-principles)
- [2. Scope](#2-scope)
- [3. Overall Character of the Style](#3-overall-character-of-the-style)
- [4. File Organization](#4-file-organization)
- [5. Braces](#5-braces)
- [6. Indentation and Vertical Rhythm](#6-indentation-and-vertical-rhythm)
- [7. Spacing and Micro-Style](#7-spacing-and-micro-style)
- [8. Naming](#8-naming)
- [9. Types, Declarations, and Qualifiers](#9-types-declarations-and-qualifiers)
- [10. `class` and `struct` Organization](#10-class-and-struct-organization)
- [11. Function Body Style](#11-function-body-style)
- [12. Error Handling](#12-error-handling)
- [13. API Design](#13-api-design)
- [14. Low-Level and Platform-Aware Code](#14-low-level-and-platform-aware-code)
- [15. Resource Management](#15-resource-management)
- [16. Synchronization](#16-synchronization)
- [17. STL Profile](#17-stl-profile)
- [18. Compile-Time and Header-Only Utilities](#18-compile-time-and-header-only-utilities)
- [19. Comments](#19-comments)
- [20. What This Style Dislikes](#20-what-this-style-dislikes)
- [21. Canonical Templates](#21-canonical-templates)
- [22. Rules in MUST / SHOULD / MAY Form](#22-rules-in-must--should--may-form)
- [23. One-Line Summary](#23-one-line-summary)
- [24. Non-Goals](#24-non-goals)
- [25. Portable Maintenance and Verification Rules](#25-portable-maintenance-and-verification-rules) — repository cleanup, generated artifacts, logging, documentation, AI edits, and tests

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
- generated C++ projects;
- projects that need explicit APIs and strong coding discipline.

### 2.1. Language Baseline

The examples assume **C++20** unless a project explicitly documents another baseline. This is required by examples that use facilities such as `consteval`, `std::bit_cast`, `std::span`, and `constinit`.

A C++17 or earlier project may adopt the style, but it must replace unavailable language/library features deliberately instead of emulating them through unrelated macros or unsafe casts.

### 2.2. Rule Precedence

When two rules appear to conflict, apply this order:

1. language correctness and defined behavior;
2. ABI, wire-format, file-format, and external API contracts;
3. security and resource-lifetime correctness;
4. documented project-local rules;
5. the detailed numbered rule in this guide;
6. the quick reference and canonical examples.

`MUST`, `SHOULD`, and `MAY` have their usual normative meaning:

- **MUST** means required unless a higher-precedence contract makes the rule impossible;
- **SHOULD** means the default, with a documented local reason allowed for deviation;
- **MAY** means an explicitly permitted option, not a recommendation for universal use.

A named compiler/platform profile may deliberately accept a documented portability risk, such as a compatibility identifier form in section 2.5. Such an exception never authorizes undefined behavior, an incorrect ABI declaration, or an undocumented expansion of the exception.

### 2.3. Legacy Code and Migration

New files should follow the guide completely. Modified code should follow it within the edited responsibility, but do not combine a behavior change with a repository-wide style rewrite unless the user explicitly asks for both.

Inside one file, preserve a single visual convention. If a legacy file uses west `const`, spaces, or another established shape, either preserve it for a focused behavioral patch or migrate the complete file in a dedicated style-only change. Do not create a mixed intermediate state.

Public APIs, callback signatures, serialized formats, ABI-bound layouts, command-line flags, and generated-file contracts remain stable unless a breaking change is explicitly requested.

### 2.4. Universal and Domain-Specific Rules

Rules that apply to almost any C++ project include:

- braces;
- indentation;
- naming;
- file structure;
- function style;
- error handling;
- ownership;
- comments;
- verification.

Rules that apply only to low-level or platform-aware code should be used only where appropriate:

- `reinterpret_cast`;
- layout-sensitive `struct` / `union`;
- architecture branches;
- raw handles;
- intrinsics;
- SEH;
- byte patches and machine code;
- compile-time literal transformation;
- generated lookup tables;
- fixed-size `constexpr` interpreters/parsers.

### 2.5. Repository Ownership and Compatibility Exceptions

Classify every repository path before applying mechanical style changes:

- **project-owned** source, templates, scripts, and documentation follow this guide;
- **vendored dependency** files are read-only unless an explicit dependency update is requested;
- **protected compatibility** files may be inspected for contracts and examples but are edited only after explicit authorization;
- **generated-only** files are changed through their owning generator whenever that generator is available;
- **binary fixtures and build artifacts** are not text-formatted or rewritten by style tools.

Each project adopting this guide should maintain a short local ownership map that names its vendored dependencies, protected compatibility files, generated-only paths, fixtures, and build/output directories. The map may add narrower exclusions, but it must not silently authorize edits to a dependency or generated artifact. If a diagnostic points into an excluded path, fix the project-owned integration or perform a separately authorized dependency update.

The style-audit and formatter entry points must exclude vendored and protected paths by default. An override may make a protected path visible for diagnosis, but it must never silently authorize modification.

Some projects need a documented compiler, platform, or ABI compatibility profile. Such a profile may permit a narrowly defined ISO-reserved identifier shape when an external contract requires it. This guide's canonical include guard is the documented `_SOMELIBSOMEHEADER_H_` form; the `_TAG` form remains available only for a C-compatible structure typedef such as `typedef struct _TAG { ... } TAG, *PTAG;`.

Do not use a leading underscore followed by an uppercase letter or `__` in ordinary project-owned names. If an external ABI requires another reserved spelling, document that exact exception in the project's compatibility profile and do not broaden it to unrelated identifiers.

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
- a conventional include guard;
- both, only when the project deliberately standardizes on the redundant form;
- compiler-specific pragmas, if they are genuinely needed.

Prefer one project-wide policy. Public or portable libraries should keep a conventional include guard even if `#pragma once` is also used.

Project-owned identifiers must not use reserved forms. In particular, do not create names that contain `__` or begin with `_` followed by an uppercase letter, except for the canonical include guard and the C-compatible `typedef struct _TAG` form documented below. Compiler and platform macros such as `_MSC_VER` and `_M_X64` are external identifiers and are not renamed.

Any reserved-identifier exception must be documented by the project's compatibility profile from section 2.5. It does not permit any other reserved identifier spelling.

This guide's canonical include-guard policy is `_<PROJECT><MODULE><FILE>_H_`, for example `_SOMELIBSOMEHEADER_H_`: concatenate the project, module, and file role in uppercase without separators, and use the `_H_` suffix. A project may also use `#pragma once` when that is part of its documented repository convention, but it must not replace the canonical guard spelling inside a file that uses a conventional guard.

Canonical pattern:

```cpp
#pragma once

#ifndef _SOMELIBSOMEHEADER_H_
#define _SOMELIBSOMEHEADER_H_

...

#endif // _SOMELIBSOMEHEADER_H_
```

Do not omit the leading or trailing underscore from the canonical guard, and do not use a guard name that lacks enough project/module/file context to avoid collisions. Keep the guard spelling identical in `#ifndef`, `#define`, and the closing `#endif` comment.

### 4.2. Include Order

Recommended order:

1. the file's own header;
2. `General` headers: platform, operating-system, compiler, and other non-C/C++/STL dependencies;
3. `C` headers: C runtime and platform C headers that use their C or platform spelling;
4. `C++` headers: C++ language/runtime headers, C++ wrappers for the C library, and core utility facilities;
5. `STL` headers: standard-library containers, algorithms, traits, memory/ownership facilities, character utilities, limits, allocation helpers, and other generic-library facilities;
6. third-party library headers;
7. project-local headers.

Groups must be separated by one blank line and labeled with a short thematic comment. Use the labels `// General`, `// C`, `// C++`, `// STL`, `// Third-party`, and `// Project` when the corresponding groups are present. Keep headers alphabetized inside a group unless dependency order or platform requirements make another order necessary. A temporary configuration define belongs immediately before the include it configures and does not replace the group label.

Use this project classification consistently:

- `// General`: operating-system, compiler, SDK, and non-C/C++ platform headers such as `<Windows.h>`, `<sys/mman.h>`, or a vendor SDK header;
- `// C`: C-runtime and platform-C headers such as `<conio.h>`, `<fcntl.h>`, and `<io.h>`;
- `// C++`: C++ runtime and C-wrapper headers such as `<cerrno>`, `<clocale>`, `<cstdarg>`, `<cstddef>`, `<cstdint>`, `<cstdio>`, and `<utility>`;
- `// STL`: generic standard-library facilities such as `<algorithm>`, `<array>`, `<cctype>`, `<cwctype>`, `<limits>`, `<memory>`, `<new>`, `<string>`, `<type_traits>`, `<unordered_map>`, and `<vector>`.

This classification is project-local and authoritative even when another source informally calls all standard-library headers "STL". Do not use alternative labels such as `// C++ standard library`, `// Standard`, or `// Runtime`. When a header is not listed, classify it by the closest responsibility above and keep the same choice across the repository.

Putting the file's own header first verifies that the header includes everything required by its public declarations.

For a translation unit without its own header, leave the first line empty and start the include block on the following line. For a translation unit with its own header, put that include on the first line and leave the second line empty before the remaining include groups. Do not place a thematic comment, macro, or unrelated declaration before that first-line empty slot or own-header include.

Example:

```cpp
#include "SomeModule.h"

// General
#include <PlatformSdk.h>

// C
#include <conio.h>
#include <fcntl.h>
#include <io.h>

// C++
#include <cerrno>
#include <clocale>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <utility>

// STL
#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

// Third-party
#include <SomeDependency.h>

// Project
#include "Common/Diagnostics.h"
```

For platform headers that require temporary configuration, keep the configuration block inside the `General` group and immediately adjacent to the configured include:

```cpp
// General
#if defined(PLATFORM_NO_LEGACY_NAMES)
#define SOME_MODULE_PLATFORM_NO_LEGACY_NAMES_WAS_DEFINED
#endif
#define PLATFORM_NO_LEGACY_NAMES
#include <PlatformSdk.h>
#if !defined(SOME_MODULE_PLATFORM_NO_LEGACY_NAMES_WAS_DEFINED)
#undef PLATFORM_NO_LEGACY_NAMES
#endif
#undef SOME_MODULE_PLATFORM_NO_LEGACY_NAMES_WAS_DEFINED
#include <PlatformInternals.h>
#include <PlatformProcess.h>
#include <PlatformText.h>
#include <PlatformDebug.h>
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
#undef COMPILETIMESTAMP_USE_64BIT
```

### 4.4. Declaration and Dependency Order

Inside a file, declarations and definitions must follow a readable dependency order. Dependency correctness wins over a rigid category order: a reader should be able to move downward through the file without repeated mental backtracking.

Recommended order after the file header / include guard:

1. include block;
2. include-time configuration defines directly next to the include they configure;
3. temporary compiler/platform macros;
4. type aliases, traits, enums, and layout records;
5. `constexpr` constants and tables before first use;
6. internal/public types that later code depends on;
7. file-scope state with constant or trivial initialization;
8. leaf-level helpers;
9. member and free-function implementations from lower-level to higher-level;
10. orchestration functions and entry points;
11. public macro facades that depend on the typed implementation;
12. `#undef` cleanup for temporary macros.

Rules:

1. Includes come before project constants, objects, and function definitions, except for documented pre-include configuration macros.
2. A macro, type, constant, table, or helper appears before its first dependent use whenever practical.
3. Constants used in array bounds, template arguments, masks, offsets, `static_assert`, and other compile-time contexts must be declared before those uses.
4. If a `constexpr` table is produced by a small `constexpr` leaf helper, the helper may appear immediately before the table.
5. Public header declarations are API contracts, not implementation-order forward declarations, and should stay minimal and stable.
6. Do not use forward declarations, declaration-only aliases, or prototype stubs in project implementation code to bypass dependency order. Define every project-owned type, alias, helper, and function before its first dependent use; if a dependency appears later, reorder the implementation instead. Declaration-only forms are allowed only when required by a public header contract, an external platform/compiler/ABI declaration, or a genuine recursive interface that cannot be expressed by reordering.
7. Member definitions should normally follow the declaration order of the class, unless a private dependency must be placed earlier.
8. Prefer constant initialization for namespace/file-scope objects. Use `constexpr` or `constinit` when applicable.
9. Avoid non-trivial dynamic global initialization. If unavoidable, document initialization order and do not depend on initialization across translation units.
10. Temporary helper macros are undefined immediately after their final required use.

This order reduces accidental reordering mistakes, makes responsibility boundaries visible, and scales better in macro-heavy, systems-heavy, generated, and header-only code.

Correct:

```cpp
int Sum2(const int nA, const int nB) {
	return nA * nB + 1;
}

int Sum(const int nA, const int nB) {
	return Sum2(nA, nB);
}
```

Incorrect:

```cpp
int Sum2(const int nA, const int nB);
int Sum(const int nA, const int nB);

int Sum(const int nA, const int nB) {
	return Sum2(nA, nB);
}

int Sum2(const int nA, const int nB) {
	return nA * nB + 1;
}
```

The allowed exceptions are narrow:

- a public header may forward-declare a type when the declaration is part of the public contract and users need only an incomplete type;
- an external ABI declaration may remain declaration-only when no authoritative platform header can provide it;
- a genuinely recursive interface may use the minimum type forward declaration needed to express the cycle.

Canonical public-header exception:

```cpp
class ProcessContext;

bool AttachProcess(ProcessContext& Context) noexcept;
```

Canonical external-ABI exception when no authoritative platform header provides the declaration:

```cpp
extern "C" LONG WINAPI VendorQuery(HANDLE hProcess, const DWORD unInformationClass, void* pInformation, const DWORD unInformationSize);
```

Canonical recursive-interface exception:

```cpp
class NodeB;

class NodeA {
public:
	explicit NodeA(NodeB* pNode) noexcept;

private:
	NodeB* m_pNode;
};

class NodeB {
public:
	explicit NodeB(NodeA* pNode) noexcept;

private:
	NodeA* m_pNode;
};
```

Keep an external ABI declaration in one compatibility header, copy its calling convention and types exactly, and document why an SDK header cannot be used. None of these exceptions permits a forward prototype for an ordinary project-owned helper whose definition can be reordered.

### 4.5. Section Banners

Large logical blocks inside a file should be separated by section banners.

The separator line must contain exactly 64 `=` or `-` characters after the `// ` prefix. Use the same width for both banner styles.

Use long `=` banners for top-level file or namespace sections:

```cpp
// ================================================================
// Parser
// ================================================================
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

Recommended order:

1. `#pragma once` and/or include guard;
2. include block;
3. include-configuration macros immediately before the include they configure;
4. temporary compiler/platform helper macros;
5. namespace with implementation details;
6. type aliases and fixed-size helper types;
7. compile-time tables and constants before first use;
8. leaf helpers;
9. state structures, byte helpers, classes, and mid-level algorithms;
10. high-level `constexpr` / `consteval` APIs;
11. public macro facade, if needed;
12. `#undef` cleanup;
13. closing include guard.

Temporary compiler helper macros must use a module-specific name and be cleaned up before the end of the header:

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

If a header exposes a macro API, keep the real implementation in typed C++ code and make the public macro a thin facade.

Canonical shape:

```cpp
#pragma once

#ifndef _SOMELIBSOMEUTILITY_H_
#define _SOMELIBSOMEUTILITY_H_

// C++
#include <cstddef>

// STL
#include <bit>
#include <type_traits>

// DependencyConfig
#define DEPENDENCY_USE_FEATURE
#include "Dependency.h"
#undef DEPENDENCY_USE_FEATURE

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

	SOMEUTILITY_FORCE_INLINE constexpr unsigned int RotateLeft(const unsigned int unValue, const unsigned int unBits) noexcept {
		return std::rotl(unValue, static_cast<int>(unBits));
	}

	class Object {
		...
	};

} // namespace SomeUtility

#define SOME_UTILITY(VALUE) ...

#undef SOMEUTILITY_FORCE_INLINE

#endif // _SOMELIBSOMEUTILITY_H_
```

### 4.7. Preprocessor Hygiene

Macros are acceptable in systems-heavy and header-only code, but they must be controlled.

Rules:

1. Use a module-specific prefix for helper macros.
2. Avoid generic helper names such as `FORCE_INLINE`, `NO_INLINE`, `MIN`, `MAX`, or `HASH`.
3. Parenthesize macro arguments and the complete replacement expression where appropriate.
4. Keep multi-line macros visually aligned and easy to scan.
5. Put public facade macros after the typed implementation they invoke.
6. `#undef` temporary helper macros immediately after their final use.
7. Feature switches that configure a dependency appear immediately before the affected `#include`.
8. Do not use macros to replace ordinary typed constants, functions, or templates when those constructs preserve all required information.
9. Never create project-owned identifiers beginning with `_` followed by an uppercase letter or containing `__`, except for the canonical include guard and the documented `typedef struct _TAG` compatibility form.
10. Platform headers that expose colliding macros must be configured or cleaned up deliberately. Prefer the platform's documented feature-selection macros when compatible with the translation unit; otherwise `#undef` only the known colliding names after inclusion.
11. When a platform header defines a function-like macro such as `LoadImage`, `GetObject`, `CreateEvent`, `min`, or `max`, remove the collision before calling a project function with that spelling. Such a macro can rewrite a qualified call and produce a link-time failure.
12. A simple low-level cleanup macro may use a direct guarded statement when its contract is intentionally statement-like. Do not add a `do { ... } while (false)` wrapper merely to normalize such an established macro.
13. Established simple one-value macros may remain macros when they are part of a project-local, command-line, ABI, or platform contract. Do not replace them with `constexpr` solely for presentation.
14. Invoke a direct statement-like macro only as a complete standalone statement inside a braced block. Never attach it directly to an unbraced `if`, `else`, `for`, or `while`, and never embed it in another expression.
15. Every argument passed to a direct cleanup macro must be a stable, side-effect-free value or lvalue. Do not pass an increment/decrement expression, assignment, comma expression, ownership transfer, or function call because the macro may evaluate the argument in both its guard and cleanup call.
16. A direct cleanup macro must contain one obvious guard and one cleanup action. If it needs branching beyond that contract, several independent statements, a return, or ownership transfer, replace it with a typed helper or RAII owner.
17. Keep `#elif`, `#else`, and `#endif` directly adjacent to the preceding line of their preprocessor branch. Do not insert a blank line before these directives; a blank line may follow a closing `#endif` when it separates the next phase.

Correct:

```cpp
#define SOMEUTILITY_VALUE(INDEX) ((INDEX) + 1)

#undef SOMEUTILITY_VALUE
```

Incorrect:

```cpp
#define VALUE(i) i + 1
```

Canonical direct cleanup macro:

```cpp
#define SOME_SAFE_CLOSE_HANDLE(X)               \
	if ((X) && ((X) != INVALID_HANDLE_VALUE)) { \
		CloseHandle(X);                         \
	}
```

Correct use passes a stable handle and keeps the invocation in a braced block:

```cpp
if (bRelease) {
	SOME_SAFE_CLOSE_HANDLE(hProcess);
}
```

Incorrect use passes an expression with side effects or relies on the macro as an unbraced branch body:

```cpp
SOME_SAFE_CLOSE_HANDLE(GetNextHandle());

if (bRelease)
	SOME_SAFE_CLOSE_HANDLE(hProcess);
```

### 4.8. Internal Linkage

In a `.cpp` file, prefer an anonymous namespace for project-owned C++ types, templates, constants, objects, and helper functions that must not leave the translation unit. Use `static` only when C linkage, a platform signature, or established project convention makes it clearer.

Do not add an anonymous namespace solely around one helper function when it provides no additional grouping or required visibility restriction. Define that function directly at file scope.

Do not place an anonymous namespace in a header. It creates a separate entity in every translation unit and can silently change type identity or storage behavior.

Close an anonymous namespace with:

```cpp
} // namespace
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

For a function or method with a constructor initializer list, keep the colon on the same line as the complete signature, break the line immediately after the colon, and put every initializer on its own following line with one tab of continuation indentation. Place the opening `{` on its own line after the complete initializer list. Keep one initializer per line and place the comma after every initializer except the last one. Do not attach the opening brace to the final initializer expression.

Correct:

```cpp
if (!pAddress) {
	return false;
}

bool SomeClass::Set(void* pAddress) {
	...
}

SomeType::SomeType(void* const pAddress, const std::size_t unSize) :
	m_pAddress(pAddress),
	m_unSize(unSize)
{
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

### 5.4. Switch Case Indentation

`case` and `default` labels are indented one level inside the `switch`. The label sits alone on its line: the case body goes on the following line(s), indented one more level. The only token that may follow the label colon is an opening `{` that introduces a case-local block scope. Put a blank line between non-empty case blocks.

Correct:

```cpp
switch (KindInfo) {
	case Kind::A:
		return 1;

	case Kind::B: {
		const int nValue = Compute();
		return nValue;
	}

	default:
		return 0;
}
```

Incorrect (compact body sharing the label line):

```cpp
switch (KindInfo) {
	case Kind::A: return 1;
	case Kind::B: return 2;
	default: return 0;
}
```

---

## 6. Indentation and Vertical Rhythm

### 6.1. Indentation

Use tabs as the primary indentation unit.

Spaces may be used for local visual alignment inside tables, macro blocks, or bit layouts, but indentation itself is tab-based for code and script files. Markdown prose, lists, and tables use spaces for indentation, while fenced code blocks inside `*.md` must use tabs for code indentation.

### 6.2. Blank Lines

Use one blank line to separate completed phases, responsibilities, declarations, and failure modes:

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

Put a blank line before an `if` when it follows a completed declaration, assignment, stream emit, function call, or other statement.

Do not put a blank line when one local variable is declared or assigned and the immediately following statement is the only direct operation that consumes, validates, or iterates over that value. This includes an `if`, a `for`, or one direct call/assignment that performs that operation. Treat the declaration/assignment and its direct operation as one compact phase:

```cpp
HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, unParentPID);
if (!hParentProcess || (hParentProcess == INVALID_HANDLE_VALUE)) {
	hParentProcess = nullptr;
}

NTSTATUS nStatus = NtResumeProcess(hProcess);
if (!NT_SUCCESS(nStatus)) {
	return false;
}

LINK_DATA LinkData {};
if (!UnlinkModule(pLoaderData, pDTE, &LinkData)) {
	return false;
}
```

When an early-exit branch ends with one simple action followed by a simple one-line return, treat both statements as one compact terminal phase. Keep the return directly adjacent to that call, assignment, declaration, diagnostic, cleanup, or other single action. This applies to `return;`, `return true;`, `return false;`, `return {};`, and `return Expression;` when the return itself remains one physical line. Do not insert a blank line between the final action and the early return.

The function's main path still follows phase separation. A final output/result commit and the final success return are separate phases, so put one blank line between them. Do not apply the compact early-exit rule merely because only one assignment precedes the function's final return.

Correct:

```cpp
if (strName.empty()) {
	ThrowError(pIsolate, kInvalidNameErrorMessage);
	return false;
}

strValueOut = std::move(strValue);

return true;
```

Incorrect:

```cpp
if (strName.empty()) {
	ThrowError(pIsolate, kInvalidNameErrorMessage);

	return false;
}
```

A blank line separates any completed main-path phase from the function's final return, including a one-statement output/result commit. Inside an early-exit branch, the compact action-and-return rule above takes precedence.

Do not add a blank line when the `if` is:

- the first statement directly after `{`;
- directly after a `case:` or `default:` label;
- the `if` in an `else if` chain;
- part of a compact cleanup sequence deliberately documented as one phase.

Do not put a blank line between `}` and a syntactically attached `else`, `catch`, `while`, or required semicolon.

A standalone closing `}` that completes a block and is followed by an ordinary statement, declaration, or expression at the same or an outer readable phase must be followed by exactly one blank line. This makes the end of the completed block visually distinct from the code that follows it. Do not require this blank line when the next non-empty line begins with another closing `}`, `else`, `catch`, `while`, a required semicolon, or a preprocessor directive; these forms either continue/close the surrounding syntax or belong to the preprocessor structure.

Correct:

```cpp
if (!pNextAddress || (pNextAddress == pCurrentAddress)) {
	return nullptr;
}

pCurrentAddress = pNextAddress;
```

Incorrect:

```cpp
if (!pNextAddress || (pNextAddress == pCurrentAddress)) {
	return nullptr;
}
pCurrentAddress = pNextAddress;
```

When a branch of an outer `if`/`else if`/`else` chain is complete and the attached outer `else` starts a new phase, put one blank line immediately before the outer `} else if` or `} else`. The blank line may follow a completed nested block or the branch's final statement. Keep `} else if` and `} else` syntactically attached without a blank line between `}` and `else`:

```cpp
if (pDTE->DllBase < pCurrentDTE->DllBase) {
	if (pCurrent->Left) {
		pCurrent = pCurrent->Left;
		continue;
	}

	pParent = pCurrent;
	bRight = FALSE;
	break;

} else if (pDTE->DllBase > pCurrentDTE->DllBase) {
	if (pCurrent->Right) {
		pCurrent = pCurrent->Right;
		continue;
	}

	pParent = pCurrent;
	bRight = TRUE;
	break;
}
```

Put one blank line between a `constexpr` / `static constexpr` constant or table and the following `static_assert`. Consecutive `static_assert` lines validating one constant group may remain adjacent.

Local `constexpr` constants and tables belong at the beginning of a function body, before ordinary local variables or executable code. Keep consecutive local `constexpr` declarations together, then put one blank line before the first ordinary statement.

Put one blank line between ordinary local variables and a following stream object, and one blank line after declaring the stream object before writing into it:

```cpp
std::string const strName = ShortenIdentifier(strRawName, 48);

std::ostringstream OutputStream;

OutputStream << "Rewrite_" << unIndex << "_" << strName;
```

A short cleanup block may remain dense when every line belongs to one action:

```cpp
std::error_code ErrorCode;
std::filesystem::remove(PathLog, ErrorCode);
return 0;
```

Never use two consecutive blank lines in source or script files.

### 6.3. Line Length

There is no tiny hard line limit.

Prefer readable wrapping over forced short lines. Long signatures are acceptable when they make types, ownership, or ABI visible.

Line length alone is not a reason to split an otherwise simple declaration or call. Auditability, nested expression depth, and the number of distinct logical parts determine whether wrapping is needed; do not impose an arbitrary formatter column limit on project code.

Wrap when a line becomes hard to scan, especially in:

- long template expressions;
- macro bodies;
- boolean conditions;
- arithmetic formulas;
- bit manipulation expressions.

### 6.4. One-Line Expression Shape

Keep ordinary function declarations, function calls, constructor calls, ternary expressions, boolean returns, stream chains, and initializer records on one physical line while they remain easy to scan. Do not split a simple expression only because it has several arguments.

A call remains on one physical line when its arguments are only names, constants, member accesses, casts, or other short expressions and the call has no multi-line lambda, aggregate, or nested condition. This includes ordinary atomic operations, getters/setters, logging calls with a short payload, and standard algorithms with a named predicate.

In particular, keep a simple method call with a small fixed argument list on one line:

```cpp
State.m_unActiveWorkerSlot.store(kInvalidWorkerSlot, std::memory_order_release);
```

Do not expand such a call into one argument per line merely to make the call appear shorter.

The same rule applies to short boolean predicates and boolean returns. Keep the complete function signature on one line. A chain of simple pointer checks, atomic loads, comparisons, and logical operators may wrap at logical operators when the complete expression is long, but each direct operand and each simple `load`, `store`, `exchange`, or comparison call must remain intact on one physical line. Do not split inside a simple call merely to align its arguments.

When a boolean expression is long enough to wrap, preserve its grouping explicitly. Break at top-level logical operators and keep nested `&&` / `||` groups parenthesized so the reader does not need to reconstruct precedence. Parenthesize a direct operand only when it is itself a comparison or nested logical/arithmetic expression whose grouping must remain explicit. Do not add an outer pair of parentheses around a simple boolean name, pointer check, unary-negation check, or function-call result merely because it is a direct operand: write `!m_pState`, not `(!m_pState)`, including on a continuation line. Continuation lines use one additional tab of indentation. Formatting must not change the expression's semantics.

Correct simple direct operands:

```cpp
if (!m_pState || !m_pFrame || (m_State.load(std::memory_order_acquire) != State::OWNED)) {
	return false;
}
```

Correct nested logical groups:

```cpp
if (((bReady && bHasData) || bForced) &&
	(!bCancelled || bTimedOut)) {
	return true;
}
```

Incorrect:

```cpp
if (bReady && bHasData || bForced && !bCancelled || bTimedOut) {
	return true;
}
```

Incorrect:

```cpp
bool IsPendingOperationSlotResettable(
	PendingOperationSlot const* const pSlot) noexcept {
	return pSlot &&
		!pSlot->m_pOwner.load(std::memory_order_seq_cst) &&
		!pSlot->m_pSnapshot.load(std::memory_order_seq_cst) &&
		!pSlot->m_bReferenceOwned.load(std::memory_order_acquire) &&
		(pSlot->m_unOperationJournalState.load(
			std::memory_order_acquire) ==
			OperationJournalState::None);
}
```

Correct:

```cpp
bool IsPendingOperationSlotResettable(PendingOperationSlot const* const pSlot) noexcept {
	return pSlot &&
		!pSlot->m_pOwner.load(std::memory_order_seq_cst) &&
		!pSlot->m_pSnapshot.load(std::memory_order_seq_cst) &&
		!pSlot->m_bReferenceOwned.load(std::memory_order_acquire) &&
		(pSlot->m_unOperationJournalState.load(std::memory_order_acquire) == OperationJournalState::None);
}
```

Incorrect:

```cpp
void ResetPendingOperationSlot(PendingOperationSlot* const pSlot) noexcept {
	if (!IsPendingOperationSlotResettable(pSlot)) {
		return;
	}

	pSlot->m_bActive.store(false, std::memory_order_release);
	pSlot->m_bCompleting.store(false, std::memory_order_release);
	pSlot->m_pGroupOwner.store(nullptr, std::memory_order_release);
	pSlot->m_Operation = PendingOperation {};
	pSlot->m_nOwnerID.store(0, std::memory_order_release);
	CloseOperationHandle(
		pSlot->m_nOwnerHandle.exchange(
			-1, std::memory_order_acq_rel));
}
```

Correct:

```cpp
void ResetPendingOperationSlot(PendingOperationSlot* const pSlot) noexcept {
	if (!IsPendingOperationSlotResettable(pSlot)) {
		return;
	}

	pSlot->m_bActive.store(false, std::memory_order_release);
	pSlot->m_bCompleting.store(false, std::memory_order_release);
	pSlot->m_pGroupOwner.store(nullptr, std::memory_order_release);
	pSlot->m_Operation = PendingOperation {};
	pSlot->m_nOwnerID.store(0, std::memory_order_release);
	CloseOperationHandle(pSlot->m_nOwnerHandle.exchange(-1, std::memory_order_acq_rel));
}
```

Wrap a call only when one or more arguments contain a genuinely complex nested expression, multi-level member traversal, an inline lambda or aggregate, or another structure that is easier to verify vertically. A long format string alone is not a reason to wrap a logging call whose values are direct names, constants, casts, or short ternaries. When wrapping is necessary:

1. break after the opening `(` or at a clear outer-expression boundary;
2. indent continuation lines with one tab rather than spaces aligned to the opening parenthesis;
3. keep short, logically related arguments together when that improves scanning;
4. do not place every trivial argument on its own line by default;
5. keep the closing `);` on the final argument line unless the final argument is itself a multi-line block or expression.

Correct wrapped call:

```cpp
LogError(
	_T("Loader exception FirstChance=%s Code=0x%08X Address=%p ThreadID=%lu"),
	ExceptionInfo.dwFirstChance ? _T("true") : _T("false"), ExceptionInfo.ExceptionRecord.ExceptionCode,
	ExceptionInfo.ExceptionRecord.ExceptionAddress, unThreadID);
```

The wrapped form is an exception for a complex payload. Do not apply it to calls such as `store`, `load`, `exchange`, `std::move`, `std::forward`, or an iterator lookup with a named predicate when those calls remain simple.

Function declarations and definitions in project C/C++ code must keep the complete signature, including all parameters, on one physical line. Do not place each parameter on a separate line, even when the signature is long. Preserve the opening `{` on that same line for ordinary functions; the constructor initializer-list exception in section 5.1 remains applicable.

Correct:

```cpp
BuildResult BuildProject(ProjectInfo const& Project, BuildOptions const& Options, ToolchainInfo const& Toolchain);
const int nSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, strText.data(), static_cast<int>(strText.size()), nullptr, 0);
return StartsWith(strLower, "error") || StartsWith(strLower, "warning") || (strLower == "done") || (strLower == "skipped");
RecordInfo.m_unOrdinal = (ExportInfo.m_unOrdinal == 0) ? AllocateOrdinal(setOrdinals, unNextOrdinal) : ExportInfo.m_unOrdinal;
```

Incorrect:

```cpp
const int nSize = MultiByteToWideChar(
	CP_UTF8,
	MB_ERR_INVALID_CHARS,
	strText.data(),
	static_cast<int>(strText.size()),
	nullptr,
	0);
```

Wrap when the complete expression becomes difficult to audit. For boolean and arithmetic expressions, break at operators and keep related operands together. Do not put one trivial argument per line by default.

### 6.5. Streams and Generated Text

When a stream constructs multi-line generated text, place the stream object on its own line and each logical emitted line or fragment on its own `<<` line. Emit blank lines explicitly so the generated shape is visible in the generator:

```cpp
OutputStream
	<< "#pragma once\n"
	<< "\n"
	<< "#ifndef " << szGuardName << "\n"
	<< "#define " << szGuardName << "\n";
```

Do not hide a leading blank line inside a literal shaped like `"
...text...
"`. Emit the blank line and text as separate chunks. A final `"

"` chunk is acceptable when it terminates the chain.

Generated C++ must still follow the same one-line expression, indentation, naming, and brace rules as hand-written C++.

---

## 7. Spacing and Micro-Style

### 7.1. Space Before `{`

Use one space before `{`:

```cpp
if (bReady) {
```

### 7.2. Space After Keywords

Use one space after control-flow keywords:

```cpp
if (...)
for (...)
while (...)
switch (...)
```

### 7.3. Inside Parentheses

Do not add spaces just inside parentheses.

Correct:

```cpp
if (pAddress && unSize) {
```

Incorrect:

```cpp
if ( pAddress && unSize ) {
```

### 7.4. Around Operators and Punctuation

Use spaces around ordinary binary and assignment operators:

```cpp
unOffset = unBase + unIndex * 4;
```

Do not put a space before `,`, `;`, `)`, `]`, or `}`. Put one space after a comma in ordinary expressions and declarations.

Keep unary operators attached to their operand:

```cpp
++unIndex;
--unCount;
!bReady;
*pAddress;
&pObject;
```

### 7.5. Extra Parentheses

Extra parentheses are allowed and often useful when:

- bitwise logic is involved;
- macro expressions are involved;
- addresses, offsets, or ranges are involved;
- operator precedence should be visually frozen.

For a wrapped expression, these parentheses are required when they preserve a comparison, arithmetic operand, or nested logical group. They are not required around a simple boolean name, pointer check, unary-negation check, or function call. Do not rely on the precedence relationship between `&&` and `||` in a large expression, and do not remove meaningful grouping parentheses merely because the compiler accepts the shorter form.

Simple expressions should not be wrapped only for decoration. Do not add parentheses around a simple arithmetic expression when its precedence is already clear: use `const std::uint64_t unEnd = unBegin + unSize;`, not `const std::uint64_t unEnd = (unBegin + unSize);`. Likewise, use `if (!pValue)` rather than `if ((!pValue))`, and write a wrapped operand as `!pValue ||`, not `(!pValue) ||`.

Call qualified standard algorithms directly. Use `std::max(...)` and `std::min(...)`; do not wrap the qualified function name as `(std::max)(...)` or `(std::min)(...)`. If a platform header defines a colliding function-like macro, resolve that collision at the include boundary or with the narrow preprocessor cleanup permitted by section 4.7.

When a comparison contains arithmetic on one side, parenthesize the arithmetic part:

```cpp
if (unEntryOffset > (std::numeric_limits<std::uint32_t>::max() - 5)) {
	return false;
}
```

For ternary expressions:

1. direct ternaries use no outer parentheses around a simple flag, member, or function-call condition;
2. simple function-call results are not wrapped;
3. comparison, logical, or arithmetic conditions are grouped before `?`;
4. arithmetic result arms are grouped;
5. if the complete ternary is embedded inside another expression, group the complete ternary;
6. keep inner arithmetic grouping where it clarifies precedence.

```cpp
return m_bUnicode ? kUnicodeFrames[unFrame] : kAsciiFrames[unFrame];
const std::size_t unGap = (unSafeColumns > (unLineColumns + unElapsedColumns)) ? (unSafeColumns - unLineColumns - unElapsedColumns) : 1;
std::string const strSize = std::to_string(unSize) + ((unSize == 1) ? " byte" : " bytes");
const std::uint64_t unEnd = (unRangeEnd <= unRangeBegin) ? std::min(unLimitEnd, unRangeBegin + 1) : unRangeEnd;
```

### 7.6. Numeric Literals

Choose the spelling that communicates the domain:

- decimal for ordinary counts, time values, and user-facing quantities;
- hexadecimal for addresses, offsets, masks, opcodes, byte values, and binary layouts;
- binary only when the individual bit pattern is the point;
- octal only for an external format that conventionally requires it, such as POSIX permission notation.

Use uppercase hexadecimal digits consistently: `0xFF`, `0x7FFF`, `0xDEADBEEF`.

Use digit separators for long values when they improve grouping: `1'000'000`, `0xFFFF'FFFF`.

Do not use integer-literal suffixes such as `U`, `UL`, `ULL`, `L`, `u`, `ul`, `ull`, or `l` when they are redundant. If the code materially requires a suffix because the literal type affects correctness, range, overload resolution, shifting, ABI behavior, or constant evaluation, document that reason locally and prefer a named typed constant or explicit construction when it keeps the intent clearer:

```cpp
constexpr std::uint64_t kHighBit = std::uint64_t(1) << 63;
```

When an explicitly typed scalar literal is used as an arithmetic operand, prefer functional-style construction such as `std::uint32_t(1)` rather than a one-expression braced construction such as `std::uint32_t{1}`. Reserve braces for object/list initialization and default initialization.

An integer-literal suffix is therefore allowed only when the code requires its type or value behavior; decorative suffixes are forbidden. Floating-point precision suffixes and externally required API spellings are separate semantic cases and remain allowed when required by the contract.

Do not use unexplained magic numbers. Give repeated values, limits, masks, offsets, timeouts, and protocol constants a semantic `constexpr` name.

### 7.7. Initialization and Null Values

Prefer brace initialization for zero/default initialization and when narrowing must be rejected:

```cpp
PROCESS_HEAP_ENTRY HeapEntry {};
std::array<unsigned char, 32> arrKey {};
```

Do not use a one-expression brace initializer merely as an alternative spelling for copying or converting a value. When copy-initialization is valid and preserves the intended construction, use the `=` form from section 7.9.

Use `nullptr` for null pointers, `false` for C++ booleans, and `0` for numeric zero. Use `NULL`, `TRUE`, and `FALSE` only at an external API boundary where those spellings are required or improve consistency with the platform signature.

Do not use `memset` to construct non-trivial C++ objects. Zeroing a raw byte buffer or an explicitly verified trivial layout is allowed.

### 7.8. Initialization Before Use

Every variable, pointer, array, structure, class object, and member must have a defined state before its first read, call, dereference, or other use. Prefer initializing an object in its declaration:

```cpp
const int nCount = 0;
float flRatio {};
void* pAddress = nullptr;
PROCESS_INFORMATION ProcessInformation {};
SOME_RECORD Record {};
SomeObject Object {};
```

Do not rely on indeterminate storage:

```cpp
int nCount;
SOME_RECORD Record;
SomeObject Object;
```

If an API or a staged operation requires declaration before assignment, assign the object on every control-flow path before any read or use. Check the assignment or construction result before continuing. A declaration without an initializer is allowed only when the next valid operation establishes the state before any possible use.

Every ordinary class or structure constructor must establish a valid state for every member on every successful construction path. A member must be initialized by a constructor initializer list, assigned in the constructor body, or be a type whose own construction guarantees a valid state. Do not leave scalar members, pointers, handles, arrays, or nested records indeterminate.

For ABI, serialized, mapped-layout, and other contract-sensitive records that cannot have a user-provided constructor, use value initialization at the declaration or an explicit initialization helper before the record is read. See section 10.4.

### 7.9. Copy and Conversion Initialization

When a variable or object is initialized from one existing expression, use copy-initialization whenever `Type Name = Expression;` is well-formed and selects the intended construction. This rule applies to values of the same type, conversions through a non-`explicit` constructor, factory and function results, handles, strings, containers, wrappers, and other copyable or conversion-initializable objects.

Correct:

```cpp
v8::Local<v8::Object> const LocalShatterSurfaceObject = v8::Object::New(pIsolate);
std::string const strName = szName;
SomeValue Value = BuildValue();
```

Incorrect:

```cpp
v8::Local<v8::Object> const LocalShatterSurfaceObject { v8::Object::New(pIsolate) };
std::string const strName(szName);
SomeValue Value(BuildValue());
```

Do not use `Type Name { Expression };` or `Type Name(Expression);` as an alternative visual style for a copy or conversion that can use `=`. This includes declarations whose initializer is a function call, factory result, cast, member access, indexed value, dereferenced value, or another named object.

Keep `{}` for zero/default/value initialization. Direct or list initialization remains permitted only when copy-initialization is ill-formed or would change the intended semantics, such as an `explicit` constructor, required narrowing rejection, a genuine aggregate or initializer-list construction, or another overload-resolution contract. Constructor initializer lists follow section 10.3. Do not mechanically replace these semantically distinct cases with `=`.

### 7.10. Empty Return Value Initialization

In a function with an explicit return type, use an untyped empty braced return when the result must be value-initialized:

Correct:

```cpp
return {};
```

Incorrect:

```cpp
return v8::Local<v8::Object> {};
return v8::Local<v8::Object>();
```

The function signature already establishes the result type. Do not repeat that type solely to construct an empty return value. This rule applies to every explicitly typed return value for which `return {};` is well-formed and has the intended semantics, not only to `v8::Local<...>`. If the function uses a language-required deduced return type or `return {};` would be ill-formed or select different semantics, use the narrow expression required by that contract.

---

## 8. Naming

### 8.1. General Principle

Names should be semantic, stable, predictable, and searchable. A reader should understand the role without guessing the underlying category.

Use **systems Hungarian notation** for scalar values, pointers, handles, buffers, raw strings, and common containers. After the prefix, use a `PascalCase` tail:

For a pointer to a primitive scalar value, combine `p` with the scalar's ordinary prefix: `pn...`, `pun...`, `pb...`, `pfl...`, `pdbl...`, `pch...`, or `pwch...`. Use `sz...` for a null-terminated string value or fixed C-string buffer and `psz...` for a pointer to a null-terminated string or to a character range within one.

Use the bare `p...` prefix when the pointee is an object, class, structure, union, enum, user-defined/non-primitive type, opaque platform type, or untyped `void` storage. Do not append an artificial type abbreviation to such pointers: the PascalCase tail describes the semantic role.

```cpp
m_unSize
m_pAddress
unOffset
pRecord
punCount
pflScale
szModuleName
pszModuleName
strOutput
vecBytes
```

Domain value objects whose type already carries the category may use a semantic PascalCase role name instead of an artificial prefix:

```cpp
BuildOptions const& Options
std::filesystem::path const PathOutput
std::error_code ErrorCode
ProjectInfo const& Project
```

Do not repeat the complete type name as the variable name when a shorter role is clearer. Do not invent a meaningless prefix merely to satisfy the table.

### 8.2. Basic Prefixes

| Prefix | Meaning | Examples |
| --- | --- | --- |
| `m_` | class/struct member, followed by the category prefix | `m_pAddress`, `m_bActive` |
| `g_` | namespace/file-scope mutable state | `g_Storage`, `g_Suspender` |
| `s_` | function-local static state | `s_unGeneration` |
| `k` | named `constexpr` constant only | `kPageSize`, `kMaxRecords` |
| `p` | pointer to an object, user-defined/non-primitive type, opaque type, or `void` storage | `pRecord`, `pContext`, `pAddress` |
| `pp` | pointer-to-pointer to an object, opaque type, or `void` storage when the indirection is part of the API | `ppRecordOut`, `ppContextOut` |
| `pn` | pointer to a signed integer | `pnResult`, `pnOffsetOut` |
| `pun` | pointer to an unsigned integer, size, count, index, or identifier | `punSize`, `punCountOut` |
| `pb` | pointer to a C++ boolean | `pbSuccess`, `pbEnabledOut` |
| `pfl` | pointer to a `float` value | `pflScale`, `pflValueOut` |
| `pdbl` | pointer to a `double` value | `pdblDistance`, `pdblValueOut` |
| `pch` | pointer to a narrow character or non-string character storage | `pchCharacter`, `pchData` |
| `pwch` | pointer to a wide character or non-string wide-character storage | `pwchCharacter`, `pwchData` |
| `psz` | pointer to a null-terminated C string or character range | `pszArgument`, `pszCurrentString` |
| `ppn` / `ppun` | pointer-to-pointer to a signed / unsigned integer category | `ppnResultOut`, `ppunCountOut` |
| `ppb` | pointer-to-pointer to a C++ boolean | `ppbEnabledOut` |
| `ppfl` / `ppdbl` | pointer-to-pointer to a `float` / `double` | `ppflScaleOut`, `ppdblRatioOut` |
| `ppch` / `ppwch` | pointer-to-pointer to narrow / wide character storage | `ppchDataOut`, `ppwchDataOut` |
| `ppsz` | pointer-to-pointer to a null-terminated C string or character range | `ppszNameOut`, `ppszArguments` |
| `un` | unsigned integer, size, count, index, identifier | `unSize`, `unOffset`, `unIndex` |
| `n` | signed integer | `nResult`, `nBufferSize` |
| `b` | C++ boolean | `bSuccess`, `bNative` |
| `fl` | `float` value | `flScale`, `flOpacity` |
| `dbl` | `double` value | `dblDistance`, `dblRatio` |
| `h` | operating-system or library handle | `hThread`, `hModule` |
| `ch` | narrow character | `chSeparator`, `chOpcode` |
| `wch` | wide character | `wchSeparator` |
| `sz` | null-terminated C string or fixed C-string buffer | `szName`, `szModuleName` |
| `str` | owning string | `strName`, `strOutput` |
| `wstr` | owning wide string | `wstrPath` |
| `strv` | non-owning string view | `strvToken`, `strvName` |
| `vec` | vector-like dynamic sequence | `vecPages`, `vecResults` |
| `arr` | fixed-size array or `std::array` | `arrBytes`, `arrRegisters` |
| `spn` | non-owning contiguous `std::span` | `spnBytes`, `spnRecords` |
| `map` | map-like associative container | `mapModules`, `mapSymbols` |
| `set` | set-like associative container | `setOrdinals`, `setNames` |
| `it` | iterator, followed by its role | `itRecord`, `itModule` |
| `fn` | function pointer type alias or callback object role | `fnCallBack`, `fnThreadProc` |

The pointer prefix describes both indirection and the primitive pointee category. Do not drop the pointee category from a primitive pointer: use `punCount`, not `pCount`, and `pflScale`, not `pScale`. Conversely, do not encode a class or custom type name into the prefix: use `pRecord` for `RECORD*` and `pWidget` for `Widget*`, not `pRecordType` or `pWidgetObject`.

For every additional pointer level, repeat `p` before the same primitive or string category when that indirection is part of the API: `ppnResultOut`, `ppunCountOut`, `ppbEnabledOut`, `ppflScaleOut`, `ppdblRatioOut`, `ppchDataOut`, `ppwchDataOut`, and `ppszArguments`. The rule continues recursively for deeper indirection: for example, an `unsigned int***` uses `pppun...`. A pointer-to-pointer to an object or custom type uses bare repeated `p`, such as `ppRecordOut`; a third level uses `pppRecordOut`.

Canonical examples:

```cpp
int* pnResult = nullptr;
unsigned int* punCount = nullptr;
float* pflScale = nullptr;
double* pdblRatio = nullptr;
bool* pbEnabled = nullptr;
TCHAR const* pszName = nullptr;
unsigned int** ppunCountOut = nullptr;
bool** ppbEnabledOut = nullptr;
double** ppdblRatioOut = nullptr;
TCHAR const** ppszNameOut = nullptr;
Widget* pWidget = nullptr;
std::string* pText = nullptr;
CUSTOM_RECORD* pRecord = nullptr;
CUSTOM_RECORD** ppRecordOut = nullptr;
void* pContext = nullptr;
```

For example, both the string parameter and a pointer that walks through it use `psz...`:

```cpp
TString QuoteCommandLineArgument(TCHAR const* const pszArgument) {
	for (TCHAR const* pszCharacter = pszArgument; *pszCharacter; ++pszCharacter) {
		// Process the string character by character.
	}
}
```

Do not use a bare `it`, `i`, `j`, `buf`, `ctx`, or `idx` in project-owned code when a complete role name remains practical.

External ABI fields, generated schema names, public command-line flags, and standard domain abbreviations keep their required spelling.

### 8.3. Extended Member Prefixes

For members, retain the same pointee-category composition after `m_`:

- `m_p...` - pointer to an object, user-defined/non-primitive type, opaque type, or `void` storage
- `m_pn...` / `m_pun...` - pointer to a signed / unsigned integer category
- `m_pb...` - pointer to a C++ boolean
- `m_pfl...` / `m_pdbl...` - pointer to a `float` / `double`
- `m_pch...` / `m_pwch...` / `m_psz...` - character / wide-character / C-string pointer
- `m_ppn...` / `m_ppun...` / `m_ppb...` / `m_ppfl...` / `m_ppdbl...` / `m_ppch...` / `m_ppwch...` / `m_ppsz...` - pointer-to-pointer to the corresponding primitive or string category
- `m_un...` - unsigned / size / count / id
- `m_n...` - signed integer
- `m_b...` - bool
- `m_h...` - handle
- `m_sz...` - C-string buffer
- `m_str...` / `m_wstr...` - owning string
- `m_vec...` / `m_arr...` - sequence storage
- `m_spn...` - non-owning contiguous view
- `m_map...` / `m_set...` - associative container

Examples:

```cpp
m_pWrapper
m_punSize
m_pflScale
m_pszName
m_ppunSizeOut
m_ppbEnabledOut
m_ppdblRatioOut
m_ppszNameOut
m_unOriginalBytes
m_bInitialized
m_hEvent
m_szPipeName
```

### 8.4. Type Names

Type names commonly take one of two forms:

- `PascalCase` for ordinary C++ classes: `Object`, `Event`, `Storage`, `Protection`
- `UPPER_CASE` or C-style for ABI/layout types: `LINK_DATA`, `RAW_CONTEXT64`, `BUFFER_VIEW_RECORD`

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
- `Load...`
- `Save...`
- `Reset...`
- `Dump...`

Historical forms such as `UnLock`, `DeAlloc`, and `ReLink` are acceptable if they are part of a project's established convention.

If a project treats `Re...` as two visible words in PascalCase identifiers or generated filenames, apply that convention consistently: `ReBuild`, `ReLink`, `ReLoad`, and `VerifyReBuild.cpp`. Lower-case ordinary words such as `rebuild`, `rebuilt`, and paths like `build/rebuilt` stay lower-case.

### 8.6. Compile-Time Constants

`constexpr` constants use the `k` prefix with a `PascalCase` tail.

The `k` prefix is reserved only for named `constexpr` constants. Do not use `k` for ordinary variables, non-`constexpr` `const` objects, macros, enum values, non-`constexpr` globals, non-`constexpr` members, function parameters, template parameters, `constexpr` functions, or `consteval` functions.

Correct:

```cpp
constexpr std::size_t kMaxRecords = 64;
constexpr unsigned int kPageSize = 0x1000;
constexpr unsigned char kBaseKey[32] {};

char szBuffer[kMaxRecords] {};
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
constexpr bool kIsSpace(const char chValue);
template <std::size_t kLength> class Buffer;
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

Template value parameters use the same semantic prefixes as ordinary variables:

```cpp
template <std::size_t unLength, typename T, std::uint64_t unLine, std::uint64_t unCounter>
class SomeCompileTimeObject {
	...
};
```

Type parameters use short semantic PascalCase names such as `T`, `TValue`, `TRecord`, or `TAllocator`. A single `T` is acceptable for a genuinely generic one-type utility; use a role name when several type parameters appear.

Type aliases normally use `PascalCase`:

```cpp
template <typename T>
using CleanType = std::remove_const_t<std::remove_reference_t<T>>;
```

An internal alias may deliberately use an STL-like lower-case name only when it behaves like a tiny type trait and remains inside a narrow `Detail` namespace:

```cpp
namespace Detail {

	template <typename T>
	using clean_type = std::remove_const_t<std::remove_reference_t<T>>;

} // namespace Detail
```

Do not expose STL-like lower-case aliases as broad public project types unless the whole project intentionally follows that convention.

### 8.9. Acronyms, Enums, and State Names

Keep standard acronyms uppercase where that improves recognizability:

```cpp
GetCPUInfo
DumpRTTI
CRC32
AESState
JSONReader
HTTPClient
IsX64
```

Project and domain abbreviations stay uppercase inside identifiers: `CPU`, `ABI`, `API`, `IO`, `HTTP`, `JSON`, `XML`, `TLS`, `SIMD`, `CRC`, `AES`, `RVA`, and `PE`.

Do not write mixed-case acronym fragments such as `JsonReader` or `HttpClient` when the project uses uppercase acronyms. Lower-case external spellings such as `x86_64`, `.json`, JSON keys, and command-line flags keep their external form.

Enum types that model instructions, stages, CPU operations, protocol values, or ABI states may use compact uppercase names when that matches the domain:

```cpp
enum class OP : unsigned char {
	ADD = 0,
	SUB,
	INVALID
};
```

Rules for project-owned enums:

1. use `enum class` unless an external ABI requires an unscoped enum;
2. initialize only the first ordinary value to zero and let later sequential values auto-increment;
3. assign every value explicitly when the numeric representation is an external contract or intentionally sparse;
4. use a stable `INVALID`, `UNKNOWN`, or `NONE` value when callers need a failure/sentinel state;
5. do not serialize a convenience `COUNT` value unless it is part of the documented format;
6. use explicit bitmask values for flag enums and provide typed operators instead of implicit integer mixing.

### 8.10. Generated File and CLI Naming

Generated artifacts must be deterministic, stable, and searchable. File names should explain what kind of artifact they hold and how the artifact fits into the generated set.

Generated chunk files should include a role prefix and a stable discriminator such as an index, logical key, address/range, schema version, or source identifier:

```text
TABLE_<INDEX>_<BEGIN>_<END>.cpp
SECTION_<INDEX>_<NAME>.<ext>
RESOURCE_<INDEX>_<ID>.bin
TEMPLATE_<INDEX>.<ext>
```

Generated file names may use an uppercase role prefix when the file is machine-owned: `TABLE_<INDEX>.cpp`, `SECTION_<INDEX>.asm`, `METADATA_<INDEX>.json`. Extensions stay in the normal spelling for the platform or toolchain. User-editable files should stand apart with ordinary role names such as `UserConfig.cpp`, `Hooks.asm`, `custom_rules.json`, or a documented `user/` directory.

If hexadecimal values appear in generated file names, use one documented spelling across the project. Uppercase hexadecimal without `0x` is recommended for sortable generated names. Fixed-width fields should keep the same width across one generated set, and the width rule should be explicit.

Large generated artifacts should be split by a documented policy:

- each split artifact type has its own size, count, or complexity cap;
- the cap name matches the artifact role, such as `--source-split-mb=N`, `--metadata-split-mb=N`, or `--table-split-count=N`;
- hard caps are measured from the actual emitted payload when practical;
- estimated caps must be documented as estimates;
- regeneration removes stale generated files from the same generated family;
- regeneration must not delete user-owned files just because an artifact moved or disappeared.

Generated file headers, README summaries, and reports should use key/value text for machine-readable facts such as addresses, sizes, schema versions, hashes, and source paths. Include units and encodings where ambiguity is possible:

```text
kind=table index=2 begin=00001000 end=00001FFF size=00001000
schema=3 source=assets/input.bin hash=4F8C2A10
```

Command-line help and parser logic should present and handle primary options in a stable order. A good default order is:

1. input selection;
2. output selection;
3. generation modes or feature switches;
4. split, cache, and performance limits;
5. toolchain/platform selection;
6. diagnostics, logging, dry-run, and help.

Generated scripts should pass through parallel-build or incremental-build options when they are safe and supported. Do not hide expensive rebuilds behind unrelated output.

User-facing CLI paths should be displayed relative to the current working directory whenever the target path is on the same filesystem root. Use an absolute path only when a relative path cannot be formed safely, such as a different filesystem root or drive. Internal filesystem operations may keep absolute paths.

Retry, recovery, or post-processing passes should update only the artifacts affected by that pass. They should reuse existing build/cache directories when possible and should not repeat high-level generation logs as if the whole pipeline restarted.

### 8.11. Generated-Code Contracts

Generated code is still code. It should follow the same style rules as hand-written code unless the generator explicitly documents a narrow exception.

Every generated project or generated output tree should define ownership boundaries:

- generated-only files may be overwritten at any time;
- user-editable files are never overwritten unless the user explicitly asks for regeneration;
- mixed files must use stable generated regions with clear begin/end markers;
- public extension points stay small, typed, and documented;
- generated examples are clean, compile-ready, and copy-paste safe;
- internal generated includes or fragments must say whether they are standalone files or included pieces.

Generated API surfaces should keep the same shape as ordinary hand-written APIs:

- declarations live in the smallest useful header;
- implementation details live in implementation files or `Detail` namespaces;
- public macros are thin facades over typed code;
- generated declarations are grouped by role and emitted in dependency order;
- generated validation code keeps layout records before layout constants, then `static_assert` checks, then helpers.

Generated transfer, packaging, or restore scripts should be conservative:

- stage extraction in a temporary directory;
- reject absolute paths and paths that escape the target root;
- read ignore rules from the project ignore file instead of duplicating hardcoded ignore lists;
- preserve user-owned files and local configuration;
- use the same indentation and blank-line rules as other project scripts.

When generated code rewrites references, relocations, imports, labels, metadata, or other cross-artifact links, the supported cases must be explicit. Unsupported or out-of-range cases should fail with a clear generation or build error instead of producing a silently broken artifact.

### 8.12. Namespace Names

Namespaces use PascalCase and name a component or library, not a generic grouping word:

```cpp
namespace SomeLibrary {
} // namespace SomeLibrary
```

Use a nested `Detail` namespace for implementation helpers that must live in a header but are not part of the public surface. Do not write `using namespace` at file or namespace scope in a header. Every namespace closes with a `// namespace Name` comment (see 19.4).

### 8.13. Directory Names

Project directories use lowercase, role-based names. A portable repository layout can look like this:

- `src/` — implementation sources;
- `include/` — public headers when the project exposes a library interface;
- `tests/` — unit, integration, smoke, and fixture-based tests;
- `tools/` — project-local maintenance utilities;
- `docs/` — human-authored documentation;
- `examples/` — small compile-ready integrations;
- `generated/` — generated-only files that may be overwritten;
- `user/` or `custom/` — user-owned extension points;
- `analysis/` — generated metadata and human-readable reports;
- `build/` — compiler/build-system artifacts, normally ignored;
- `output/` — packaged or runtime outputs, normally ignored.

Directory names should describe responsibility, not a temporary implementation detail or an individual developer.

### 8.14. Source File Names

Use one stable project-wide file-name convention. For C++ projects that use PascalCase type and module names, prefer names such as:

```text
ProcessSuspender.h
ProcessSuspender.cpp
PEImage.h
PEImage.cpp
```

A public header should normally match the primary public component it declares. Split files by stable responsibility rather than arbitrary line count.

Machine-owned generated files may use an uppercase role prefix as described in 8.10. User-authored files should remain visually distinct.

### 8.15. Abbreviations

Use complete, searchable names unless an abbreviation is a standard project, ABI, CPU, platform, file-format, or library term.

Bad:

```cpp
const std::int64_t nRel = ComputeRelative();
const std::int64_t nDisp = ComputeDisplacement();
std::size_t unIdx = 0;
unsigned char* punBuf = nullptr;
```

Good:

```cpp
const std::int64_t nRelative = ComputeRelative();
const std::int64_t nDisplacement = ComputeDisplacement();
std::size_t unIndex = 0;
unsigned char* punBuffer = nullptr;
```

Recommended replacements include:

- `disp` -> `displacement`;
- `rel` -> `relative` when it is not a standard relocation term;
- `addr` -> `address`;
- `buf` -> `buffer`;
- `ctx` -> `context`;
- `cfg` -> `configuration`;
- `idx` -> `index`;
- `cnt` -> `count`;
- `len` -> `length`;
- `src` -> `source`;
- `dst` -> `destination`.

Do not rename established terms such as `RVA`, `VA`, `TLS`, `PE`, `ELF`, `COFF`, `MASM`, `ASM`, `x86`, `x86_64`, `argv`, external structure fields, or public command-line flags.

---

## 9. Types, Declarations, and Qualifiers

### 9.1. Explicit Types

Signatures should be as explicit as needed.

Do not over-rely on:

- auto return types without a reason;
- non-obvious type deduction;
- "smart" hiding of types where the type matters to understanding the API.

### 9.2. `const` Style

Use west `const` for simple scalar types whose declaration has one clear type:

```cpp
const int nA = 0;
const float flB = 0.0f;
const std::size_t unSize = 0;
```

For compound declarations, place `const` next to the qualified type or pointer/reference as required by the declaration:

```cpp
char const* pszName;
wchar_t const* pszModuleName;
Block const& BlockValue;
void const* const pAddress;
```

Do not choose a spelling that obscures pointer constness, pointee constness, reference binding, ownership, or the ABI type. A legacy file may retain its established spelling during a focused behavioral patch, but a dedicated migration should apply this rule consistently within the edited file.

### 9.3. `const` on By-Value Parameters

Top-level `const` on a by-value parameter affects only the local copy inside the function definition; it is not part of the function type.

It is allowed when it makes the implementation declarative:

```cpp
bool SetSize(const unsigned int unSize);
```

Keep declaration and definition visually consistent within the project, but do not describe top-level parameter `const` as an ownership or caller-side guarantee. Constness of pointed-to or referenced data remains part of the API contract.

### 9.4. `*` and `&` Binding

Bind `*` and `&` to the type:

```cpp
void* pAddress
Page** ppPage
Block const& BlockValue
```

Do not use spaced forms such as:

```cpp
void * pAddress
```

Declare one pointer or reference variable per statement when multiple declarators would make binding unclear.

Every declaration in project C/C++ code must declare exactly one variable or object. Do not combine variables, arrays, pointers, or references of the same type in one declaration. Write `char szName[kNameCapacity] {};` and `char szExtension[kExtensionCapacity] {};` as two separate declarations instead of `char szName[kNameCapacity] {}, szExtension[kExtensionCapacity] {};`.

### 9.5. `typedef struct` and `typedef enum`

For C-compatible, ABI-facing, and layout-sensitive data, use the project typedef form with a leading-underscore tag and pointer alias:

```cpp
typedef struct _SOME_RECORD {
	void* m_pAddress;
	std::size_t m_unSize;
} SOME_RECORD, *PSOME_RECORD;
```

The `_TAG` spelling is reserved for this exact C-compatible structure-tag pattern. Do not use leading-underscore tags for ordinary C++ classes, variables, functions, or unrelated types.

```cpp
typedef enum SOME_MODE {
	SOME_MODE_DISABLED = 0,
	SOME_MODE_ENABLED
} SOME_MODE, *PSOME_MODE;
```

The leading-underscore tag is permitted here only because it is part of the required C-compatible structure typedef convention.

For pure C++ interfaces, prefer an ordinary `struct`, `enum class`, or type alias unless the C-compatible spelling is part of the boundary convention.

### 9.6. `using` for Function Pointer Aliases

For callbacks and function pointer aliases, prefer:

```cpp
using fnCallBack = bool(*)(void* pData);
```

### 9.7. `noexcept`

Use `noexcept` only when the implementation and every operation it calls are guaranteed not to let an exception escape, or when the function catches and translates all failures.

Common candidates include:

- destructors and cleanup functions;
- query functions implemented only with non-throwing operations;
- search/scanning helpers that report failure explicitly;
- byte conversion helpers;
- `constexpr` utilities;
- small low-level wrappers around non-throwing platform APIs;
- APIs that report failure through `bool`, `nullptr`, or a status object.

Do not mark a function `noexcept` merely because its name begins with `Get`, `Find`, or `Set`. Allocation, string formatting, container growth, filesystem operations, callbacks, and user code may throw. An incorrect `noexcept` turns an ordinary error into `std::terminate`.

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

### 9.10. Fixed-Size Storage, Views, and Limits

When size is part of the contract, make it visible in the type. Prefer array references, `std::array`, template parameters, `std::span`, and `std::string_view` over hidden runtime-length conventions at C++ boundaries.

Examples:

```cpp
template <std::size_t unLength>
constexpr unsigned int Hash(char const(&szText)[unLength]) noexcept;

template <std::size_t unLength>
constexpr void SetDataFromBytes(std::array<unsigned char, unLength> const& arrData) noexcept;

bool ParseBytes(std::span<unsigned char const> spnBytes) noexcept;
```

At a C ABI, OS API, binary hook, or wire-format boundary, a raw pointer plus explicit size is normal. Keep the pointer and its size adjacent in the signature and validate both together.

Every non-trivial array bound should come from a named `constexpr` constant:

```cpp
struct ParserLimits {
	static constexpr std::size_t kMaxLines = 2048;
	static constexpr std::size_t kMaxTokens = 8;
};

struct Line {
	std::size_t m_unTokenCount;
	Token m_Tokens[ParserLimits::kMaxTokens];
};
```

When a fixed-buffer aggregate intentionally has no constructor, value-initialize it at the use site whenever a default state is required:

```cpp
Line LineValue {};
```

Related capacities should be grouped in a small `Limits` / `...Limits` structure when that improves readability.

Use raw arrays when the code is layout-sensitive, C-compatible, stack-local, or intentionally fixed-buffer oriented. Use `std::array` for value semantics and `std::span` for a non-owning contiguous view.

A view never owns the referenced storage. Do not return or store a `std::span` or `std::string_view` whose source may expire.

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

Put one blank line between the constant/layout declaration and its first `static_assert`. Group related assertions together.

### 9.12. Casts and Ignored Values

Do not use C-style casts. Choose the narrowest C++ cast:

- `static_cast<T>(Value)` for numeric conversions, enum conversions, and other explicit language-level conversions;
- `reinterpret_cast<T>(Value)` for low-level pointer/address representation conversions;
- `const_cast<T>(Value)` only when changing cv-qualification is unavoidable and the external contract justifies it;
- `std::bit_cast<T>(Value)` for same-size trivially copyable object-representation conversion;
- `dynamic_cast<T>(Value)` only in code that intentionally uses RTTI and polymorphic down-casting.

Bad:

```cpp
(void)WriteFile();
std::uint32_t unValue = (std::uint32_t)nValue;
```

Good:

```cpp
	WriteFile();
	const std::uint32_t unValue = static_cast<std::uint32_t>(nValue);
```

Call a function normally when its return value is intentionally not needed. Handle status-returning APIs when the status affects correctness; do not add a cast only to discard a result or suppress an unused-result warning. Add a short comment when ignoring the result is not self-evidently safe.

Do not use `[[maybe_unused]]` or any equivalent unused-suppression attribute or declaration modifier. An unused warning is an ownership and dependency signal, not a formatting problem. If a project-owned function, class, struct, enum, type alias, parameter, local or global variable, data member, constant, macro, include, or other declaration is completely unused in every supported configuration and call path, remove it after checking the supported build configurations, callback contracts, ABI requirements, and call sites. Remove unused parameters from internal APIs, or omit parameter names for fixed ABI callbacks:

```cpp
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
	return TRUE;
}
```

If a declaration is required by a supported architecture, compiler, ABI, callback contract, or conditional build path but is unused in another valid configuration, suppress the warning only for that exact declaration or case. Use the narrowest compiler-specific warning-suppression form available, keep its scope adjacent to the affected line, and restore the previous warning state immediately. Never disable an unused warning for a whole file, project, target, configuration, or repository, and never use a global warning-disable macro as a substitute for the local justification.

Apply this order:

1. remove the declaration if it is unused in every supported configuration;
2. remove an unused parameter from a private/internal API and update every caller;
3. omit the parameter name when an external ABI/callback requires the position but no supported configuration uses the value;
4. place the declaration inside the preprocessor branch that uses it when the declaration is configuration-local;
5. only then use an adjacent compiler-specific suppression when the same named declaration is required across configurations.

Every suppression must include a short reason, name the exact warning being suppressed, cover the smallest possible declaration or function, and restore the previous diagnostic state immediately afterward.

Canonical cross-compiler form for a callback parameter that is required by the ABI and used only in one supported configuration:

```cpp
// nCallbackData is required by the callback ABI and is used only when SOME_FEATURE is enabled.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4100)
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

BOOL CALLBACK EnumerateWindow(HWND const hWindow, const LPARAM nCallbackData) {
#if defined(SOME_FEATURE)
	ConsumeCallbackData(nCallbackData);
#endif

	return IsWindow(hWindow);
}

#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
```

For a single MSVC declaration, prefer the next-line form when the warning supports it:

```cpp
// The platform registration macro reads this symbol only through generated metadata.
#if defined(_MSC_VER)
#pragma warning(suppress: 4189)
#endif
const DWORD unRegistrationCookie = RegisterGeneratedMetadata();
```

Do not copy these warning identifiers blindly. Use the warning number or diagnostic name produced for the exact supported compiler and declaration. A suppression that covers unrelated declarations or remains active after the affected case is invalid.

### 9.13. Object Representation and Type Punning

Do not access an object through an unrelated type merely because a cast compiles. For representation conversion, prefer `std::bit_cast`, `std::memcpy`, or byte access through `unsigned char` / `std::byte`.

A `reinterpret_cast` changes the expression type; it does not create object lifetime, guarantee alignment, or make aliasing valid. Keep such casts at a narrow, reviewed boundary.

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
	SomeType() noexcept;
	~SomeType() noexcept;

public:
	bool Set(...) noexcept;
	void Release() noexcept;

public:
	void* GetAddress() const noexcept;

private:
	void* m_pAddress;
};
```

Keep access labels at the class indentation level and indent every member declaration one additional tab. In particular, a repeated lifecycle section remains nested inside the class:

```cpp
class Page {
public:
	Page(void* const pBaseAddress, const bool bAutoRestore, const bool bCommitPage = false);
	Page(void* const pDesiredAddress = nullptr);
	~Page() noexcept;

public:
	Page(Page const&) = delete;
	Page(Page&&) noexcept;
	Page& operator=(Page const&) = delete;
	Page& operator=(Page&&) noexcept;
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

Do not use in-class/default member initializers for ordinary project-owned classes or structs. Declare constructors in the header and define them in the source file. When the language permits assignment after construction, initialize the default state in the constructor body with explicit assignments, one member per statement:

The header/source rule applies to every non-template constructor definition, including a delegating constructor and its initializer list. Keep the declaration in the header and put the complete definition, initializer list, and state initialization in the `.cpp` file. Do not place a non-template constructor body or initializer list in a public header merely because the declaration is short.

There is one narrow template exception: a function-template constructor whose definition must be visible for caller-side deduction may remain in the header. Such a definition must be a thin forwarding adapter; the non-template constructor that performs the real initialization is still declared in the header and defined in the `.cpp` file. Do not move a required template definition to the `.cpp`, and do not duplicate the full constructor implementation in the template adapter. When the template definition is also its first declaration, a default argument may appear there; do not repeat that default on another declaration or out-of-class definition.

Correct complete example:

```cpp
// SharedClient.h
class SharedClient final {
public:
#if defined(_WIN32)
	SharedClient(TCHAR const* pszSharedName, std::size_t unCapacity, bool bIsGlobal = false);

	template <std::size_t unCapacity>
	SharedClient(TCHAR const (&szSharedName)[unCapacity], bool bIsGlobal = false) :
		SharedClient(szSharedName, unCapacity, bIsGlobal)
	{
	}
#elif defined(__linux__)
	SharedClient(char const* pszSharedName, std::size_t unCapacity, bool bIsGlobal = false);

	template <std::size_t unCapacity>
	SharedClient(char const (&szSharedName)[unCapacity], bool bIsGlobal = false) :
		SharedClient(szSharedName, unCapacity, bIsGlobal)
	{
	}
#endif

	~SharedClient();

private:
	void* m_pSharedMemory;
	std::size_t m_unCapacity;
	bool m_bGlobal;
};
```

The template adapters above are allowed because the compiler must see them to deduce `unCapacity` from an array reference. They do exactly one thing: forward the array and its extent to the non-template constructor. They must not allocate, validate, mutate state, acquire a handle, or duplicate platform-specific initialization.

The real constructors and all member initialization belong in the source file:

```cpp
// SharedClient.cpp
#if defined(_WIN32)
SharedClient::SharedClient(TCHAR const* pszSharedName, std::size_t unCapacity, bool bIsGlobal) :
	m_pSharedMemory(OpenSharedMemory(pszSharedName, unCapacity, bIsGlobal)),
	m_unCapacity(unCapacity),
	m_bGlobal(bIsGlobal)
{
}
#elif defined(__linux__)
SharedClient::SharedClient(char const* pszSharedName, std::size_t unCapacity, bool bIsGlobal) :
	m_pSharedMemory(OpenSharedMemory(pszSharedName, unCapacity, bIsGlobal)),
	m_unCapacity(unCapacity),
	m_bGlobal(bIsGlobal)
{
}
#endif
```

Do not move `OpenSharedMemory`, validation, ownership setup, or additional state assignments into the header template adapter. If the template requires more than a single forwarding initializer, use a separate header-only factory/helper or move the supported instantiations into the `.cpp` file.

```cpp
// SomeType.h
struct SomeType {
	SomeType() noexcept;

	int m_nA;
	int m_nB;
};
```

```cpp
// SomeType.cpp
SomeType::SomeType() noexcept {
	m_nA = 0;
	m_nB = 0;
}
```

The following form is not allowed:

```cpp
struct SomeType {
	int m_nA = 0;
	int m_nB = 0;
};
```

Constructor-body assignment is not permitted when C++ requires initialization before the body begins. Use the constructor initializer list for:

- base classes that need explicit construction;
- reference members;
- `const` members;
- arrays that must be value-initialized;
- members without a usable default constructor;
- members whose required initial state cannot be established safely by default construction followed by assignment;
- every value supplied directly by a constructor argument.

When one constructor contains both language-required initialization and ordinary default-state assignment, initialize only the required/base/argument-supplied parts in the initializer list and assign the remaining ordinary members in the body. This mixed form is intentional and does not permit in-class/default member initializers.

```cpp
// SomeType.h
class SomeType final : public BaseType {
public:
	SomeType(SomeDependency& Dependency) noexcept;

private:
	SomeDependency& m_Dependency;
	const int m_nLimit;
	BYTE m_arrBytes[16];
	void* m_pAddress;
};
```

```cpp
// SomeType.cpp
SomeType::SomeType(SomeDependency& Dependency) noexcept :
	BaseType(Dependency),
	m_Dependency(Dependency),
	m_nLimit(0),
	m_arrBytes {}
{
	m_pAddress = nullptr;
}
```

A member whose type performs valid default construction needs no redundant body assignment. Scalar values, raw pointers, handles, and raw arrays do not receive that exemption unless they were initialized in the initializer list.

For values supplied by constructor arguments, declare the constructor and members in the header and define the constructor in the source file:

```cpp
// SomeBuffer.h
class SomeBuffer {
public:
	SomeBuffer(void* const pAddress, const std::size_t unSize) noexcept;

private:
	void* m_pAddress;
	std::size_t m_unSize;
};
```

```cpp
// SomeBuffer.cpp
SomeBuffer::SomeBuffer(void* const pAddress, const std::size_t unSize) noexcept :
	m_pAddress(pAddress),
	m_unSize(unSize)
{
}
```

Initializer-list order must match member declaration order. The compiler initializes members by declaration order regardless of the textual order in the list.

Use a constructor initializer list for values supplied by constructor arguments and for every language-required case listed above. Do not mix an in-class/default member initializer with constructor-body default initialization. Keep each member's default state in one obvious place.

The rule in this section does not override section 10.4: ABI, serialized, mapped-layout, and other contract-sensitive records must remain simple and should be zero-initialized at the use site instead of receiving a user-provided constructor.

### 10.4. Layout and ABI Records

A structure used as an ABI record, serialized record, mapped file layout, instruction layout, or externally copied byte block should remain as simple as the contract requires.

Do not add a user-provided constructor, destructor, virtual function, virtual base, or hidden ownership to such a record unless the contract explicitly permits it. A constructor can preserve byte offsets while still changing aggregate, triviality, or implicit-lifetime properties.

Prefer zero initialization at the use site or a separate typed helper:

```cpp
SOME_RECORD Record {};
InitializeRecord(Record);
```

When the contract depends on those properties, verify them:

```cpp
static_assert(std::is_standard_layout_v<SOME_RECORD>, "SOME_RECORD must remain standard-layout");
static_assert(std::is_trivially_copyable_v<SOME_RECORD>, "SOME_RECORD must remain trivially copyable");
static_assert(sizeof(SOME_RECORD) == kSomeRecordSize, "unexpected SOME_RECORD size");
```

### 10.5. Special Members

Use `= delete` and `= default` to express ownership and value semantics explicitly. For constructors, use `= default` only for a constructor with no arguments. Use it only when the compiler-generated constructor leaves every member in a valid, defined state; it must not replace explicit initialization of scalar or pointer members.

Example:

```cpp
SomeGuard() noexcept = default;
SomeGuard(SomeGuard const&) = delete;
SomeGuard& operator=(SomeGuard const&) = delete;
SomeGuard(SomeGuard&& Other) noexcept;
SomeGuard& operator=(SomeGuard&&) noexcept = default;
```

Define a parameterized, copy, or move constructor in the source file, or delete it when the operation is not supported. Do not write a parameterized, copy, or move constructor as `= default`.

A zero-argument `= default` constructor is an intentional in-header definition and is the only non-template, non-forwarding-adapter constructor-definition exception to the header/source rule.

A resource-owning type should normally be non-copyable. It may be movable only when the moved-from state is valid, empty, and safely destructible.

Follow the rule of zero when standard members already model the ownership correctly. Use the rule of five only when the class directly manages a resource.

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

Blank lines between phases are required. Inside an early-exit branch, its final single action and the simple one-line return form one compact terminal phase and remain adjacent as specified in section 6.2. A final main-path output/result commit remains separated from the function's final success return by one blank line.

### 11.4. `auto`

Use `auto` for every iterator declaration and use the range-loop forms defined below. Use `auto` for a local domain value initialized directly from a project function or factory when the return type is the intended contract and the variable name already communicates the role; for example, write `auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);` instead of repeating `TStringOptional`. Prefer an explicit type whenever the declaration exposes ownership, ABI layout, or initialization semantics. Apply section 7.9 to the initializer: use `=` whenever copy- or conversion-initialization is valid and semantics-preserving, and reserve direct `(...)` or list `{ Expression }` initialization for cases that require their distinct construction semantics. Do not use `auto` merely to shorten a simple scalar, ownership-bearing allocation, or platform ABI record.

For simple scalar values, write the scalar type explicitly with west `const` when applicable. For pointers to complex types with multiple qualifiers, prefer the platform or project pointer alias whose name begins with `P` (for example, `PRecord`). If no suitable `P*` alias exists, use `auto*` when the initializer determines the pointer type without hiding ownership or ABI semantics. Pointers to simple character types remain explicit, including qualified forms such as `char const* const` and `wchar_t const* const`; do not replace these with `auto*`. Do not use `auto` for a pointer merely to shorten a simple scalar or handle declaration.

```cpp
PRecord pRecord = GetRecord();
auto* const pComplexRecord = GetComplexRecord();
```

Use this decision matrix:

| Situation | Required/default form | Example |
| --- | --- | --- |
| Iterator or iterator-returning algorithm result | `auto` | `auto itEntry = std::find_if(...);` |
| Read-only range element | `auto const&` | `for (auto const& RegistryEntry : Registry.m_mapStates)` |
| Mutable range element | `auto&` | `for (auto& RegistryEntry : Registry.m_mapStates)` |
| Intentional copied range element | `auto` | `for (auto RegistryEntry : vecEntries)` |
| Simple scalar outside a range | explicit scalar type | `const unsigned int unCount = GetCount();` |
| Complex pointer with a suitable `P*` alias | explicit alias | `PRecord pRecord = GetRecord();` |
| Complex pointer without a suitable alias | `auto*` with required qualifiers | `auto* const pRecord = GetComplexRecord();` |
| Local domain value returned by a project function or factory | `auto` | `auto ModuleFileName = GetDebugModuleName(unProcessID, pImageBase);` |
| Named local lambda | `auto` | `auto Predicate = [&](Record const& RecordValue) -> bool { ... };` |
| Generated/dependent object type that cannot be named usefully | `auto` | `auto strValue = COMPILE_TIME_TEXT("value");` |
| Ownership-bearing allocation or smart pointer | explicit owner type | `std::unique_ptr<char[]> pBuffer(new (std::nothrow) char[unSize]);` |
| ABI/system record | explicit record type | `PROCESS_RECORD ProcessInformation {};` |

The `std::unique_ptr` row uses direct initialization because its raw-pointer constructor is `explicit`; copy-initialization from that pointer is not available. This required direct construction is an exception under section 7.9, not an alternative style for an ordinary copy.

Use `auto const&` as the default range form because it avoids an unintended copy and prevents mutation. Use `auto&` only when the loop intentionally changes the stored element. Use plain `auto` only when each element must be copied; the copy must be semantically intentional rather than an incidental result of type deduction.

Named local lambdas and narrow compile-time or macro facades whose generated type cannot be named use `auto`. Range-based `for` elements use `auto` with the required `const` and reference qualifiers; do not spell their value type through `decltype(...)`, `std::remove_reference_t`, `value_type`, or another container-derived type. This keeps the loop coupled to the expression being traversed without exposing implementation-specific container details.

Use `decltype` only when it preserves a genuinely expression-dependent type that cannot be stated clearly by an explicit type or the approved `auto` rules. Do not use `decltype` as a general replacement for `auto` or to spell a type that is already clear from the initializer and surrounding contract. Iterator variables and results from iterator-returning algorithms must use `auto`, for example `auto it = std::find_if(...)`; do not write `decltype(Container.begin()) it` or another `decltype`-based iterator declaration. A scalar algorithm result still uses its explicit scalar type when that type is part of the local contract.

`decltype(auto)` follows the same restriction. It is allowed only in a forwarding or adapter function whose contract must preserve the exact value/reference category of an expression and where neither an explicit return type nor ordinary `auto` is correct. Do not use `decltype(auto)` for local variables, iterator declarations, range elements, or as a convenience return type.

A canonical portable case is a `COMPILE_TIME_TEXT` facade in a project-owned header. It needs `decltype(S)` to preserve the literal's array type for `std::extent_v` and `decltype(S[0])` to derive the exact character element type for both narrow and wide literals. Replacing either expression with a fixed type would lose information that is part of the compile-time contract:

```cpp
constexpr std::size_t kLength = std::extent_v<std::remove_reference_t<decltype(S)>>;
constexpr auto kEncoded = CompileTimeText::Encoded<kLength, CompileTimeText::CharacterType<decltype(S[0])>, __LINE__, __COUNTER__>(S);
```

This is an allowed use because both resulting types genuinely depend on the macro expression. It does not justify `decltype` for iterators, range elements, ordinary objects, or values whose type is already represented by the approved `auto` or explicit-type rules. A different project may use a differently named macro and helper type; the expression-dependent contract is the portable part.

Example:

```cpp
auto NeedRegister = [&](int& nRegisterOut, std::string_view const strvToken) -> bool {
	const int nRegister = RegisterFrom(strvToken);
	if (nRegister < 0) {
		return false;
	}

	nRegisterOut = nRegister;

	return true;
};
```

Iterator declarations always use `auto`, especially for nested associative containers:

```cpp
auto itModule = g_Modules.find(unProcessID);
```

Range-based loops and algorithm results follow the same rule:

```cpp
for (auto const& RegistryEntry : Registry.m_mapStates) {
	...
}

auto it = std::find_if(vecReferenceCounts.begin(), vecReferenceCounts.end(), Predicate);
```

Do not spell an iterator or range-loop element through a container-derived type:

```cpp
for (std::remove_reference_t<decltype(Registry.m_mapStates)>::value_type const& RegistryEntry : Registry.m_mapStates) {
	...
}

decltype(vecReferenceCounts.begin()) it = std::find_if(...);
```

Prefer explicit object initialization when the type is known:

```cpp
SYSTEMTIME SystemTime {};
TString strName = szName;
std::unique_ptr<char[]> pCommandLine(new (std::nothrow) char[unLength + 1]);
PROCESS_STARTUP_INFO StartupInfo {};
PROCESS_RECORD ProcessInformation {};
```

`auto` remains appropriate for iterators and for an object whose generated or dependent type cannot be named usefully. Do not extend it to ownership-bearing allocations or ABI/system records merely to shorten the declaration.

Do not use structured bindings when they would hide important field names or types. An explicit record object is preferred in systems code.

### 11.5. Explicit `return true;` / `return false;`

Even when the logic is obvious, end the function with an explicit return value.

### 11.6. Cleanup and Ownership Near the Failure Point

Prefer RAII so every acquired resource is attached to an owner immediately. When a platform or ABI boundary requires manual cleanup, perform it near the failure point and keep every exit path visible.

Do not acquire several raw resources and defer assigning owners until the end of the function. Do not hide allocation, lock acquisition, ownership transfer, or cleanup inside a helper whose name sounds like a pure query.

A manual `goto Cleanup` block is allowed in C-compatible or multi-resource low-level code when it is flatter and easier to audit than repeated cleanup branches. The label must have one clear responsibility and must not bypass initialization of non-trivial C++ objects.

### 11.7. Local Lambdas as Phase Helpers

Local lambdas are allowed when they make a long function flatter and more phase-oriented. They are especially useful for parsers, validators, small emitters, repeated error checks, and tiny local adapters.

Rules:

- give the lambda a semantic `PascalCase` name;
- keep it close to the phase where it is used;
- keep captures obvious and narrow;
- do not hide ownership transfer, allocation, locking, or cleanup inside an innocent-looking helper.

The canonical shape is shown in 11.4. Do not duplicate a lambda merely to shorten the surrounding function; extract a named private helper when the logic has an independent responsibility.

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
- a status enum;
- an error object;
- a result structure containing both value and status.

Do not add declaration attributes solely to force callers to inspect a status value. Make status handling visible through explicit return types, operation names, call-site checks, review, and tests.

### 12.2. Exceptions

Exceptions are allowed only when the project uses them consistently and the boundary permits them.

In systems-heavy, low-level, compile-time, real-time, ABI-facing, callback, and hook code, prefer explicit result reporting.

Never allow an exception to escape:

- a C ABI;
- an OS callback;
- a thread entry point;
- a destructor;
- a `noexcept` function;
- an injected/hooked boundary whose caller does not expect C++ exceptions.

Catch at the boundary, translate to the project's status model, and preserve enough context to diagnose the failure.

### 12.3. Platform Error State

Capture transient platform error state immediately after the failing call and before any operation that may overwrite it.

Examples include:

- `GetLastError()` on Windows;
- `errno` on POSIX;
- library-specific thread-local error values.

Do not call logging, formatting, allocation, cleanup APIs, or another platform function before capturing the value.

### 12.4. SEH and Platform-Specific Error Handling

SEH and platform-specific mechanisms are allowed when they are the actual tool needed for the platform boundary.

Keep the protected region as small as practical. Do not use SEH as ordinary C++ control flow, and do not assume it makes an invalid memory algorithm safe.

### 12.5. Diagnostic Ownership

Choose which layer owns the diagnostic. A low-level helper should usually return detailed status; a higher layer that knows the operation context should log it.

Avoid logging the same failure at every stack level. This creates duplicate, misleading messages. Add context while propagating the error instead.

Error text should include the failed operation and relevant non-secret values such as path, offset, index, status code, or expected size. Never log keys, passwords, access tokens, plaintext secrets, or full sensitive buffers.

### 12.6. Compile-Time Error Reporting

For compile-time interpreters, parsers, assemblers, or generators, prefer a result object that carries:

- success/failure;
- stage;
- line/index/offset;
- output data;
- a stable error code or message.

Example:

```cpp
// Error.h
struct Error {
	Error() noexcept;

	char const* m_pMessage;
	int m_nLine;
};

enum class STAGE : unsigned char {
	OK = 0,
	FIRST_PASS,
	SECOND_PASS,
	RUNTIME
};
```

```cpp
// Error.cpp
Error::Error() noexcept {
	m_pMessage = nullptr;
	m_nLine = -1;
}
```

---

## 13. API Design

### 13.1. Explicit API Families

When an API has several related operations, use explicit names rather than one overloaded name that hides behavior:

```cpp
FindByName
FindByAddress
FindByIndex
```

Overloads are acceptable when they preserve the same semantics and differ only by a natural representation. Use distinct names when ownership, blocking behavior, allocation, lookup policy, encoding, or failure behavior differs.

### 13.2. ANSI/Wide and Generic Wrapper

For Windows-style APIs, it is acceptable to expose `A` and `W` variants plus a generic wrapper when that is the domain convention:

```cpp
OpenFileA
OpenFileW
OpenFile
```

The generic wrapper must select the variant predictably and must not silently convert with a lossy encoding.

### 13.3. Callback APIs

Callback APIs expose the callback type clearly:

```cpp
using fnEnumCallback = bool(*)(void* pEntry, void* pUserData);
```

Prefer explicit `pUserData` over hidden captures at ABI boundaries. Document callback lifetime, calling thread, lock state, reentrancy, and whether returning `false` stops enumeration.

Do not invoke user-provided or untrusted callbacks while holding an internal lock unless the API contract explicitly requires it.

### 13.4. Getters

Simple getters may return raw values when the underlying concept is raw:

```cpp
void* GetAddress() const noexcept;
std::size_t GetSize() const noexcept;
```

A getter should not allocate, block, mutate observable state, or transfer ownership unless the name makes that behavior explicit.

### 13.5. Ownership and Lifetime

Every API boundary must make ownership and lifetime understandable from the type, name, or adjacent contract.

- raw pointers are non-owning by default;
- `std::unique_ptr` transfers or owns one heap object;
- `std::span` and `std::string_view` are non-owning views;
- a returned handle must state who closes it;
- a returned pointer/view must not outlive its source;
- an output buffer must expose capacity and written length.

Use names such as `pOwner`, `pBorrowed`, `pBufferOut`, `unCapacity`, and `unWrittenOut` only when the distinction is not already obvious from the type and API family.

### 13.6. Nullability and Output Parameters

A pointer parameter that may be null must say what null means. A required pointer should be validated immediately unless the function is a private leaf whose caller has already established the invariant.

Output parameters use an `Out` suffix and are assigned only after validation or successful construction:

```cpp
bool GetImageRange(void const* pImage, std::uintptr_t& unBeginOut, std::size_t& unSizeOut) noexcept;
```

For multi-value results in C++ code, prefer a named result structure when it makes partial-state and failure behavior clearer.

### 13.7. Pointer and Size Pairs

Keep a pointer adjacent to its size/capacity parameter:

```cpp
bool WriteBytes(void* pBuffer, std::size_t unBufferSize, void const* pData, std::size_t unDataSize) noexcept;
```

Validate null, zero-size policy, range, and overlap before use. Do not infer a binary buffer size from a terminator unless the API explicitly accepts a string.

### 13.8. ABI and Versioning

Public ABI records and exported functions require stable calling convention, packing, integer widths, symbol names, and ownership rules.

Do not expose STL containers, exceptions, compiler-specific RTTI types, or allocator ownership across a binary boundary unless both sides deliberately share the same toolchain/runtime contract.

Version extensible records with an explicit size/version field and reject unsupported values clearly.

---

## 14. Low-Level and Platform-Aware Code

This section applies where the project genuinely deals with ABI, layout, memory mapping, page protection, intrinsics, machine code, system APIs, binary formats, or compile-time byte generation.

### 14.1. Allowed Tools

The following are acceptable when they are the correct tool:

- `reinterpret_cast`;
- `static_cast`;
- `std::bit_cast`;
- `offsetof`, `sizeof`, and `alignof`;
- `union` and bitfields for documented layouts;
- raw pointer arithmetic;
- compiler intrinsics;
- byte arrays;
- architecture-specific preprocessor branches;
- macros;
- `constexpr` lookup tables;
- fixed-size local buffers.

Their use does not waive range, lifetime, aliasing, alignment, or error checks.

### 14.2. Layout-First Structures

If a structure represents an external binary layout, layout accuracy takes priority over abstract object-oriented neatness.

```cpp
union FLAGS {
	unsigned int m_unValue;

	struct {
		unsigned int m_unA : 1;
		unsigned int m_unB : 1;
	};
};
```

Document offsets, widths, packing, endianness, and architecture assumptions. Verify every relied-on property:

```cpp
static_assert(sizeof(FLAGS) == sizeof(unsigned int), "unexpected FLAGS size");
static_assert(offsetof(SOME_RECORD, m_unSize) == kSomeRecordSizeOffset, "unexpected field offset");
```

Remember that C++ bitfield allocation order is implementation-defined. Use bitfields only when the compiler/ABI contract is controlled; otherwise read and write masks explicitly.

### 14.3. Address and Range Validation

Validate the complete range before dereferencing or copying. Prefer subtraction-based checks that avoid overflow:

```cpp
if (unOffset > unBufferSize || unDataSize > (unBufferSize - unOffset)) {
	return false;
}
```

Do not validate only the starting address. A range can begin inside a valid object and extend beyond it.

For mapped images and binary formats, validate each header, directory, table, count, multiplication, and nested range against the trusted outer size before following it.

### 14.4. Macros

Macros are allowed when they:

- encapsulate a compiler/platform directive;
- encode flags or tables;
- reduce repetitive low-level patterns;
- provide a predictable compile-time result;
- preserve information available only to the preprocessor, such as `__LINE__`, `__COUNTER__`, or literal extent.

Do not use a macro where an ordinary function, template, or `constexpr` value preserves the same control and improves type checking.

### 14.5. Architecture Branches

If ABI or layout differs across architectures, branch explicitly and reject unsupported targets:

```cpp
#if defined(_M_X64) || defined(__x86_64__)
	...
#elif defined(_M_IX86) || defined(__i386__)
	...
#elif defined(_M_ARM64) || defined(__aarch64__)
	...
#else
#error Unsupported architecture
#endif
```

Keep compiler detection and architecture detection separate. Do not assume that pointer width alone identifies the instruction set or ABI.

### 14.6. Byte, Endian, and Bit-Level Helpers

Isolate byte conversion in small helpers instead of scattering shifts through high-level code.

Rules:

- use `unsigned char`, `std::uint8_t`, or `std::byte` for raw storage;
- make endianness visible in names such as `ReadU32LE`, `WriteU64BE`, or `ByteIO`;
- support only widths the algorithm actually handles;
- use `static_assert` for unsupported compile-time widths;
- use explicit casts around shifts, masks, and sign extension;
- keep aliasing through byte pointers localized.

Each concrete fixed-width reader should perform its own bounds check and build the result explicitly:

```cpp
static bool ReadU32LE(std::vector<std::uint8_t> const& vecBytes, const std::uint64_t unOffset, std::uint32_t& unValueOut) noexcept {
	const std::uint64_t unFileSize = static_cast<std::uint64_t>(vecBytes.size());
	const std::uint64_t unByteCount = static_cast<std::uint64_t>(sizeof(std::uint32_t));

	if ((unOffset > unFileSize) || ((unFileSize - unOffset) < unByteCount)) {
		return false;
	}

	std::uint32_t unValue = 0;
	for (std::uint64_t unIndex = 0; unIndex < unByteCount; ++unIndex) {
		const unsigned int unShift = static_cast<unsigned int>(unIndex * 8);
		unValue |= static_cast<std::uint32_t>(static_cast<std::uint32_t>(vecBytes[static_cast<std::size_t>(unOffset + unIndex)]) << unShift);
	}

	unValueOut = unValue;

	return true;
}
```

### 14.7. Compile-Time Tables and Algorithms

Large compile-time tables are acceptable when they make the algorithm deterministic, fast, or self-contained.

Rules:

- name table constants with `k`;
- put tables before functions that read them;
- keep the element type explicit;
- group related tables with the owning algorithm;
- use `constexpr` for compile-time data;
- avoid mutable global tables unless mutation is part of the design;
- validate table size and indexes with `static_assert` or range checks.

### 14.8. Compile-Time Obfuscation, Hashing, and Crypto Utilities

Compile-time hashing, literal transformation, obfuscated variables, stack strings, and encrypted arrays are allowed in protection-oriented code when they solve a real project problem.

Rules:

- keep the typed implementation inside a namespace;
- expose only a narrow public macro or function facade;
- use `constexpr` / `consteval` when deterministic compile-time generation is the point;
- keep seed, salt, timestamp, line, and counter mixing explicit;
- do not describe build-time variation as true randomness;
- do not treat compile-time obfuscation as a cryptographic boundary;
- do not claim embedded literals, constants, or keys cannot be recovered;
- wipe temporary plaintext buffers where practical;
- use reviewed cryptography for actual confidentiality or integrity.

### 14.9. Integer Overflow and Narrowing

Before addition, multiplication, alignment, count-to-byte conversion, or relative displacement calculation, verify that the result fits the destination type.

Prefer checks shaped around the operation:

```cpp
if (!unElementSize || (unCount > (std::numeric_limits<std::size_t>::max() / unElementSize))) {
	return false;
}

const std::size_t unByteSize = unCount * unElementSize;
```

Do not cast a large value to a smaller type and validate after truncation. Validate in the source type first.

Relative branches, RVAs, file offsets, and pointer differences should use an explicitly wide signed/unsigned intermediate and then validate the target encoding range.

### 14.10. Alignment, Lifetime, and Aliasing

A pointer value must satisfy the target type's alignment before typed access. Packed or unaligned input should be copied into aligned storage or read byte-wise unless the platform explicitly supports and the project intentionally relies on unaligned access.

A pointer cast by itself does not establish the target object's lifetime or validate that a live target object exists in the storage. Construct or implicitly create objects only through mechanisms permitted by the selected language standard and storage contract.

Do not dereference a pointer obtained by adding an unchecked integer to a base. Keep arithmetic in `std::uintptr_t` or byte pointers only at the narrow boundary, validate the range, then convert to the final typed pointer.

### 14.11. Packing and ABI Checks

Keep `#pragma pack(push, N)` and `#pragma pack(pop)` in the smallest possible scope. Never leave altered packing active across unrelated declarations or includes.

For every relied-on external record, add relevant `sizeof`, `alignof`, and `offsetof` assertions for each supported architecture.

Do not assume an x86 layout is valid on x86_64 or ARM64 merely because compilation succeeds.

### 14.12. CPU Features and Intrinsics

Compile-time architecture selection does not prove that a runtime CPU supports every instruction enabled by the compiler.

Before executing optional SIMD, AES, SHA, AVX, AVX2, AVX-512, or other feature-specific paths:

- detect the CPU/OS capability;
- account for OS-managed extended state where required;
- provide a valid fallback or reject the operation clearly;
- keep feature-specific code in a narrow function or translation unit;
- test each enabled architecture/configuration independently.

### 14.13. `volatile`, Atomics, and MMIO

`volatile` is not a synchronization primitive and does not make a data race valid. Use `std::atomic`, a lock, or the platform synchronization API for shared memory between threads.

Use `volatile` only for contracts that actually require observable accesses, such as memory-mapped device I/O or a documented compiler/platform primitive. Keep MMIO wrappers separate from ordinary memory code and preserve required barriers/order.

---

## 15. Resource Management

### 15.1. RAII as the Default

Attach an acquired resource to an owner immediately. Small RAII wrappers are preferred for handles, mappings, allocated memory, locks, file descriptors, sockets, and temporary state.

```cpp
class HandleGuard final {
public:
	HandleGuard() noexcept;
	explicit HandleGuard(HANDLE const hValue) noexcept;
	~HandleGuard() noexcept;

public:
	HandleGuard(HandleGuard const&) = delete;
	HandleGuard& operator=(HandleGuard const&) = delete;
	HandleGuard(HandleGuard&& Other) noexcept;
	HandleGuard& operator=(HandleGuard&& Other) noexcept;

private:
	HANDLE m_hValue;
};
```

```cpp
// HandleGuard.cpp
HandleGuard::HandleGuard() noexcept {
	m_hValue = nullptr;
}
```

Destructors must not throw. Cleanup should tolerate an empty or moved-from state.

### 15.2. Manual Lifecycle

Manual `Init` / `Release` style is allowed when explicit lifecycle fits the domain better than constructor ownership, especially for injected modules, platform callbacks, global subsystem state, or APIs that need recoverable initialization.

Rules:

- make the state visible, for example `m_bInitialized`;
- make `Release` safe to call after partial initialization;
- make repeated `Release` calls harmless when practical;
- restore the object to a known empty state;
- prevent use before `Init` and after `Release`;
- do not mix implicit RAII ownership and undocumented manual ownership for the same resource.

### 15.3. Owning Pointers and Handles

Prefer `std::unique_ptr` for a single-owner heap object. A raw pointer is non-owning unless an external API explicitly defines otherwise.

Do not force smart pointers into ABI records, OS handle fields, shared-memory layouts, or binary formats. Wrap those resources in an owning class at the C++ boundary.

Avoid `std::shared_ptr` unless shared lifetime is an actual requirement. Shared ownership should not be used to avoid designing the owner.

### 15.4. Move Semantics

A movable owner transfers exactly one resource and clears the source. Move assignment releases the destination's old resource before taking the new one and handles self-move safely.

A moved-from object must remain destructible and may support only the operations explicitly documented for an empty state.

### 15.5. Temporary Plaintext and Sensitive Buffers

When a utility materializes plaintext, decrypted data, temporary keys, masks, authentication data, or other sensitive intermediate state, keep the lifetime explicit and short.

Recommended pattern:

- wrap the buffer in a small owner type;
- delete copy construction and copy assignment;
- allow move only if the source is cleared;
- clear the buffer in the destructor;
- use a project-approved secure-zero primitive such as `SecureZeroMemory`, `explicit_bzero`, or `memset_s` when available;
- keep secure wiping localized and test that the primitive is not optimized away;
- never log the sensitive contents.

Do not store decrypted literal buffers or runtime keys in global/static objects unless the threat model explicitly accepts that lifetime.

---

## 16. Synchronization

### 16.1. Explicit Primitives

Use an explicit primitive that matches the platform and access pattern:

```cpp
std::mutex
std::shared_mutex
CRITICAL_SECTION
SRWLOCK
std::atomic
```

Do not use `volatile`, sleep loops, or incidental API calls as synchronization.

### 16.2. Local Visibility of Lock Ownership

Lock acquisition and release should be visible near the protected logic. Prefer an RAII guard whose name identifies the primitive or protected state.

Keep the critical section as small as correctness allows, but do not split one invariant across separate lock acquisitions merely to reduce line count.

### 16.3. Lock Ordering

When code may hold more than one lock, define and follow a stable lock order. Document the order near the lock declarations or subsystem contract.

Do not acquire locks in caller-dependent order. Use `std::scoped_lock` or an equivalent platform strategy when acquiring a known set together.

### 16.4. Callbacks, Blocking, and Reentrancy

Do not call user-provided callbacks, virtual extension points, logging sinks, IPC, filesystem/network operations, or potentially blocking code while holding an internal lock unless the contract explicitly requires it.

If the lock must remain held, document reentrancy and deadlock constraints at the call site.

### 16.5. Atomics and Memory Order

Use `std::atomic` only for a state that can be expressed correctly as atomic operations. A group invariant usually needs a lock.

Use the default sequentially consistent order unless a weaker memory order is justified by a documented concurrency argument. Do not add `memory_order_relaxed` merely for performance without proving that ordering is irrelevant.

### 16.6. Condition Variables and Waiting

Wait with a predicate and handle spurious wakeups:

```cpp
ConditionVariable.wait(Lock, [&]() -> bool {
	return m_bStopping || !m_vecQueue.empty();
});
```

Timeouts use a monotonic clock. Do not compute elapsed time with a wall clock that can jump.

### 16.7. Thread-Safety Contracts

Public concurrent APIs should state whether an object is:

- not thread-safe;
- safe for concurrent readers;
- internally synchronized;
- externally synchronized;
- confined to one thread.

State which operations may block and which callbacks may run on which thread.

---

## 17. STL Profile

### 17.1. Preferred Types

Use standard-library types where they improve ownership, lifetime, or value semantics:

- `std::vector`;
- `std::array`;
- `std::span`;
- `std::string`;
- `std::wstring`;
- `std::string_view`;
- `std::optional` for simple absence;
- `std::unique_ptr`;
- `std::filesystem::path`;
- `std::error_code` when non-throwing filesystem/system APIs are desired.

Do not force STL types into binary layouts, ABI records, shared-memory contracts, compile-time fixed buffers, or platform structures where raw arrays and explicit fields are more correct.

### 17.2. Views and Lifetime

`std::span` and `std::string_view` do not own storage. Their use is encouraged only when lifetime remains obvious.

Do not store a view into a temporary, a vector/string that may reallocate, a stack object that will return, or memory owned by an asynchronously destroyed object.

### 17.3. Explicit Loops

Prefer explicit loops when they improve auditability:

```cpp
for (std::size_t unIndex = 0; unIndex < unCount; ++unIndex) {
	...
}
```

Algorithms such as `std::find_if`, `std::sort`, and `std::transform` are allowed when they make the operation clearer rather than hiding control flow or error handling.

### 17.4. Container Access

Use `operator[]` when the index has already been validated by the local invariant. Use `.at()` when exception-based bounds reporting matches the subsystem.

Do not keep pointers, references, iterators, spans, or string views across an operation that can invalidate them.

Reserve container capacity when a reliable upper bound is known and repeated reallocation matters. Do not reserve speculative enormous capacities.

### 17.5. Higher-Level Wrappers

Use higher-level wrappers when they clarify ownership or lifetime. Do not use them to hide domain-critical details such as byte order, file offsets, ABI widths, lock state, or handle ownership.

---

## 18. Compile-Time and Header-Only Utilities

### 18.1. General Model

Header-only compile-time utilities should be built as typed C++ first and macro syntax second:

1. fixed helper types;
2. constants and tables;
3. leaf algorithms;
4. state/helper classes;
5. high-level `constexpr` / `consteval` entry points;
6. a public macro facade only when needed.

Header-only status does not override section 10.3 for ordinary constructors. A required caller-visible function-template constructor may remain in the header as a thin forwarding adapter with its delegating initializer; the real non-template constructor definition and state initialization remain `.cpp` responsibilities.

### 18.2. Compile-Time Tables

Compile-time tables should be `constexpr`, explicitly typed, named with `k`, placed before use, and grouped with the owning algorithm.

```cpp
constexpr std::uint32_t kCRC32Table[256] = {
	...
};
```

Large tables should have a generation source or documented derivation. Add `static_assert` checks for expected count and element width.

### 18.3. Byte Serialization Helpers

For compile-time strings, arrays, hashes, VMs, and binary-format utilities, byte serialization should be explicit:

```cpp
template <typename T, std::size_t unSize>
struct ByteIO {
	static_assert(unSize == 2, "unsupported byte width");

	static constexpr void To(T const Value, unsigned char(&arrOutput)[unSize]) noexcept {
		const unsigned short unValue = static_cast<unsigned short>(Value);

		arrOutput[0] = static_cast<unsigned char>(unValue & 0xFF);
		arrOutput[1] = static_cast<unsigned char>((unValue >> 8) & 0xFF);
	}
};
```

Do not depend on host endianness or object padding unless the algorithm explicitly operates on the host representation.

### 18.4. Public Compile-Time API Macros

A macro is acceptable as a public compile-time API when it preserves syntax or information a function cannot naturally receive:

- literal or array extent;
- `__LINE__`;
- `__COUNTER__`;
- architecture selection;
- expression-like lazy construction.

The macro delegates to typed implementation code:

```cpp
#define COMPILE_TIME_TEXT(S)                                                                                                             \
	([]() -> auto {                                                                                                                      \
		constexpr std::size_t kLength = std::extent_v<std::remove_reference_t<decltype(S)>>;                                             \
		constexpr auto kEncoded = CompileTimeText::Encoded<kLength, CompileTimeText::CharacterType<decltype(S[0])>, __LINE__, __COUNTER__>(S); \
		return kEncoded.Decode();                                                                                                        \
	} ())
```

The two `decltype` expressions are required to preserve the literal extent and element type. The `constexpr auto` object and `-> auto` return are also limited to this narrow facade because their generated types intentionally depend on the literal expression.

### 18.5. `constexpr` / `consteval` Entry Points

Use `consteval` when the API must run at compile time. Use `constexpr` when the same code is useful at compile time and runtime.

For multi-stage operations, return an explicit result object rather than hiding errors behind template-substitution noise.

Compile-time algorithms may use loops, local mutable state, fixed-size arrays, helper records, and explicit casts. They should still resemble readable systems code.

### 18.6. Compile-Time Resource Limits

Compile-time parsers, assemblers, obfuscators, and generated tables must have named limits for input length, instruction count, recursion depth, output size, and diagnostic count where applicable.

Validate limits with `static_assert` and produce a message that identifies the exceeded contract. Do not allow accidental template recursion or enormous constant evaluation to become an unexplained compiler hang.

---

## 19. Comments

### 19.1. Banners

Use banners to divide stable responsibilities:

```cpp
// ----------------------------------------------------------------
// Decoder
// ----------------------------------------------------------------
```

Do not create a banner for every small helper. The section name should remain meaningful after ordinary refactoring.

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

A comment should explain intent, invariant, reason, external contract, or non-obvious consequence. Do not narrate an obvious statement.

### 19.3. Layout and Safety Comments

For binary layouts and low-level code, comments should clarify:

- offsets and sizes;
- encoding and endianness;
- packing/alignment assumptions;
- ownership/lifetime;
- architecture-specific behavior;
- why an apparently unusual cast, barrier, or cleanup is required.

Do not use a comment as a substitute for a missing range check or `static_assert`.

### 19.4. Namespace Closing Comments

Close every named namespace with its name. Close an anonymous namespace with `// namespace`:

```cpp
} // namespace SomeUtility

} // namespace
```

### 19.5. TODO and FIXME

A TODO/FIXME must be actionable and searchable. Include the missing behavior or failure mode, not only a person's name:

```cpp
// TODO: Reject overlapping relocation blocks before applying entries.
```

Use an issue identifier when the project has an issue tracker. Remove stale TODOs when the work is completed.

### 19.6. Public Documentation

Document public APIs when ownership, nullability, threading, encoding, units, error behavior, or lifetime is not fully visible in the signature.

Do not duplicate the function name in prose. State the contract callers need to use the API safely.

---

## 20. What This Style Dislikes

This style dislikes:

- hidden ownership or lifetime;
- excessive abstraction around raw facts;
- deep nesting;
- unordered files and dependencies used before declaration;
- hidden non-trivial global initialization;
- public macros placed before their typed implementation;
- helper macros that leak across headers;
- reserved project identifiers outside the documented compatibility profile;
- C-style casts and unchecked narrowing;
- `auto` everywhere;
- `volatile` used as synchronization;
- unchecked pointer arithmetic, integer overflow, alignment, or range assumptions;
- calling unknown callbacks while holding internal locks;
- copying ABI records without layout assertions;
- using "modern C++" as a substitute for clear domain logic;
- claiming compile-time obfuscation is a strong runtime security boundary;
- comments that describe code instead of preserving the reason or contract.

---

## 21. Canonical Templates

### 21.1. Canonical Function

```cpp
bool SomeObject::SetBuffer(void const* const pBuffer, const std::size_t unSize) noexcept {
	if (!pBuffer || !unSize) {
		return false;
	}

	void* const pNewBuffer = AllocBuffer(unSize);

	if (!pNewBuffer) {
		return false;
	}

	CopyBuffer(pNewBuffer, pBuffer, unSize);

	ReleaseBuffer(m_pBuffer);
	m_pBuffer = pNewBuffer;
	m_unSize = unSize;

	return true;
}
```

### 21.2. Canonical Class

```cpp
class SomeObject final {
public:
	SomeObject() noexcept;
	~SomeObject() noexcept;

public:
	SomeObject(SomeObject const&) = delete;
	SomeObject& operator=(SomeObject const&) = delete;
	SomeObject(SomeObject&& Other) noexcept;
	SomeObject& operator=(SomeObject&& Other) noexcept;

public:
	bool Init() noexcept;
	void Release() noexcept;

public:
	void* GetAddress() const noexcept;
	std::size_t GetSize() const noexcept;

private:
	void* m_pAddress;
	std::size_t m_unSize;
	bool m_bInitialized;
};
```

```cpp
// SomeObject.cpp
SomeObject::SomeObject() noexcept {
	m_pAddress = nullptr;
	m_unSize = 0;
	m_bInitialized = false;
}
```

### 21.3. Canonical Overload Family

```cpp
bool FindByName(char const* pszName) noexcept;
bool FindByAddress(void const* pAddress) noexcept;
bool FindByIndex(std::size_t unIndex) noexcept;
```

### 21.4. Canonical Low-Level Record

```cpp
typedef struct _SOME_RECORD {
	void* m_pAddress;
	std::size_t m_unSize;
	bool m_bActive;
} SOME_RECORD, *PSOME_RECORD;

static_assert(std::is_standard_layout_v<SOME_RECORD>, "SOME_RECORD must remain standard-layout");
static_assert(std::is_trivially_copyable_v<SOME_RECORD>, "SOME_RECORD must remain trivially copyable");
```

### 21.5. Canonical Header-Only Compile-Time Utility

```cpp
#pragma once

#ifndef _SOMELIBCOMPILETIMEUTILITY_H_
#define _SOMELIBCOMPILETIMEUTILITY_H_

// C++
#include <cstddef>
#include <cstdint>

// STL
#include <type_traits>

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

	constexpr std::uint32_t kFNV32OffsetBasis = static_cast<std::uint32_t>(2166136261);
	constexpr std::uint32_t kFNV32Prime = 16777619;

	COMPILETIMEUTILITY_FORCE_INLINE constexpr std::uint32_t HashByte(const std::uint32_t unState, const unsigned char unByte) noexcept {
		return (unState * kFNV32Prime) ^ unByte;
	}

	template <std::size_t unLength>
	consteval std::uint32_t Hash(char const(&szText)[unLength]) noexcept {
		static_assert(unLength > 0, "string extent must include a terminator");

		std::uint32_t unHash = kFNV32OffsetBasis;

		for (std::size_t unIndex = 0; unIndex < (unLength - 1); ++unIndex) {
			unHash = HashByte(unHash, static_cast<unsigned char>(szText[unIndex]));
		}

		return unHash;
	}

} // namespace CompileTimeUtility

#define COMPILE_TIME_HASH(STRING) CompileTimeUtility::Hash(STRING)

#undef COMPILETIMEUTILITY_FORCE_INLINE

#endif // _SOMELIBCOMPILETIMEUTILITY_H_
```

---

## 22. Rules in MUST / SHOULD / MAY Form

### MUST

- Put `{` on the same line as the controlling construct or ordinary function signature; use the documented constructor-initializer-list exception.
- Use braces for every branch and loop body.
- Use tabs as the primary code indentation unit.
- Follow the repository ownership map: never style-edit vendored dependencies or protected compatibility files without explicit authorization.
- Use the canonical include-group labels and classification, and obey the first-line own-header/empty-line rule for translation units.
- Keep one naming convention inside a file and use semantic role names. Primitive pointers combine `p` with the pointee category (`pn`, `pun`, `pb`, `pfl`, `pdbl`, `pch`, `pwch`, `psz`); object, user-defined/non-primitive, opaque, and `void` pointers use bare `p`.
- Reserve `k` only for named `constexpr` constants.
- Use west `const` for simple scalar values and the compound-type placement from section 9.2 for pointers and references.
- Call qualified standard algorithms as `std::max(...)` and `std::min(...)`; never as `(std::max)(...)` or `(std::min)(...)`.
- Do not use integer-literal suffixes such as `U`, `UL`, `ULL`, `L`, or their lower-case/combined variants unless the code materially requires them for type, range, overload, shift, ABI, or constant-evaluation correctness.
- Keep declarations in dependency order and constants before first use; do not use forward prototypes or declaration-only aliases to bypass reorderable implementation dependencies.
- Avoid reserved project identifiers outside the documented compatibility profile, C-style casts, and unchecked narrowing.
- Do not use `[[maybe_unused]]` or ignored-result casts; remove unused declarations or apply only the narrow conditional/ABI procedure from section 9.12.
- Declare exactly one variable or object per declaration statement.
- Use `Type Name = Expression;` for every copy or conversion initialization where that form is well-formed and semantics-preserving; do not spell the same initialization as `Type Name { Expression };` or `Type Name(Expression);`. Use the narrow semantic exceptions from section 7.9 only when required.
- In an explicitly typed function, use `return {};` for an empty value-initialized result whenever that form is well-formed and semantics-preserving; do not repeat the return type.
- Keep project C/C++ function signatures on one physical line and keep simple calls on one line.
- Keep short boolean predicates and boolean returns on one physical line when their operands are direct checks, loads, comparisons, or logical operators; wrap only genuinely complex expressions. When wrapping a boolean expression, break at logical operators, preserve comparisons and nested logical/arithmetic groups with parentheses, and do not add an outer pair around a simple boolean name, pointer check, unary-negation check, or function-call result, as described in section 6.4.
- Put exactly one blank line after a standalone closing `}` before the next ordinary statement, declaration, or expression; do not insert that blank line before another `}`, `else`, `catch`, `while`, a required semicolon, a preprocessor directive, or an existing blank line, as specified in section 6.2.
- Inside an early-exit branch, keep its single final call, assignment, declaration, diagnostic, cleanup, or other action directly adjacent to the simple one-line return that completes that branch. Keep one blank line between a final main-path output/result commit and the function's final success return.
- Use `auto` for iterators and range elements with the required qualifiers; use `decltype` only for a genuinely expression-dependent type that the approved explicit-type or `auto` forms cannot express correctly.
- Use an explicit ownership type for allocations/smart pointers and an explicit type for ABI/system records.
- Start externally callable functions with required invariant/input validation.
- Make ownership, nullability, extent, and lifetime visible.
- Validate integer operations and complete address ranges before use.
- Verify relied-on ABI layouts with `static_assert`.
- Attach acquired resources to owners immediately or keep manual cleanup explicit on every path.
- Capture transient platform error state immediately after failure.
- Keep temporary macros narrow and `#undef` them after use.
- Reject unsupported architectures, formats, versions, and widths clearly.
- Initialize every variable, object, array, structure, class, and member before its first use; never read indeterminate storage.
- Use `= default` for constructors only when they have no arguments and the generated construction leaves every member in a valid state.
- Declare non-template constructors in headers and define them in source files; keep their initializer lists and bodies in the `.cpp`, use body assignment or an initializer list exactly as required by section 10.3, and do not use in-class/default member initializers. A required caller-visible constructor template may remain as a thin forwarding adapter in the header, but its real non-template constructor definition still belongs in the `.cpp`.
- Remove declarations that are unused in every supported configuration; use only adjacent, case-specific warning suppression for a required conditional/ABI declaration and restore diagnostics immediately.
- Use the canonical logging severity vocabulary, keep severity prefixes out of `Log*` message text, and preserve the same diagnostic fields in terminal and file output.
- For state-changing CLI commands, print exactly one documented success or failure marker only after a syntactically valid operation has run; malformed input prints help without a result marker.
- Preserve public ABI, serialized, generated, and CLI contracts unless a breaking change is explicitly requested.

### SHOULD

- Prefer explicit, information-rich signatures over shortened signatures that hide meaning.
- Prefer explicit types for named objects, use the section 7.9 `=` form whenever copy-initialization is available, and reserve `auto` for the cases in section 11.4.
- Preserve a phase-based structure with guard clauses and early returns.
- Callers should handle status values explicitly when the status affects correctness; otherwise a normal call is sufficient. Add a short comment when ignoring the result is not obvious.
- Prefer RAII and `std::unique_ptr` for local single ownership.
- Keep platform/ABI branches explicit and test each supported architecture.
- Isolate byte, endian, bit, and representation conversion in small helpers.
- Use `std::array`, `std::span`, array references, and `std::string_view` when extent/lifetime remains visible.
- Keep lock scope local, define lock ordering, and avoid callbacks while holding locks.
- Clear temporary plaintext and sensitive buffers when practical.
- Keep compile-time obfuscation and hashing claims limited to actual guarantees.
- Update focused tests when behavior or generated contracts change.

### MAY

- Use compiler/platform pragmas when the target requires them.
- Use `reinterpret_cast`, unions, bitfields, macros, raw arrays, and byte arithmetic in reviewed low-level sections.
- Use `constexpr`, `consteval`, non-type template parameters, and macro facades for compile-time utilities.
- Use A/W API families where they match the platform domain.
- Use explicit manual lifecycle or cleanup labels when they are clearer at a C/ABI boundary.
- Use a direct guarded statement-like cleanup macro only under the standalone-use and side-effect-free-argument restrictions in section 4.7.
- Use exceptions in subsystems that consistently define and contain that error model.

---

## 23. One-Line Summary

Write code so that a systems programmer can read it top-to-bottom, see ownership and dependencies immediately, and trust that names, constants, macros, buffers, and control flow mean exactly what they say.

---

## 24. Non-Goals

This guide does not:

- replace language, ABI, platform, security, or cryptographic specifications;
- require every permitted low-level tool in every subsystem;
- justify abstraction, templates, macros, or raw memory access when a simpler typed solution is clearer;
- require style-only churn during an unrelated behavioral fix;
- guarantee correctness merely because formatting and naming checks pass;
- override externally defined identifiers, layouts, calling conventions, or serialized representations;
- treat compile-time transformation, obfuscation, or embedded constants as a secret-management boundary.

---

## 25. Portable Maintenance and Verification Rules

These rules are a repository-level checklist for cleanup work, generated code, documentation, tests, and AI-assisted edits.

### 25.1. Behavior-Preserving Cleanup

When cleaning code:

- remove unused parameters from private/internal functions and update every call site;
- remove unused locals, dead branches, stale comments, and unreachable code;
- remove an include only after checking every build target that depends on the file;
- merge temporary variables only when the resulting expression remains easy to audit;
- extract a helper only when it has a stable responsibility or removes meaningful repetition;
- preserve public APIs, callback signatures, calling conventions, binary layouts, generated formats, and command-line compatibility unless a breaking change is requested;
- separate style-only churn from behavior changes when practical.

### 25.2. Generated Artifact Ownership

Generated source, scripts, configuration, and examples follow the same style rules as hand-written files.

- generated-only files may be overwritten and should say so in a header comment when users may open them;
- user-editable files live in an obvious `user/` or `custom/` area or in stable generated regions;
- mixed generated/user files preserve user regions exactly unless a documented migration rewrites them;
- regeneration removes stale files only from the same generated family;
- public generated APIs stay small and typed;
- generated examples are compile-ready and copy-paste safe;
- recovery/post-processing updates only affected artifacts and reuses existing cache/build directories where safe;
- archive extraction rejects absolute paths, parent traversal, and paths outside the target root.

### 25.3. Logging and Terminal Output

Normal output must be complete and redirect-safe. Only an interactive renderer may visually clip or rewrite a live line; redirected logs must never contain spinner control sequences or truncated records.

#### Severity and Message Ownership

Use one severity vocabulary consistently for file and terminal diagnostics:

- `[DEBUG]` debug-only diagnostic detail;
- `[INFO]` ordinary informational state or successful progress;
- `[WARNING]` recoverable problem, fallback, retry, or degraded behavior;
- `[ERROR]` failed operation or unrecoverable result.

The logging function owns the severity prefix. Text passed to `LogDebug`, `LogInfo`, `LogWarning`, or `LogError` must begin with the operation/context itself and must not add a standalone `DEBUG`, `INFO`, `WARNING`, `ERROR`, or equivalent severity prefix. Do not produce duplicated forms such as `[ERROR] ERROR: OpenResource failed`, and do not calculate, detect, strip, or skip a textual severity prefix at runtime. Write the message correctly at its call site.

Correct:

```cpp
LogError("OpenResource failed Error=0x%08X", unError);
```

Incorrect:

```cpp
LogError("ERROR: OpenResource failed Error=0x%08X", unError);
```

A file log may place timestamp/process/thread metadata before the severity, but the severity remains one bracketed field:

```text
[2026-08-21 12:34:56.789] [Process=100 Thread=200] [ERROR] OpenResource failed Error=0x00000005
```

When the same event is written both to the terminal and to a file, both outputs must contain the same operation, result, identifiers, paths, sizes, and error/status values. Presentation metadata may differ, but the console must not reduce a detailed file diagnostic to a generic message. Capture transient platform error state before either output path.

#### Diagnostic Fields

Use stable key/value field names and spellings so terminal output, file logs, tests, and searches agree:

- `Error=0x%08X` for a platform error whose width is contractually hexadecimal;
- `Status=0x%08X` for a platform or library status value with the same hexadecimal contract;
- `HRESULT=0x%08X` for an HRESULT-style status value;
- `Result=%d` or a more specific semantic name for an ordinary signed result code;
- `Process=%lu`, `Thread=%lu`, `Address=%p`, `Size=%zu`, and `Path="..."` when those fields are relevant.

Capture the platform or library's transient error value immediately after the failing operation and before cleanup, logging, formatting, allocation, or terminal output. Do not fetch the error again independently for the console and file paths. One captured value owns both diagnostics.

Put the failed operation first, followed by semantic fields:

```cpp
LogError("ReadProcessResult failed Process=%lu Error=0x%08X", unProcessID, unError);
```

Do not use inconsistent alternatives such as `Error =`, `error=`, `ErrorCode=`, or a decimal error for the same field family.

#### Target-Scoped Log Files

When a tool operates on a target process, file, workspace, or device, store target-scoped diagnostics according to the target's canonical identity rather than the launcher or current directory. Resolve the canonical target path or identifier once, derive a collision-resistant base name, and document the naming scheme in the project's local documentation.

Do not silently write a log next to the wrong target, fall back to an ambiguous basename, or relocate a log without reporting the attempted and final paths. If the target identity cannot be resolved or the selected directory is not writable, report that failure through the available terminal diagnostic. Keep architecture, debug/release, and other session qualifiers in a stable documented position instead of deriving them from display text.

#### CLI Help and Result Markers

Parse and validate the complete command line before executing or emitting an operation result. No arguments, an unknown command, a missing required operand, an extra unsupported operand, or an invalid flag value prints the version/help/usage response and returns the parser's documented exit code. It must not print an operation-failure marker because no operation was attempted.

After a syntactically valid state-changing operation runs, print exactly one final success or failure marker using the project's documented vocabulary. The marker is the final terminal line for that operation, is not written as a log severity, and never replaces the detailed diagnostic that explains a failure. The process exit code must agree with the marker. Reporting and query commands should not append a state-changing result marker. A relaunch/elevation parent or wrapper propagates the child exit code and must not print a second marker.

Debug-only diagnostics compile and emit only in a debug configuration. Diagnostic macros may capture file and line, but the implementation remains a typed, thread-safe logging function.

Debug-only terminal output remains inside the debug conditional. When debug file logging is enabled, emit the same debug event through the typed logger so that the debug log and console remain correlated.

Do not log secrets, authentication material, plaintext keys, or full sensitive buffers. State whether elapsed time is stage time or total time.

### 25.4. Markdown Documentation

Markdown is project knowledge, not decoration. An important document should explain:

- where the component lives;
- what it does;
- when it is used;
- why the approach exists;
- how to use it safely;
- related files, limitations, and common mistakes.

Use spaces for Markdown prose indentation. Inside fenced code blocks, follow the target language style.

Large Markdown files should start with an AI-processing/navigation note and include a table of contents. Do not invent architecture that is not present in code or supported by the referenced source.

### 25.5. AI-Agent Editing Rules

An AI agent must:

- read the relevant implementation, declarations, tests, and local instructions before editing;
- make direct structural edits instead of appending a one-off normalization pass;
- process huge generated files and output trees by focused sections;
- preserve unrelated dirty work and user-owned regions;
- avoid repeating a question already answered by the repository or conversation context;
- update this guide when a new recurring project-wide rule is established;
- update tests and documentation when behavior or generated contracts change;
- run the smallest useful verification first, then broaden only as the affected surface requires;
- report what was verified and what was not verified without inventing success.

### 25.6. Builds, Warnings, and Tests

Tests are the executable contract for the project and generated output.

- keep tests under a predictable directory such as `tests/` and reusable inputs under `tests/fixtures/`;
- use one test module/script per scenario and name it after the behavior it verifies;
- accept common build-configuration and architecture parameters when the project supports them;
- compile edited targets with the project's strict warning level and treat new warnings as failures;
- remove completely unused functions, classes, structs, enums, aliases, parameters, variables, members, constants, macros, includes, and other declarations instead of suppressing their warnings; when a supported conditional case requires a declaration that is unused elsewhere, use only an adjacent, case-specific suppression and restore the warning state immediately;
- test debug and release behavior when macros, optimization, assertions, logging, or layout may differ;
- test every supported architecture whose ABI/layout path changed;
- use ASan, UBSan, iterator diagnostics, or platform equivalents where compatible;
- add focused boundary/failure tests for parsers, pointer ranges, integer overflow, allocation failure, and malformed inputs;
- test deterministic regeneration and stale-file cleanup when generator contracts change;
- run the smallest relevant test first, then broader integration/regression tests for shared infrastructure and public APIs.

### 25.7. Mechanical Enforcement

The project's canonical high-confidence audit entry point should be a read-only command documented by the repository. For example:

```powershell
<project-style-check-command>
```

If the project provides such a script, it must be read-only by default, audit project-owned text/source files, and exclude the ownership exceptions from section 2.5. An explicit diagnostic option may include protected compatibility files in output, but it must not authorize modification. Regex findings that need semantic judgment are review items, not compiler/parser proof. If no checker exists, document the available formatter, linter, or manual verification commands instead of inventing a repository-specific path.

If the checker supports a changed-only mode, use it for the first focused pass over working-tree, index, and untracked changes. A final verification still runs the default full-repository command.

A project adopting this guide should maintain:

- `.editorconfig` for tabs, line endings, final newline, and trailing whitespace;
- a formatter configuration for braces, indentation, and basic wrapping;
- a style-audit/linter for naming, `k` usage, reserved identifiers outside documented profile exceptions, C-style casts, incorrect `auto` / `decltype` use, include groups, constructor shape, and generated source;
- compile-time layout checks for ABI records;
- CI jobs that run formatting/style checks, builds, focused tests, and required architecture matrices.

At minimum, a style verification pass must check:

1. tabs for code indentation and no leading-space indentation in project C/C++ files;
2. no trailing whitespace, no accidental repeated blank lines, and a final newline;
3. exact 64-character `=` / `-` section banners;
4. only the canonical include-group labels and the project header classification from section 4.2;
5. no `[[maybe_unused]]`, ignored-result casts, C-style casts, or broad warning suppressions;
6. `auto` for iterators and range elements according to the section 11.4 matrix;
7. no `decltype` used as an iterator/range/object spelling shortcut;
8. explicit owner and ABI/system-record types, plus the section 8.2 primitive-pointer prefix composition and bare-`p` object/custom-type rule;
9. one declaration per statement and no combined array/pointer declarations;
10. `=` for every declaration that can copy- or conversion-initialize without a semantic change, with each one-expression `{ Expression }` or `(Expression)` declaration justified by a section 7.9 exception;
11. `return {};` for every well-formed, semantics-preserving empty value-initialized result in an explicitly typed function, with no redundant repeated return type;
12. direct qualified standard algorithm calls as `std::max(...)` / `std::min(...)`, with no `(std::max)(...)` / `(std::min)(...)` spelling;
13. no redundant integer-literal suffixes such as `U`, `UL`, `ULL`, `L`, or their lower-case/combined variants unless code requires them materially;
14. one-line signatures and one-line simple calls, with only justified complex wrapping;
15. exactly one blank line after a standalone closing `}` before the next ordinary statement/declaration/expression, excluding another `}`, `else`, `catch`, `while`, a required semicolon, a preprocessor directive, or an existing blank line;
16. no blank line between one final action and the simple one-line return that completes an early-exit branch, plus one blank line between a final main-path output/result commit and the function's final success return;
17. constructor declaration/definition placement, initializer ordering, and initialization of every member;
18. no message-level severity prefix passed to `Log*` functions;
19. no unused warnings in every supported build configuration;
20. clean repository diff with no generated or dependency changes outside the requested scope;
21. guide self-consistency: positive/canonical examples follow the guide, negative examples are explicitly labeled, and the MUST/SHOULD/MAY summary remains synchronized with detailed rules.

Useful first-pass searches include:

```text
<project-style-check-command>
git diff --check
rg -n "\[\[maybe_unused\]\]|static_cast<void>\s*\(" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "decltype\s*\([^)]*\.(begin|end)\s*\(" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "remove_reference_t\s*<\s*decltype|value_type\s+const&" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "^// (C\+\+ standard library|Standard|Runtime)$" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "^// [=-]+$" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "^// (={64}|-{64})$" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "^ +\S" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "[ \t]+$" .
rg -U -n "\r?\n\r?\n\r?\n" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "Log(Debug|Info|Warning|Error)\([^\n]*\b(DEBUG|INFO|WARNING|ERROR):" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
rg -n "#pragma (warning|GCC diagnostic|clang diagnostic)" -g "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}" .
```

The first banner search lists every banner candidate; the second lists only correctly sized banners. Compare the result sets rather than treating the second search alone as proof.

These searches are audit candidates, not proof by themselves: generated code, external dependencies, protected compatibility files, strings, comments, negative documentation examples, and ABI declarations may produce false positives. Restrict paths to project-owned code and review every match. Approved expression-dependent `decltype` uses should be documented by the local project; investigate other matches independently. Use a parser-aware linter or compiler diagnostics for C-style casts, declaration structure, unused entities, and type-sensitive rules that regular expressions cannot prove.

The verification sequence is:

1. run focused searches for the edited rule;
2. run `git diff --check` and inspect the complete diff;
3. run the formatter in check-only mode only when its configuration agrees with this guide;
4. build every affected debug/release and architecture configuration with warnings enabled;
5. run focused tests, then broader tests for shared behavior;
6. repeat the style pass if any check or build-driven fix changes project code.

Formatter output is not proof of semantic correctness and must not overwrite an intentional guide rule merely because the formatter cannot express it. Review ownership, error propagation, ranges, concurrency, ABI, constructor validity, diagnostic fidelity, and generated contracts separately.

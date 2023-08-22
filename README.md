# Detours
A set of tools for working with software modifications.

# Definitions
* `LINKER_OPTION(OPTION)` - Passing a parameter to the compiler.
* `INCLUDE(SYMBOL_NAME)` - Forces the compiler to include and link the given symbol.
* `SELF_INCLUDE` - Same as above but easy to use inside a function to include and link the function itself.
* `EXPORT(SYMBOL_NAME, ALIAS_NAME)` - Exports a symbol under a specific name.
* `SELF_EXPORT(ALIAS_NAME)` - Same as above but easy to use inside a function to export the function itself.
* `DECLARE_SECTION(NAME, ATTRIBUTES)` - Declares a new section.
* `DEFINE_SECTION(NAME)` - Defines a new section.
* `DEFINE_IN_SECTION(NAME)` - Allocates data to a section.

# Detours::KUserSharedData
* A data area structure that the kernel allocates for sharing with user-mode software.

# Detours::GetPEB
* Contains information on the currently running process.

# Detours::GetTEB
* Contains information on the currently running thread.

# Detours::Codec
* Allows to encode and decode text into different encodings.

# Detours::Hexadecimal
* Allows to encode and decode text in hexadecimal encoding.

# Detours::Scan
* Scanners for patterns and data.

# Detours::RTTI
* RTTI search and casting, and VTable search by RTTI.

# Detours::Memory
* Memory management such as Shared Memory, Protection and Pages.

# Detours::Exception
* Global exception handler.

# Detours::rddiaasm
* Dissambler.

# Detours::Hook
* Hooks for intercepting memory access or execution, executing interrupts, all or part of a VTable, API, or specific instructions.

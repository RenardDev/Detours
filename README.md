# Detours
A set of tools for working with software modifications.

# Definitions
* `LINKER_OPTION(OPTION)` - Macro for passing a parameter to the MSVC linker.
* `INCLUDE(SYMBOL_NAME)` - Macro for forcing the inclusion of a symbol in the build.
* `SELF_INCLUDE` - Macro for self-inclusion in the build, equivalent to `INCLUDE(FUNCDNAME)`.
* `EXPORT(SYMBOL_NAME, ALIAS_NAME)` - Macro for exporting a symbol with an alias in MSVC.
* `SELF_EXPORT(ALIAS_NAME)` - Macro for self-exporting a symbol with an alias, equivalent to `EXPORT(FUNCDNAME, ALIAS_NAME)`.
* `DECLARE_SECTION(NAME)` - Macro for declaring a section for use with `DEFINE_IN_SECTION`.
* `DEFINE_SECTION(NAME, ATTRIBUTES)` - Macro for defining or redefining a section with specified attributes.
* `DEFINE_IN_SECTION(NAME)` - Macro for defining data in a section specified by its name.
* `DEFINE_IN_CODE_SECTION(NAME)` - Macro for defining code in a section not created by `DECLARE_SECTION` but defined by `DEFINE_SECTION`.

# Detours
* KUserSharedData - A data area structure that the kernel allocates for sharing with user-mode software.
* KUserQpcSharedData - A data area structure that the kernel allocates for sharing with QueryPerformanceCounter in user-mode software.
* GetPEB - Gets *Process Environment Block* (PEB) of the currently running process.
* GetTEB - Gets *Thread Environment Block* (TEB) of the current thread or thread from a handle.

# Detours::LDR
* FindModuleListEntry - Finds a module list entry.
* FindModuleDataTableEntry - Finds a module data table entry.
* LINK_DATA - A structure containing pointers to various linked lists related to module loading.
* UnLinkModule - Unlinks a module from linked lists using the base address, module handle, or module name. It takes a LINK_DATA structure as an additional parameter.
* ReLinkModule - Relinks a module back into the linked lists using a provided LINK_DATA structure.

# Detours::Codec
* Encode - Converts a sequence of characters from a specified character encoding to another.
* Decode - Converts a sequence of characters from a specified wide-character encoding to another.

# Detours::Hexadecimal
* Encode - Converts binary data into a hexadecimal representation with an optional ignored byte.
* Decode - Converts a hexadecimal string back to binary data with an optional ignored byte.

# Detours::Scan
* FindSection - Locates a section within the specified module based on the provided section name.
* FindSectionPOGO - Locates a POGO section within the specified module based on the provided section name.
* FindSignature - Searches for a signature pattern.
* FindData - Searches for a specified data pattern.

# Detours::RTTI
* Object - Represents an object in memory with rich type information, including its base classes, type descriptor, class hierarchy descriptor, complete object locator, and virtual function table (VTable). The class supports dynamic casting for polymorphic objects.
* FindObject - Locates an object in memory based on specified parameters, including module information, object name, and whether to search for the complete object.

# Detours::Sync
* Event - Represents an event synchronization object, providing functionalities for signaling, resetting, pulsing, and waiting on events.
* EventServer - Specialized version of the Event class designed for server-side usage. Includes functionalities for obtaining the event name.
* EventClient - Specialized version of the Event class designed for client-side usage. Supports synchronization with server events.
* Mutex - Represents a mutex synchronization object, providing functionalities for locking and unlocking.
* MutexServer - Specialized version of the Mutex class designed for server-side usage. Includes functionalities for obtaining the mutex name.
* MutexClient - Specialized version of the Mutex class designed for client-side usage. Supports synchronization with server mutexes.
* Semaphore - Represents a semaphore synchronization object, providing functionalities for entering and leaving.
* SemaphoreServer - Specialized version of the Semaphore class designed for server-side usage. Includes functionalities for obtaining the semaphore name.
* SemaphoreClient - Specialized version of the Semaphore class designed for client-side usage. Supports synchronization with server semaphores.
* CriticalSection - Represents a critical section synchronization object, providing functionalities for entering and leaving.
* SRWLock - Represents a slim reader/writer (SRW) lock synchronization object, providing functionalities for acquiring and releasing.
* ConditionVariable - Represents a condition variable synchronization object, providing functionalities for sleeping, waking, and waking all.
* Suspender - Manages the suspension and resumption of threads. Supports fixing the execution address of suspended threads.
* g_Suspender - Global instance of the *Suspender*.

# Detours::Pipe
* PipeServer - Represents a server-side named pipe, facilitating communication with a client using a specified buffer size.
* PipeClient - Represents a client-side connection to a named pipe server, supporting communication with a specified buffer size.

# Detours::Parallel
* Thread - Represents a lightweight thread with a callback function and associated data.
* Fiber - Represents a lightweight fiber with a callback function and associated data.

# Detours::Memory
* Shared - Represents a shared memory region.
* SharedServer - Represents a server-side shared memory region.
* SharedClient - Represents a client-side connection to a shared memory region.
* Page - Manages a memory page with allocation and deallocation capabilities.
* NearPage - Manages a memory page with near allocations to a desired address.
* Storage - Manages a collection of pages to provide a storage space for allocations.
* NearStorage - Manages a collection of near pages to provide storage with near allocations.
* Protection - Manages memory protection for a specified range of memory.

# Detours::Exception
* ExceptionListener - Manages exception handling through a vectored exception handler (VEH) and provides a mechanism for adding and removing callback functions to handle exceptions.
* g_ExceptionListener - Global instance of the *ExceptionListener*.

# Detours::rddiaasm
* RdInitContext - Initializes the decoding context structure.
* RdDecodeWithContext - Decodes an instruction using the specified decoding context.
* RdDecodeEx - Decodes an instruction with extended options.
* RdDecode - Decodes an instruction.
* RdIsInstruxRipRelative - Checks if the decoded instruction is RIP-relative.
* RdGetFullAccessMap - Retrieves the full access map for the decoded instruction.
* RdGetOperandRlut - Retrieves the operand register lookup table for the decoded instruction.

# Detours::Hook
* HookMemory - Hooks a memory address with the specified callback and auto-disable option.
* UnHookMemory - Unhooks a memory address with the specified callback.
* EnableHookMemory - Enables a previously disabled memory hook.
* DisableHookMemory - Disables a memory hook.
* HookInterrupt - Hooks the specified interrupt with the given callback.
* UnHookInterrupt - Unhooks the specified interrupt.
* VTableFunctionHook - Class for hooking virtual table (VTable) functions.
* VTableHook - Class for hooking virtual tables (VTables).
* InlineHook - Class for hooking functions using inline hooking technique. (Has support for checking Return Address to avoid crashes after unhook)
* InlineWrapperHook - Class for hooking functions using inline hooking with a wrapper function. (Has support for checking Return Address to avoid crashes after unhook)
* RawHook - Class for raw hooking functions with full control over registers and the stack. (Has support for checking Return Address to avoid crashes after unhook)

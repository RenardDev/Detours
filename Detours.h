#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

// Default
#include <Windows.h>

// C++
#include <cstdlib>

// STL
#include <array>
#include <deque>
#include <memory>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#ifndef PROCESSOR_FEATURE_MAX
#define PROCESSOR_FEATURE_MAX 64
#endif // !PROCESSOR_FEATURE_MAX

#ifndef RTL_MAX_DRIVE_LETTERS
#define RTL_MAX_DRIVE_LETTERS 32
#endif // !RTL_MAX_DRIVE_LETTERS

#ifndef GDI_HANDLE_BUFFER_SIZE32
#define GDI_HANDLE_BUFFER_SIZE32 34
#endif // !GDI_HANDLE_BUFFER_SIZE32

#ifndef GDI_HANDLE_BUFFER_SIZE64
#define GDI_HANDLE_BUFFER_SIZE64 60
#endif // !GDI_HANDLE_BUFFER_SIZE64

#ifndef GDI_BATCH_BUFFER_SIZE
#define GDI_BATCH_BUFFER_SIZE 310
#endif // !GDI_BATCH_BUFFER_SIZE

#ifdef _M_X64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#elif _M_IX86
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#error Only x86 and x86_64 platforms are supported.
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) (x >= 0)
#endif

// MSVC - Linker
#define LINKER_OPTION(OPTION) __pragma(comment(linker, OPTION))

// MSVC - Symbols
#define INCLUDE(SYMBOL_NAME) LINKER_OPTION("/INCLUDE:" SYMBOL_NAME)
#define SELF_INCLUDE INCLUDE(__FUNCDNAME__)
#define EXPORT(SYMBOL_NAME, ALIAS_NAME) LINKER_OPTION("/EXPORT:" ALIAS_NAME "=" SYMBOL_NAME)
#define SELF_EXPORT(ALIAS_NAME) EXPORT(__FUNCDNAME__, ALIAS_NAME)

// MSVC - Sections
#define CODE_SECTION_BEGIN(IDENTIFIER, SECTION_NAME) __pragma(code_seg(push, IDENTIFIER, SECTION_NAME))
#define CODE_SECTION_END(IDENTIFIER) __pragma(code_seg(pop, IDENTIFIER))
#define DATA_SECTION_BEGIN(IDENTIFIER, SECTION_NAME) __pragma(data_seg(push, IDENTIFIER, SECTION_NAME))
#define DATA_SECTION_END(IDENTIFIER) __pragma(data_seg(pop, IDENTIFIER))

// ----------------------------------------------------------------
// Detours
// ----------------------------------------------------------------

namespace Detours {

	// ----------------------------------------------------------------
	// KUSER_SHARED_DATA
	// ----------------------------------------------------------------

	typedef enum _NT_PRODUCT_TYPE {
		NtProductWinNt = 1,
		NtProductLanManNt,
		NtProductServer
	} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
		StandardDesign,
		NEC98x86,
		EndAlternatives
	} ALTERNATIVE_ARCHITECTURE_TYPE, *PALTERNATIVE_ARCHITECTURE_TYPE;

	typedef struct _KSYSTEM_TIME {
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, *PKSYSTEM_TIME;

	typedef struct _KUSER_SHARED_DATA {
		ULONG TickCountLowDeprecated;
		ULONG TickCountMultiplier;
		volatile KSYSTEM_TIME InterruptTime;
		volatile KSYSTEM_TIME SystemTime;
		volatile KSYSTEM_TIME TimeZoneBias;
		USHORT ImageNumberLow;
		USHORT ImageNumberHigh;
		WCHAR NtSystemRoot[260];
		ULONG MaxStackTraceDepth;
		ULONG CryptoExponent;
		ULONG TimeZoneId;
		ULONG LargePageMinimum;
		ULONG AitSamplingValue;
		ULONG AppCompatFlag;
		ULONGLONG RNGSeedVersion;
		ULONG GlobalValidationRunlevel;
		volatile LONG TimeZoneBiasStamp;
		ULONG NtBuildNumber;
		NT_PRODUCT_TYPE NtProductType;
		BOOLEAN ProductTypeIsValid;
		BOOLEAN Reserved0[1];
		USHORT NativeProcessorArchitecture;
		ULONG NtMajorVersion;
		ULONG NtMinorVersion;
		BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
		ULONG Reserved1;
		ULONG Reserved3;
		volatile ULONG TimeSlip;
		ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
		ULONG BootId;
		LARGE_INTEGER SystemExpirationDate;
		ULONG SuiteMask;
		BOOLEAN KdDebuggerEnabled;
		union {
			UCHAR MitigationPolicies;
			struct {
				UCHAR NXSupportPolicy : 2;
				UCHAR SEHValidationPolicy : 2;
				UCHAR CurDirDevicesSkippedForDlls : 2;
				UCHAR Reserved : 2;
			};
		};
		USHORT CyclesPerYield;
		volatile ULONG ActiveConsoleId;
		volatile ULONG DismountCount;
		ULONG ComPlusPackage;
		ULONG LastSystemRITEventTickCount;
		ULONG NumberOfPhysicalPages;
		BOOLEAN SafeBootMode;
		UCHAR VirtualizationFlags;
		UCHAR Reserved12[2];
		union {
			ULONG SharedDataFlags;
			struct {
				ULONG DbgErrorPortPresent : 1;
				ULONG DbgElevationEnabled : 1;
				ULONG DbgVirtEnabled : 1;
				ULONG DbgInstallerDetectEnabled : 1;
				ULONG DbgLkgEnabled : 1;
				ULONG DbgDynProcessorEnabled : 1;
				ULONG DbgConsoleBrokerEnabled : 1;
				ULONG DbgSecureBootEnabled : 1;
				ULONG DbgMultiSessionSku : 1;
				ULONG DbgMultiUsersInSessionSku : 1;
				ULONG DbgStateSeparationEnabled : 1;
				ULONG SpareBits : 21;
			};
		};
		ULONG DataFlagsPad[1];
		ULONGLONG TestRetInstruction;
		LONGLONG QpcFrequency;
		ULONG SystemCall;
		ULONG Reserved2;
		ULONGLONG SystemCallPad[2];
		union {
			volatile KSYSTEM_TIME TickCount;
			volatile ULONG64 TickCountQuad;
			struct {
				ULONG ReservedTickCountOverlay[3];
				ULONG TickCountPad[1];
			};
		};
		ULONG Cookie;
		ULONG CookiePad[1];
		LONGLONG ConsoleSessionForegroundProcessId;
		ULONGLONG TimeUpdateLock;
		ULONGLONG BaselineSystemTimeQpc;
		ULONGLONG BaselineInterruptTimeQpc;
		ULONGLONG QpcSystemTimeIncrement;
		ULONGLONG QpcInterruptTimeIncrement;
		UCHAR QpcSystemTimeIncrementShift;
		UCHAR QpcInterruptTimeIncrementShift;
		USHORT UnparkedProcessorCount;
		ULONG EnclaveFeatureMask[4];
		ULONG TelemetryCoverageRound;
		USHORT UserModeGlobalLogger[16];
		ULONG ImageFileExecutionOptions;
		ULONG LangGenerationCount;
		ULONGLONG Reserved4;
		volatile ULONGLONG InterruptTimeBias;
		volatile ULONGLONG QpcBias;
		ULONG ActiveProcessorCount;
		volatile UCHAR ActiveGroupCount;
		UCHAR Reserved9;
		union {
			USHORT QpcData;
			struct {
				volatile UCHAR QpcBypassEnabled;
				UCHAR QpcShift;
			};
		};
		LARGE_INTEGER TimeZoneBiasEffectiveStart;
		LARGE_INTEGER TimeZoneBiasEffectiveEnd;
		XSTATE_CONFIGURATION XState;
		KSYSTEM_TIME FeatureConfigurationChangeStamp;
		ULONG Spare;
		ULONG64 UserPointerAuthMask;
	} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

	extern const volatile KUSER_SHARED_DATA& KUserSharedData;

	// ----------------------------------------------------------------
	// PEB
	// ----------------------------------------------------------------

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _CURDIR {
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, *PCURDIR;

	typedef struct _STRING {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} STRING, *PSTRING;

	typedef struct _RTL_DRIVE_LETTER_CURDIR {
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		STRING DosPath;
	} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;
		ULONG Length;
		ULONG Flags;
		ULONG DebugFlags;
		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;
		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;
		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;
		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
		UNICODE_STRING RedirectionDllName;
		UNICODE_STRING HeapPartitionName;
		ULONG_PTR DefaultThreadpoolCpuSetMasks;
		ULONG DefaultThreadpoolCpuSetMaskCount;
		ULONG DefaultThreadpoolThreadMaximum;
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _API_SET_NAMESPACE {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		ULONG EntryOffset;
		ULONG HashOffset;
		ULONG HashFactor;
	} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

	using GDI_HANDLE_BUFFER = ULONG[GDI_HANDLE_BUFFER_SIZE];
	using GDI_HANDLE_BUFFER32 = ULONG[GDI_HANDLE_BUFFER_SIZE32];
	using GDI_HANDLE_BUFFER64 = ULONG[GDI_HANDLE_BUFFER_SIZE64];

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union {
			BOOLEAN BitField;
			struct {
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN IsLongPathAwareProcess : 1;
			};
		};
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
		PSLIST_HEADER AtlThunkSListPtr;
		PVOID IFEOKey;
		union {
			ULONG CrossProcessFlags;
			struct {
				ULONG ProcessInJob : 1;
				ULONG ProcessInitializing : 1;
				ULONG ProcessUsingVEH : 1;
				ULONG ProcessUsingVCH : 1;
				ULONG ProcessUsingFTH : 1;
				ULONG ProcessPreviouslyThrottled : 1;
				ULONG ProcessCurrentlyThrottled : 1;
				ULONG ProcessImagesHotPatched : 1;
				ULONG ReservedBits0 : 24;
			};
		};
		union {
			PVOID KernelCallbackTable;
			PVOID UserSharedInfoPtr;
		};
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		PAPI_SET_NAMESPACE ApiSetMap;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];
		PVOID ReadOnlySharedMemoryBase;
		PVOID SharedData;
		PVOID* ReadOnlyStaticServerData;
		PVOID AnsiCodePageData;
		PVOID OemCodePageData;
		PVOID UnicodeCaseTableData;
		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;
		ULARGE_INTEGER CriticalSectionTimeout;
		SIZE_T HeapSegmentReserve;
		SIZE_T HeapSegmentCommit;
		SIZE_T HeapDeCommitTotalFreeThreshold;
		SIZE_T HeapDeCommitFreeBlockThreshold;
		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID* ProcessHeaps;
		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		ULONG GdiDCAttributeList;
		PRTL_CRITICAL_SECTION LoaderLock;
		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		USHORT OSBuildNumber;
		USHORT OSCSDVersion;
		ULONG OSPlatformId;
		ULONG ImageSubsystem;
		ULONG ImageSubsystemMajorVersion;
		ULONG ImageSubsystemMinorVersion;
		KAFFINITY ActiveProcessAffinityMask;
		GDI_HANDLE_BUFFER GdiHandleBuffer;
		PVOID PostProcessInitRoutine;
		PVOID TlsExpansionBitmap;
		ULONG TlsExpansionBitmapBits[32];
		ULONG SessionId;
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		PVOID pShimData;
		PVOID AppCompatInfo;
		UNICODE_STRING CSDVersion;
		PVOID ActivationContextData;
		PVOID ProcessAssemblyStorageMap;
		PVOID SystemDefaultActivationContextData;
		PVOID SystemAssemblyStorageMap;
		SIZE_T MinimumStackCommit;
		PVOID SparePointers[2];
		PVOID PatchLoaderData;
		PVOID ChpeV2ProcessInfo;
		ULONG AppModelFeatureState;
		ULONG SpareUlongs[2];
		USHORT ActiveCodePage;
		USHORT OemCodePage;
		USHORT UseCaseMapping;
		USHORT UnusedNlsField;
		PVOID WerRegistrationData;
		PVOID WerShipAssertPtr;
		union {
			PVOID pContextData;
			PVOID pUnused;
			PVOID EcCodeBitMap;
		};
		PVOID pImageHeaderHash;
		union {
			ULONG TracingFlags;
			struct {
				ULONG HeapTracingEnabled : 1;
				ULONG CritSecTracingEnabled : 1;
				ULONG LibLoaderTracingEnabled : 1;
				ULONG SpareTracingBits : 29;
			};
		};
		ULONGLONG CsrServerReadOnlySharedMemoryBase;
		PRTL_CRITICAL_SECTION TppWorkerpListLock;
		LIST_ENTRY TppWorkerpList;
		PVOID WaitOnAddressHashTable[128];
		PVOID TelemetryCoverageHeader;
		ULONG CloudFileFlags;
		ULONG CloudFileDiagFlags;
		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderCompatibilityModeReserved[7];
		struct _LEAP_SECOND_DATA* LeapSecondData;
		union {
			ULONG LeapSecondFlags;
			struct {
				ULONG SixtySecondEnabled : 1;
				ULONG Reserved : 31;
			};
		};
		ULONG NtGlobalFlag2;
		ULONGLONG ExtendedFeatureDisableMask;
	} PEB, *PPEB;

	const PPEB GetPEB();

	// ----------------------------------------------------------------
	// TEB
	// ----------------------------------------------------------------

	typedef struct _CLIENT_ID32 {
		ULONG UniqueProcess;
		ULONG UniqueThread;
	} CLIENT_ID32, *PCLIENT_ID32;

	typedef struct _CLIENT_ID64 {
		ULONGLONG UniqueProcess;
		ULONGLONG UniqueThread;
	} CLIENT_ID64, *PCLIENT_ID64;

#ifdef _M_X64
	typedef CLIENT_ID64 CLIENT_ID;
#elif _M_IX86
	typedef CLIENT_ID32 CLIENT_ID;
#endif

	typedef struct _ACTIVATION_CONTEXT_STACK {
		struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

	typedef struct _GDI_TEB_BATCH {
		ULONG Offset;
		ULONG_PTR HDC;
		ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
	} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

	typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
		ULONG Flags;
		PSTR FrameName;
	} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

	typedef struct _TEB_ACTIVE_FRAME {
		ULONG Flags;
		struct _TEB_ACTIVE_FRAME* Previous;
		PTEB_ACTIVE_FRAME_CONTEXT Context;
	} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

	typedef struct _TEB {
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PPEB ProcessEnvironmentBlock;
		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[26];
		ULONG UserReserved[5];
		PVOID WOW32Reserved;
		LCID CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _M_X64
		PVOID SystemReserved1[30];
#elif _M_IX86
		PVOID SystemReserved1[26];
#endif
		CHAR PlaceholderCompatibilityMode;
		BOOLEAN PlaceholderHydrationAlwaysExplicit;
		CHAR PlaceholderReserved[10];
		ULONG ProxiedProcessId;
		ACTIVATION_CONTEXT_STACK ActivationStack;
		UCHAR WorkingOnBehalfTicket[8];
		NTSTATUS ExceptionCode;
		PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
		ULONG_PTR InstrumentationCallbackSp;
		ULONG_PTR InstrumentationCallbackPreviousPc;
		ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _M_X64
		ULONG TxFsContext;
#endif
		BOOLEAN InstrumentationCallbackDisabled;
#ifdef _M_X64
		BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifdef _M_IX86
		UCHAR SpareBytes[23];
		ULONG TxFsContext;
#endif
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		HANDLE GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG_PTR Win32ClientInfo[62];
		PVOID glDispatchTable[233];
		ULONG_PTR glReserved1[29];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;
		NTSTATUS LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[261];
		PVOID DeallocationStack;
		PVOID TlsSlots[64];
		LIST_ENTRY TlsLinks;
		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[2];
		ULONG HardErrorMode;
#ifdef _M_X64
		PVOID Instrumentation[11];
#elif _M_IX86
		PVOID Instrumentation[9];
#endif
		GUID ActivityId;
		PVOID SubProcessTag;
		PVOID PerflibData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;
		union {
			PROCESSOR_NUMBER CurrentIdealProcessor;
			ULONG IdealProcessorValue;
			struct {
				UCHAR ReservedPad0;
				UCHAR ReservedPad1;
				UCHAR ReservedPad2;
				UCHAR IdealProcessor;
			};
		};
		ULONG GuaranteedStackBytes;
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG_PTR ReservedForCodeCoverage;
		PVOID ThreadPoolData;
		PVOID* TlsExpansionSlots;
#ifdef _M_X64
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
#endif
		ULONG MuiGeneration;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		ULONG HeapData;
		HANDLE CurrentTransactionHandle;
		PTEB_ACTIVE_FRAME ActiveFrame;
		PVOID FlsData;
		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;
		union {
			USHORT CrossTebFlags;
			USHORT SpareCrossTebBits : 16;
		};
		union {
			USHORT SameTebFlags;
			struct {
				USHORT SafeThunkCall : 1;
				USHORT InDebugPrint : 1;
				USHORT HasFiberData : 1;
				USHORT SkipThreadAttach : 1;
				USHORT WerInShipAssertCode : 1;
				USHORT RanProcessInit : 1;
				USHORT ClonedThread : 1;
				USHORT SuppressDebugMsg : 1;
				USHORT DisableUserStackWalk : 1;
				USHORT RtlExceptionAttached : 1;
				USHORT InitialThread : 1;
				USHORT SessionAware : 1;
				USHORT LoadOwner : 1;
				USHORT LoaderWorker : 1;
				USHORT SkipLoaderInit : 1;
				USHORT SkipFileAPIBrokering : 1;
			};
		};
		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		LONG WowTebOffset;
		PVOID ResourceRetValue;
		PVOID ReservedForWdf;
		ULONGLONG ReservedForCrt;
		GUID EffectiveContainerId;
		ULONGLONG LastSleepCounter;
		ULONG SpinCallCount;
		ULONGLONG ExtendedFeatureDisableMask;
	} TEB, *PTEB;

	const PTEB GetTEB();

	// ----------------------------------------------------------------
	// Codec
	// ----------------------------------------------------------------

	namespace Codec {

		// ----------------------------------------------------------------
		// Encode
		// ----------------------------------------------------------------

		int Encode(unsigned short unCodePage, const char* const szText, wchar_t* szBuffer = nullptr, const int nBufferSize = 0);

		// ----------------------------------------------------------------
		// Decode
		// ----------------------------------------------------------------

		int Decode(unsigned short unCodePage, const wchar_t* const szText, char* szBuffer = nullptr, const int nBufferSize = 0);
	}

	// ----------------------------------------------------------------
	// Hexadecimal
	// ----------------------------------------------------------------

	namespace Hexadecimal {

		// ----------------------------------------------------------------
		// Encode
		// ----------------------------------------------------------------

		bool EncodeA(const void* const pData, const size_t unSize, char* szHex, const unsigned char unIgnoredByte = 0x2A);
		bool EncodeW(const void* const pData, const size_t unSize, wchar_t* szHex, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		bool Encode(const void* const pData, const size_t unSize, wchar_t* szHex, const unsigned char unIgnoredByte = 0x2A);
#else
		bool Encode(const void* const pData, const size_t unSize, char* szHex, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// Decode
		// ----------------------------------------------------------------

		bool DecodeA(const char* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
		bool DecodeW(const wchar_t* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		bool Decode(const wchar_t* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#else
		bool Decode(const char* const szHex, void* pData, const unsigned char unIgnoredByte = 0x2A);
#endif
	}

	namespace Scan {

		// ----------------------------------------------------------------
		// FindSection
		// ----------------------------------------------------------------

		bool FindSection(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const void** pAddress, const size_t* pSize);

		// ----------------------------------------------------------------
		// FindSectionPOGO
		// ----------------------------------------------------------------

		bool FindSectionPOGO(const HMODULE hModule, const char* const szSectionName, const void** pAddress, const size_t* pSize);

		// ----------------------------------------------------------------
		// FindSignature (Native)
		// ----------------------------------------------------------------

		const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (SSE2)
		// ----------------------------------------------------------------

		const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX)
		// ----------------------------------------------------------------

		const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX2)
		// ----------------------------------------------------------------

		const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (Auto)
		// ----------------------------------------------------------------

		const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#ifdef UNICODE
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		const void* const FindSignature(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindData (Native)
		// ----------------------------------------------------------------

		const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataNative(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (SSE2)
		// ----------------------------------------------------------------

		const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataSSE2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX)
		// ----------------------------------------------------------------

		const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX2)
		// ----------------------------------------------------------------

		const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataAVX512(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (Auto)
		// ----------------------------------------------------------------

		const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindDataW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#ifdef UNICODE
		const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		const void* const FindData(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindRTTI
		// ----------------------------------------------------------------

		const void* const FindRTTI(const void* const pBaseAddress, const void* const pAddress, const size_t unSize, const char* const szRTTI);
		const void* const FindRTTI(const void* const pBaseAddress, const size_t unSize, const char* const szRTTI);
		const void* const FindRTTI(const HMODULE hModule, const char* const szRTTI);
		const void* const FindRTTIA(const char* const szModuleName, const char* const szRTTI);
		const void* const FindRTTIW(const wchar_t* const szModuleName, const char* const szRTTI);
#ifdef UNICODE
		const void* const FindRTTI(const wchar_t* const szModuleName, const char* const szRTTI);
#else
		const void* const FindRTTI(const char* const szModuleName, const char* const szRTTI);
#endif
	}

	// ----------------------------------------------------------------
	// Memory
	// ----------------------------------------------------------------

	namespace Memory {

		// ----------------------------------------------------------------
		// Definitions
		// ----------------------------------------------------------------

		using fnVirtualProtect = BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

		// ----------------------------------------------------------------
		// Server
		// ----------------------------------------------------------------

		class Server {
		public:
			Server(const size_t unMemorySize, bool bIsGlobal = false);
			~Server();

		public:
			bool GetSessionName(TCHAR szSessionName[64]);
			void* GetAddress();

		private:
			TCHAR m_szSessionName[64];
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Client
		// ----------------------------------------------------------------

		class Client {
		public:
			Client(TCHAR szSessionName[64], bool bIsGlobal = false);
			~Client();

		public:
			void* GetAddress();

		private:
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Protection
		// ----------------------------------------------------------------

		class Protection {
		public:
			Protection(const void* const pAddress, const size_t unSize);
			~Protection();

		public:
			bool GetProtection(const PDWORD pProtection);
			bool ChangeProtection(const DWORD unNewProtection);
			bool RestoreProtection();

		public:
			const void* const GetAddress();
			const size_t GetSize();
			DWORD GetOriginalProtection();

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			fnVirtualProtect m_VirtualProtect;
			DWORD m_unOriginalProtection;
		};

		// ----------------------------------------------------------------
		// Simple Protection
		// ----------------------------------------------------------------

		bool ChangeProtection(const void* const pAddress, const size_t unSize, const DWORD unNewProtection);
		bool RestoreProtection(const void* const pAddress);
	}

	// ----------------------------------------------------------------
	// Exception
	// ----------------------------------------------------------------

	namespace Exception {

		// ----------------------------------------------------------------
		// ExceptionCallBack
		// ----------------------------------------------------------------

		using fnExceptionCallBack = bool(__fastcall*)(const EXCEPTION_RECORD& pException, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// ExceptionListener
		// ----------------------------------------------------------------

		class ExceptionListener {
		public:
			ExceptionListener();
			~ExceptionListener();

		public:
			bool EnableHandler();
			bool DisableHandler();
			bool RefreshHandler();
			bool AddCallBack(const fnExceptionCallBack pCallBack);
			bool RemoveCallBack(const fnExceptionCallBack pCallBack);

		public:
			std::deque<fnExceptionCallBack>& GetCallBacks();

		private:
			PVOID m_pVEH;
			std::deque<fnExceptionCallBack> m_vecCallBacks;
		};

		extern ExceptionListener g_ExceptionListener;
	}

	// ----------------------------------------------------------------
	// Hook
	// ----------------------------------------------------------------

	namespace Hook {

		// ----------------------------------------------------------------
		// Memory Hook CallBack
		// ----------------------------------------------------------------

		using fnMemoryHookCallBack = bool(__fastcall*)(std::unique_ptr<class MemoryHook>& pHook, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Memory Hook
		// ----------------------------------------------------------------

		class MemoryHook {
		public:
			MemoryHook(const void* const pAddress, const size_t unSize = 1, bool bAutoDisable = false);
			~MemoryHook();

		public:
			bool Hook(const fnMemoryHookCallBack pCallBack);
			bool UnHook();

		public:
			bool Enable();
			bool Disable();

		public:
			const void* const GetAddress();
			const size_t GetSize();
			bool IsAutoDisable();
			fnMemoryHookCallBack GetCallBack();

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			bool m_bAutoDisable;
			fnMemoryHookCallBack m_pCallBack;
		};

		// ----------------------------------------------------------------
		// Simple Memory Hook
		// ----------------------------------------------------------------

		bool HookMemory(const void* const pAddress, const fnMemoryHookCallBack pCallBack, bool bAutoDisable = false);
		bool UnHookMemory(const fnMemoryHookCallBack pCallBack);
		bool EnableHookMemory(const fnMemoryHookCallBack pCallBack);
		bool DisableHookMemory(const fnMemoryHookCallBack pCallBack);
	}
}

#endif // !_DETOURS_H_

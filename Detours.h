#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

// Default
#include <Windows.h>

// C++
#include <cstdlib>

// STL
#include <array>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#define PROCESSOR_FEATURE_MAX 64

#ifndef DETOURS_MAX_STRSIZE
#define DETOURS_MAX_STRSIZE 0x1000 // 4 KiB
#endif // !DETOURS_MAX_SIZE

// ----------------------------------------------------------------
// Checking platform
// ----------------------------------------------------------------

#if !defined(_M_IX86) && !defined(_M_X64)
#error Only x86 and x86_64 platforms are supported.
#endif // !_M_IX86 && !_M_X64

#if !defined(_WIN32) && !defined(_WIN64)
#error Only Windows platform are supported.
#endif // !_WIN32 && !_WIN64

// ----------------------------------------------------------------
// Detours
// ----------------------------------------------------------------

namespace Detours {

	// ----------------------------------------------------------------
	// KUSER_SHARED_DATA
	// ----------------------------------------------------------------

	typedef struct _KSYSTEM_TIME {
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, *PKSYSTEM_TIME;

	typedef enum _NT_PRODUCT_TYPE : unsigned int {
		NtProductWinNt = 1,
		NtProductLanManNt = 2,
		NtProductServer = 3
	} NT_PRODUCT_TYPE;

	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE : unsigned int {
		StandardDesign = 0,
		NEC98x86 = 1,
		EndAlternatives = 2
	} ALTERNATIVE_ARCHITECTURE_TYPE;

	typedef struct _KUSER_SHARED_DATA {
		ULONG TickCountLowDeprecated;
		ULONG TickCountMultiplier;
		KSYSTEM_TIME InterruptTime;
		KSYSTEM_TIME SystemTime;
		KSYSTEM_TIME TimeZoneBias;
		USHORT ImageNumberLow;
		USHORT ImageNumberHigh;
		WCHAR NtSystemRoot[MAX_PATH];
		ULONG MaxStackTraceDepth;
		ULONG CryptoExponent;
		ULONG TimeZoneId;
		ULONG LargePageMinimum;
		ULONG AitSamplingValue;
		ULONG AppCompatFlag;
		ULONGLONG RNGSeedVersion;
		ULONG GlobalValidationRunlevel;
		LONG TimeZoneBiasStamp;
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
		ULONG TimeSlip;
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
		ULONG ActiveConsoleId;
		ULONG DismountCount;
		ULONG ComPlusPackage;
		ULONG LastSystemRITEventTickCount;
		ULONG NumberOfPhysicalPages;
		BOOLEAN SafeBootMode;
		union {
			UCHAR VirtualizationFlags;
			struct {
				UCHAR ArchStartedInEl2 : 1;
				UCHAR QcSlIsSupported : 1;
			};
		};
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
			KSYSTEM_TIME TickCount;
			ULONG64 TickCountQuad;
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
		ULONGLONG InterruptTimeBias;
		ULONGLONG QpcBias;
		ULONG ActiveProcessorCount;
		UCHAR ActiveGroupCount;
		UCHAR Reserved9;
		union {
			USHORT QpcData;
			struct {
				UCHAR QpcBypassEnabled;
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

	extern const KUSER_SHARED_DATA& KUserSharedData;

	// ----------------------------------------------------------------
	// Scan
	// ----------------------------------------------------------------

	namespace Scan {

		// ----------------------------------------------------------------
		// FindSection
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding section in module.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pAddress'>Section address.</param>
		/// <param name='pSize'>Section size.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool FindSection(const HMODULE hModule, const std::array<unsigned char, 8>& SectionName, void** pAddress, size_t* pSize);

		// ----------------------------------------------------------------
		// FindSectionPOGO
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding section in module.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pAddress'>Section address.</param>
		/// <param name='pSize'>Section size.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool FindSectionPOGO(const HMODULE hModule, const char* const szSectionName, void** pAddress, const size_t* pSize);

		// ----------------------------------------------------------------
		// FindSignature (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>

		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding signature in data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data without/with SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
		
		/// <summary>
		/// Finding signature in data without/with SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding signature in data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const char* const szSectionName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindData (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (SSE2) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data with SIMD (AVX512) by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding data-in-data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle and section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module handle and POGO section name.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);
		
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and seciton name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding data-in-data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='SectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const std::array<const unsigned char, 8>& SectionName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding data-in-data without/with SIMD by module name and POGO section name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSectionName'>Section name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const char* const szSectionName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindRTTI
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const void* const pBaseAddress, const size_t unSize, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const HMODULE hModule, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTIA(const char* const szModuleName, const char* const szRTTI);

		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTIW(const wchar_t* const szModuleName, const char* const szRTTI);

#ifdef UNICODE
		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const wchar_t* const szModuleName, const char* const szRTTI);
#else
		/// <summary>
		/// Finding for a virtual table in run-time type information without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szRTTI'>Desired virtual table from run-time type information.</param>
		/// <returns>Returns address of virtual table from run-time type information on success, null otherwise.</returns>
		const void* const FindRTTI(const char* const szModuleName, const char* const szRTTI);
#endif
	}

	// ----------------------------------------------------------------
	// Memory
	// ----------------------------------------------------------------
	namespace Memory {

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
			const size_t m_unMemorySize;
			TCHAR m_szSessionName[64];
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Client
		// ----------------------------------------------------------------

		class Client {
		public:
			Client(const size_t unMemorySize, TCHAR szSessionName[64], bool bIsGlobal = false);
			~Client();

		public:
			void* GetAddress();

		private:
			const size_t m_unMemorySize;
			HANDLE m_hMap;
			void* m_pAddress;
		};

		// ----------------------------------------------------------------
		// Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Memory protection that automatically restores protection.
		/// </summary>
		class Protection {
		public:
			/// <summary>
			/// Memory protection that automatically restores protection.
			/// </summary>
			/// <param name='pAddress'>Memory address.</param>
			/// <param name='unSize'>Memory size.</param>
			Protection(const void* const pAddress, const size_t unSize);
			~Protection();

		public:
			/// <summary>
			/// Get current memory protection.</returns>
			/// </summary>
			/// <param name='pProtection'>Recording address.</param>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool GetProtection(const PDWORD pProtection);

			/// <summary>
			/// Change memory protection.
			/// </summary>
			/// <param name='unFlag'>Memory protection flag.</param>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool ChangeProtection(const DWORD unNewProtection);

			/// <summary>
			/// Restore memory protection.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool RestoreProtection();

		public:
			/// <returns>Returns memory address.</returns>
			const void* const GetAddress();

			/// <returns>Returns memory size.</returns>
			const size_t GetSize();

			/// <returns>Returns original memory protection.</returns>
			DWORD GetOriginalProtection();

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			DWORD m_unOriginalProtection;
		};

		// ----------------------------------------------------------------
		// Simple Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Change memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		/// <param name='unSize'>Memory size.</param>
		/// <param name='unFlag'>Memory protection flag.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool ChangeProtection(const void* const pAddress, const size_t unSize, const DWORD unNewProtection);

		/// <summary>
		/// Restore memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		bool RestoreProtection(const void* const pAddress);
	}

	// ----------------------------------------------------------------
	// Exception
	// ----------------------------------------------------------------
	namespace Exception {

		// ----------------------------------------------------------------
		// ExceptionCallBack
		// ----------------------------------------------------------------

		typedef bool(__fastcall* fnExceptionCallBack)(const EXCEPTION_RECORD Exception, const PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Exception
		// ----------------------------------------------------------------

		bool AddCallBack(const fnExceptionCallBack pCallBack);
		bool RemoveCallBack(const fnExceptionCallBack pCallBack);
	}

	// ----------------------------------------------------------------
	// Hook
	// ----------------------------------------------------------------
	namespace Hook {

		// ----------------------------------------------------------------
		// Import Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class ImportHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='szModuleName'>Module name.</param>
			/// <param name='szExportName'>Importing name.</param>
			/// <param name='szImportModuleName'>Importing module name.</param>
			ImportHook(const HMODULE hModule, const char* const szImportName, const char* const szImportModuleName = nullptr);
			~ImportHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pHookAddress'>Hook address.</param>
			bool Hook(const void* const pHookAddress);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <returns>Returns original address.</returns>
			const void* GetOriginalAddress();

			/// <returns>Returns hook address.</returns>
			const void* GetHookAddress();

		private:
			const void** m_pAddress;
			const void* m_pOriginalAddress;
			const void* m_pHookAddress;
		};

		// ----------------------------------------------------------------
		// Simple Import Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szImportName'>Importing name.</param>
		/// <param name='pHookAddress'>Hook address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookImport(const HMODULE hModule, const char* const szImportName, const void* const pHookAddress);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pHookAddress'>Hook address.</param>
		bool UnHookImport(const void* const pHookAddress);

		// ----------------------------------------------------------------
		// Export Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class ExportHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='szModuleName'>Module name.</param>
			/// <param name='szExportName'>Exporting name.</param>
			ExportHook(const HMODULE hModule, const char* const szExportName);
			~ExportHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pHookAddress'>Hook address.</param>
			bool Hook(const void* const pHookAddress);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <returns>Returns original address.</returns>
			const void* GetOriginalAddress();

			/// <returns>Returns hook address.</returns>
			const void* GetHookAddress();

		private:
			HMODULE m_hModule;
			PDWORD m_pAddress;
			DWORD m_unOriginalAddress;
			const void* m_pHookAddress;
		};

		// ----------------------------------------------------------------
		// Simple Export Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szExportName'>Exporting name.</param>
		/// <param name='pHookAddress'>Hook address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookExport(const HMODULE hModule, const char* const szExportName, const void* const pHookAddress);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pHookAddress'>Hook address.</param>
		bool UnHookExport(const void* const pHookAddress);

		// ----------------------------------------------------------------
		// Memory Hook CallBack
		// ----------------------------------------------------------------

		typedef bool(__fastcall* fnMemoryHookCallBack)(class MemoryHook* pHook, PCONTEXT pCTX);

		// ----------------------------------------------------------------
		// Memory Hook
		// ----------------------------------------------------------------

		/// <summary>
		/// Hook that automatically unhooking.
		/// </summary>
		class MemoryHook {
		public:
			/// <summary>
			/// Hook that automatically unhooking.
			/// </summary>
			/// <param name='pAddress'>Memory address.</param>
			/// <param name='unSize'>Memory size.</param>
			MemoryHook(const void* const pAddress, const size_t unSize = 1, bool bAutoDisable = false);
			~MemoryHook();

		public:
			/// <summary>
			/// Hook with a specific address.
			/// </summary>
			/// <param name='pCallBack'>Callback address.</param>
			bool Hook(const fnMemoryHookCallBack pCallBack);

			/// <summary>
			/// UnHook.
			/// </summary>
			bool UnHook();

		public:
			/// <summary>
			/// Enable hook.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool Enable();

			/// <summary>
			/// Disable hook.
			/// </summary>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool Disable();

		public:
			/// <returns>Returns memory address.</returns>
			const void* const GetAddress();

			/// <returns>Returns memory size.</returns>
			const size_t GetSize();

			/// <returns>Returns auto disable param.</returns>
			bool IsAutoDisable();

			/// <returns>Returns callback address.</returns>
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

		/// <summary>
		/// Hook with a specific address.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool HookMemory(const void* const pAddress, const fnMemoryHookCallBack pCallBack, bool bAutoDisable = false);

		/// <summary>
		/// UnHook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		bool UnHookMemory(const fnMemoryHookCallBack pCallBack);

		/// <summary>
		/// Enable hook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EnableHookMemory(const fnMemoryHookCallBack pCallBack);

		/// <summary>
		/// Disable hook.
		/// </summary>
		/// <param name='pCallBack'>Callback address.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DisableHookMemory(const fnMemoryHookCallBack pCallBack);
	}
}

#endif // !_DETOURS_H_

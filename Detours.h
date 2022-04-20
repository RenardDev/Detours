#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

// Default
#include <Windows.h>

// C++
#include <cstdlib>

// General definitions
#ifndef DETOURS_MAX_STRSIZE
#define DETOURS_MAX_STRSIZE 0x1000 // 4 KiB
#endif // !DETOURS_MAX_SIZE

// Cheking platform
#if !defined(_M_IX86) && !defined(_M_X64)
#error Only x86 and x86_64 platforms are supported.
#endif // !_M_IX86 && !_M_X64

#if !defined(_WIN32) && !defined(_WIN64)
#error Only Windows platforms are supported.
#endif // !_WIN32 && !_WIN64

// ----------------------------------------------------------------
// DetoursUtils
// ----------------------------------------------------------------
namespace DetoursUtils {
	// ----------------------------------------------------------------
	// Encode/Decode HEX
	// ----------------------------------------------------------------
	
	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHexA(const unsigned char* const pData, const size_t unDataSize, char* szHex, const bool bUseUpperCase = true);

	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHexW(const unsigned char* const pData, const size_t unDataSize, wchar_t* szHex, const bool bUseUpperCase = true);

#ifdef UNICODE
	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, wchar_t* szHex, const bool bUseUpperCase = true);
#else
	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, char* szHex, const bool bUseUpperCase = true);
#endif

	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHexA(const char* const szHex, const size_t unHexSize, unsigned char* pData);

	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHexW(const wchar_t* const szHex, const size_t unHexSize, unsigned char* pData);

#ifdef UNICODE
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const wchar_t* const szHex, const size_t unHexSize, unsigned char* pData);
#else
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const char* const szHex, const size_t unHexSize, unsigned char* pData);
#endif
}

// ----------------------------------------------------------------
// MemoryScan
// ----------------------------------------------------------------
namespace MemoryScan {
	// ----------------------------------------------------------------
	// FindSignature (Native)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature without SIMD by address and size.
	/// </summary>
	const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature without SIMD by module handle.
	/// </summary>
	const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindSignature (SSE2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by address and size.
	/// </summary>
	const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by module handle.
	/// </summary>
	const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with AVX (SIMD) by address and size.
	/// </summary>
	const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX (SIMD) by module handle.
	/// </summary>
	const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by address and size.
	/// </summary>
	const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by module handle.
	/// </summary>
	const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX512) [AVX512BW]
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by address and size.
	/// </summary>
	const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by module handle.
	/// </summary>
	const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindSignature (Auto)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with/without SIMD by address and size.
	/// </summary>
	const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with/without SIMD by module handle.
	/// </summary>
	const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with/without SIMD by module name.
	/// </summary>
	const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

	/// <summary>
	/// Finding for a signature with/without SIMD by module name.
	/// </summary>
	const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with/without SIMD by module name.
	/// </summary>
	const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
	/// <summary>
	/// Finding for a signature with/without SIMD by module name.
	/// </summary>
	const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

	// ----------------------------------------------------------------
	// FindData (Native)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data without SIMD by address and size.
	/// </summary>
	const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data without SIMD by module handle.
	/// </summary>
	const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data without SIMD by module name.
	/// </summary>
	const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data without SIMD by module name.
	/// </summary>
	const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data without SIMD by module name.
	/// </summary>
	const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data without SIMD by module name.
	/// </summary>
	const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (SSE2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by address and size.
	/// </summary>
	const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by module handle.
	/// </summary>
	const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data with SSE2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (AVX)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data with AVX (SIMD) by address and size.
	/// </summary>
	const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX (SIMD) by module handle.
	/// </summary>
	const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data with AVX (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (AVX2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by address and size.
	/// </summary>
	const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by module handle.
	/// </summary>
	const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data with AVX2 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (AVX512) [AVX512BW]
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by address and size.
	/// </summary>
	const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by module handle.
	/// </summary>
	const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data with AVX512 (SIMD) by module name.
	/// </summary>
	const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (Auto)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a data with/without SIMD by address and size.
	/// </summary>
	const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with/without SIMD by module handle.
	/// </summary>
	const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with/without SIMD by module name.
	/// </summary>
	const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a data with/without SIMD by module name.
	/// </summary>
	const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for a data with/without SIMD by module name.
	/// </summary>
	const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for a data with/without SIMD by module name.
	/// </summary>
	const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindRTTI
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for RTTI by address and size.
	/// </summary>
	const void* const FindRTTI(const void* const pAddress, const size_t unSize, const char* const szRTTI);

	/// <summary>
	/// Finding for RTTI by module handle.
	/// </summary>
	const void* const FindRTTI(const HMODULE hModule, const char* const szRTTI);

	/// <summary>
	/// Finding for RTTI by module name.
	/// </summary>
	const void* const FindRTTIA(const char* const szModuleName, const char* const szRTTI);

	/// <summary>
	/// Finding for RTTI by module name.
	/// </summary>
	const void* const FindRTTIW(const wchar_t* const szModuleName, const char* const szRTTI);

#ifdef UNICODE
	/// <summary>
	/// Finding for RTTI by module name.
	/// </summary>
	const void* const FindRTTI(const wchar_t* const szModuleName, const char* const szRTTI);
#else
	/// <summary>
	/// Finding RTTI by module name.
	/// </summary>
	const void* const FindRTTI(const char* const szModuleName, const char* const szRTTI);
#endif
}

// ----------------------------------------------------------------
// MemoryProtections
// ----------------------------------------------------------------
namespace MemoryProtections {
	// ----------------------------------------------------------------
	// Memory Protections Flags
	// ----------------------------------------------------------------

	enum MemoryProtectionsFlags : unsigned char {
		MEMORYPROTECTION_READONLY = 0,
		MEMORYPROTECTION_READWRITE = 1,
		MEMORYPROTECTION_READWRITE_EXECUTE = 2
	};

	// ----------------------------------------------------------------
	// Smart Memory Protection
	// ----------------------------------------------------------------

	/// <summary>
	/// Smart memory protection that is automatically restore protecting.
	/// </summary>
	class SmartMemoryProtection {
	public:
		SmartMemoryProtection(void* const pAddress, const size_t unSize);
		~SmartMemoryProtection();
	public:
		bool ChangeProtection(const unsigned char unFlag = MEMORYPROTECTION_READONLY);
		bool RestoreProtection();
	public:
		void* GetAddress();
		size_t GetSize();
	private:
		void* m_pAddress;
		size_t m_unSize;
		DWORD m_unOriginalProtection;
	};

	// ----------------------------------------------------------------
	// Manual Memory Protection
	// ----------------------------------------------------------------

	/// <summary>
	/// A simple change in memory protection.
	/// </summary>
	bool ChangeMemoryProtection(void* const pAddress, const size_t unSize, const unsigned char unFlag = MEMORYPROTECTION_READONLY);

	/// <summary>
	/// A simple change in memory protection.
	/// </summary>
	bool RestoreMemoryProtection(void* const pAddress);
}

#endif // !_DETOURS_H_

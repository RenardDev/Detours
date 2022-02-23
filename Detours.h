#pragma once

#ifndef _DETOURS_H_
#define _DETOURS_H_

// Default
#include <Windows.h>

// C++
#include <cstdlib>

// General definitions
#ifndef DETOURS_MAX_STRSIZE
#define DETOURS_MAX_STRSIZE 0x1000000 // 16 MiB
#endif // !DETOURS_MAX_SIZE

// Cheking platform
#if !defined(_M_IX86) && !defined(_M_X64)
#error Only x86 and x86_64 platforms are supported.
#endif // !_M_IX86 && !_M_X64

#if !defined(_WIN32) && !defined(_WIN64)
#error Only Windows platforms are supported.
#endif // !_WIN32 && !_WIN64

// ----------------------------------------------------------------
// MemoryUtils
// ----------------------------------------------------------------
namespace MemoryUtils {
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
	bool DecodeFromHexA(const char* szHex, const size_t unHexSize, unsigned char* const pData);

	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHexW(const wchar_t* szHex, const size_t unHexSize, unsigned char* const pData);

#ifdef UNICODE
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const wchar_t* szHex, const size_t unHexSize, unsigned char* const pData);
#else
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const char* szHex, const size_t unHexSize, unsigned char* const pData);
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
	void* FindSignatureNative(void* const pAddress, const size_t unSize, const char* const szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module handle.
	/// </summary>
	void* FindSignatureNative(const HMODULE hModule, const char* const szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNativeA(const char* const szModuleName, const char* const szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature);
#else
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNative(const char* const szModuleName, const char* const szSignature);
#endif

#if defined(_M_IX86) || defined(_M_X64)
	// ----------------------------------------------------------------
	// FindSignature (SSE2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by address and size.
	/// </summary>
	void* FindSignatureSSE2(void* const pAddress, const size_t unSize, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module handle.
	/// </summary>
	void* FindSignatureSSE2(const HMODULE hModule, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2(const char* const szModuleName, const char* const szSignature);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by address and size.
	/// </summary>
	void* FindSignatureAVX2(void* const pAddress, const size_t unSize, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module handle.
	/// </summary>
	void* FindSignatureAVX2(const HMODULE hModule, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2(const char* const szModuleName, const char* const szSignature);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX512)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by address and size.
	/// </summary>
	void* FindSignatureAVX512(void* const pAddress, const size_t unSize, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module handle.
	/// </summary>
	void* FindSignatureAVX512(const HMODULE hModule, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512(const char* const szModuleName, const char* const szSignature);
#endif
#endif // _M_IX86 || _M_X64

	// ----------------------------------------------------------------
	// FindSignature (Auto)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature by address and size.
	/// </summary>
	void* FindSignature(void* const pAddress, const size_t unSize, const char* const szSignature);

	/// <summary>
	/// Finding for a signature by module handle.
	/// </summary>
	void* FindSignature(const HMODULE hModule, const char* const szSignature);

	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignatureA(const char* const szModuleName, const char* const szSignature);

	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignature(const wchar_t* const szModuleName, const char* const szSignature);
#else
	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignature(const char* const szModuleName, const char* const szSignature);
#endif

	// ----------------------------------------------------------------
	// FindData (Native)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for data without SIMD by address and size.
	/// </summary>
	void* FindDataNative(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for a signature without SIMD by module handle.
	/// </summary>
	void* FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data without SIMD by module name.
	/// </summary>
	void* FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data without SIMD by module name.
	/// </summary>
	void* FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for data without SIMD by module name.
	/// </summary>
	void* FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for data without SIMD by module name.
	/// </summary>
	void* FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

#if defined(_M_IX86) || defined(_M_X64)
	// ----------------------------------------------------------------
	// FindData (SSE2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for data with SIMD (SSE2) by address and size.
	/// </summary>
	void* FindDataSSE2(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (SSE2) by module handle.
	/// </summary>
	void* FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (SSE2) by module name.
	/// </summary>
	void* FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (SSE2) by module name.
	/// </summary>
	void* FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for data with SIMD (SSE2) by module name.
	/// </summary>
	void* FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for data with SIMD (SSE2) by module name.
	/// </summary>
	void* FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (AVX2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for data with SIMD (AVX2) by address and size.
	/// </summary>
	void* FindDataAVX2(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX2) by module handle.
	/// </summary>
	void* FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX2) by module name.
	/// </summary>
	void* FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX2) by module name.
	/// </summary>
	void* FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for data with SIMD (AVX2) by module name.
	/// </summary>
	void* FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for data with SIMD (AVX2) by module name.
	/// </summary>
	void* FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

	// ----------------------------------------------------------------
	// FindData (AVX512)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for data with SIMD (AVX512) by address and size.
	/// </summary>
	void* FindDataAVX512(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX512) by module handle.
	/// </summary>
	void* FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX512) by module name.
	/// </summary>
	void* FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data with SIMD (AVX512) by module name.
	/// </summary>
	void* FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for data with SIMD (AVX512) by module name.
	/// </summary>
	void* FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for data with SIMD (AVX512) by module name.
	/// </summary>
	void* FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif
#endif // _M_IX86 || _M_X64

	// ----------------------------------------------------------------
	// FindData (Auto)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for data by address and size.
	/// </summary>
	void* FindData(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data by module handle.
	/// </summary>
	void* FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data by module name.
	/// </summary>
	void* FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

	/// <summary>
	/// Finding for data by module name.
	/// </summary>
	void* FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
	/// <summary>
	/// Finding for data by module name.
	/// </summary>
	void* FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
	/// <summary>
	/// Finding for data by module name.
	/// </summary>
	void* FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif
}

// ----------------------------------------------------------------
// MemoryProtection
// ----------------------------------------------------------------
namespace MemoryProtection {
	// ----------------------------------------------------------------
	// MemoryProtectionFlags
	// ----------------------------------------------------------------

	enum MemoryProtectionFlags : unsigned char {
		MEMORYPROTECTION_READONLY = 0,
		MEMORYPROTECTION_READWRITE = 1,
		MEMORYPROTECTION_READWRITE_EXECUTE = 2
	};

	// ----------------------------------------------------------------
	// Smart Memory Protection
	// ----------------------------------------------------------------

	/// <summary>
	/// Smart memory protection that is automatically protecting.
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
		DWORD GetOriginalProtection();
	private:
		void* m_pAddress;
		size_t m_unSize;
		DWORD m_unOriginalProtection;
	};

	// ----------------------------------------------------------------
	// MemoryProtect
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

// ----------------------------------------------------------------
// MemoryInstructions
// ----------------------------------------------------------------
namespace MemoryInstructions {
	// ----------------------------------------------------------------
	// MemoryInstructions
	// ----------------------------------------------------------------
}

// ----------------------------------------------------------------
// MemoryHook
// ----------------------------------------------------------------
namespace MemoryHook {
	// ----------------------------------------------------------------
	// Import Hook
	// ----------------------------------------------------------------

	// ----------------------------------------------------------------
	// Export Hook
	// ----------------------------------------------------------------

	// ----------------------------------------------------------------
	// VTable Hook
	// ----------------------------------------------------------------

	// ----------------------------------------------------------------
	// Direct Hook
	// ----------------------------------------------------------------

}

#endif // !_DETOURS_H_

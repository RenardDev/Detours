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
	bool EncodeToHexA(unsigned char* pData, const size_t unSize, char* szData, const bool bUseUpperCase = true);

	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHexW(unsigned char* pData, const size_t unSize, wchar_t* szData, const bool bUseUpperCase = true);

#ifdef UNICODE
	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHex(unsigned char* pData, const size_t unSize, wchar_t* szData, const bool bUseUpperCase = true);
#else
	/// <summary>
	/// Encode the data array to a hexadecimal string.
	/// </summary>
	bool EncodeToHex(unsigned char* pData, const size_t unSize, char* szData, const bool bUseUpperCase = true);
#endif

	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHexA(const char* szData, unsigned char* pData);

	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHexW(const wchar_t* szData, unsigned char* pData);

#ifdef UNICODE
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const wchar_t* szData, unsigned char* pData);
#else
	/// <summary>
	/// Decoding a hexadecimal string into an array of data.
	/// </summary>
	bool DecodeFromHex(const char* szData, unsigned char* pData);
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
	void* FindSignatureNative(void* pAddress, size_t unSize, const char* szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module handle.
	/// </summary>
	void* FindSignatureNative(HMODULE hModule, const char* szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNativeA(const char* szModuleName, const char* szSignature);

	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNativeW(const wchar_t* szModuleName, const char* szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNative(const wchar_t* szModuleName, const char* szSignature);
#else
	/// <summary>
	/// Finding for a signature without SIMD by module name.
	/// </summary>
	void* FindSignatureNative(const char* szModuleName, const char* szSignature);
#endif

#if defined(_M_IX86) || defined(_M_X64)
	// ----------------------------------------------------------------
	// FindSignature (SSE2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by address and size.
	/// </summary>
	void* FindSignatureSSE2(void* pAddress, size_t unSize, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module handle.
	/// </summary>
	void* FindSignatureSSE2(HMODULE hModule, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2A(const char* szModuleName, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2W(const wchar_t* szModuleName, const char* szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2(const wchar_t* szModuleName, const char* szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (SSE2) by module name.
	/// </summary>
	void* FindSignatureSSE2(const char* szModuleName, const char* szSignature);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX2)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by address and size.
	/// </summary>
	void* FindSignatureAVX2(void* pAddress, size_t unSize, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module handle.
	/// </summary>
	void* FindSignatureAVX2(HMODULE hModule, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2A(const char* szModuleName, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2W(const wchar_t* szModuleName, const char* szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2(const wchar_t* szModuleName, const char* szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (AVX2) by module name.
	/// </summary>
	void* FindSignatureAVX2(const char* szModuleName, const char* szSignature);
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX512)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by address and size.
	/// </summary>
	void* FindSignatureAVX512(void* pAddress, size_t unSize, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module handle.
	/// </summary>
	void* FindSignatureAVX512(HMODULE hModule, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512A(const char* szModuleName, const char* szSignature);

	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512W(const wchar_t* szModuleName, const char* szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512(const wchar_t* szModuleName, const char* szSignature);
#else
	/// <summary>
	/// Finding for a signature with SIMD (AVX512) by module name.
	/// </summary>
	void* FindSignatureAVX512(const char* szModuleName, const char* szSignature);
#endif
#endif // _M_IX86 || _M_X64

	// ----------------------------------------------------------------
	// FindSignature (Auto)
	// ----------------------------------------------------------------

	/// <summary>
	/// Finding for a signature by address and size.
	/// </summary>
	void* FindSignature(void* pAddress, size_t unSize, const char* szSignature);

	/// <summary>
	/// Finding for a signature by module handle.
	/// </summary>
	void* FindSignature(HMODULE hModule, const char* szSignature);

	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignatureA(const char* szModuleName, const char* szSignature);

	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignatureW(const wchar_t* szModuleName, const char* szSignature);

#ifdef UNICODE
	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignature(const wchar_t* szModuleName, const char* szSignature);
#else
	/// <summary>
	/// Finding for a signature by module name.
	/// </summary>
	void* FindSignature(const char* szModuleName, const char* szSignature);
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
		SmartMemoryProtection(void* pAddress, size_t unSize);
		~SmartMemoryProtection();
	public:
		bool ChangeProtection(unsigned char unFlags = MEMORYPROTECTION_READONLY);
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
	bool ChangeMemoryProtection(void* pAddress, size_t unSize, unsigned char unFlags = MEMORYPROTECTION_READONLY);

	/// <summary>
	/// A simple change in memory protection.
	/// </summary>
	bool RestoreMemoryProtection(void* pAddress);
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

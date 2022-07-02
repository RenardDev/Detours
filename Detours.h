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
// Detours
// ----------------------------------------------------------------
namespace Detours {

	// ----------------------------------------------------------------
	// Codec
	// ----------------------------------------------------------------
	namespace Codec {

		// ----------------------------------------------------------------
		// Encode/Decode HEX
		// ----------------------------------------------------------------

		/// <summary>
		/// Encode the data array to a hexadecimal string.
		/// </summary>
		/// <param name='pData'>Input data.</param>
		/// <param name='unDataSize'>The size in bytes of the input data.</param>
		/// <param name='szHex'>Output hexadecimal string.</param>
		/// <param name='bUseUpperCase'>Does the output string have to be in capital letters?</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EncodeToHexA(const unsigned char* const pData, const size_t unDataSize, char* const szHex, const bool bUseUpperCase = true);

		/// <summary>
		/// Encode the data array to a hexadecimal string.
		/// </summary>
		/// <param name='pData'>Input data.</param>
		/// <param name='unDataSize'>The size in bytes of the input data.</param>
		/// <param name='szHex'>Output hexadecimal string.</param>
		/// <param name='bUseUpperCase'>Does the output string have to be in capital letters?</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EncodeToHexW(const unsigned char* const pData, const size_t unDataSize, wchar_t* const szHex, const bool bUseUpperCase = true);

#ifdef UNICODE
		/// <summary>
		/// Encode the data array to a hexadecimal string.
		/// </summary>
		/// <param name='pData'>Input data.</param>
		/// <param name='unDataSize'>The size in bytes of the input data.</param>
		/// <param name='szHex'>Output hexadecimal string.</param>
		/// <param name='bUseUpperCase'>Does the output string have to be in capital letters?</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, wchar_t* const szHex, const bool bUseUpperCase = true);
#else
		/// <summary>
		/// Encode the data array to a hexadecimal string.
		/// </summary>
		/// <param name='pData'>Input data.</param>
		/// <param name='unDataSize'>The size in bytes of the input data.</param>
		/// <param name='szHex'>Output hexadecimal string.</param>
		/// <param name='bUseUpperCase'>Does the output string have to be in capital letters?</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, char* const szHex, const bool bUseUpperCase = true);
#endif

		/// <summary>
		/// Decoding a hexadecimal string into an array of data.
		/// </summary>
		/// <param name='szHex'>Input hexadecimal string.</param>
		/// <param name='unHexSize'>The size in bytes of the input hexadecimal string.</param>
		/// <param name='pData'>Output data.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DecodeFromHexA(const char* const szHex, const size_t unDecodeBytes, unsigned char* const pData);

		/// <summary>
		/// Decoding a hexadecimal string into an array of data.
		/// </summary>
		/// <param name='szHex'>Input hexadecimal string.</param>
		/// <param name='unHexSize'>The size in bytes of the input hexadecimal string.</param>
		/// <param name='pData'>Output data.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DecodeFromHexW(const wchar_t* const szHex, const size_t unDecodeBytes, unsigned char* const pData);

#ifdef UNICODE
		/// <summary>
		/// Decoding a hexadecimal string into an array of data.
		/// </summary>
		/// <param name='szHex'>Input hexadecimal string.</param>
		/// <param name='unHexSize'>The size in bytes of the input hexadecimal string.</param>
		/// <param name='pData'>Output data.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DecodeFromHex(const wchar_t* const szHex, const size_t unDecodeBytes, unsigned char* const pData);
#else
		/// <summary>
		/// Decoding a hexadecimal string into an array of data.
		/// </summary>
		/// <param name='szHex'>Input hexadecimal string.</param>
		/// <param name='unHexSize'>The size in bytes of the input hexadecimal string.</param>
		/// <param name='pData'>Output data.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool DecodeFromHex(const char* const szHex, const size_t unDecodeBytes, unsigned char* const pData);
#endif
	}

	// ----------------------------------------------------------------
	// Scan
	// ----------------------------------------------------------------
	namespace Scan {

		// ----------------------------------------------------------------
		// FindSignature (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindSignature (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a signature in data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

		/// <summary>
		/// Finding for a signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);

#ifdef UNICODE
		/// <summary>
		/// Finding for a signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#else
		/// <summary>
		/// Finding for a signature in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='szSignature'>Desired data signature.</param>
		/// <param name='unIgnoredByte'>Byte to ignore in signature.</param>
		/// <returns>Returns address of data from signature on success, null otherwise.</returns>
		const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte = 0x2A);
#endif

		// ----------------------------------------------------------------
		// FindData (Native)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data without SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data without SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (SSE2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data with SIMD (SSE2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data with SIMD (AVX) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX2)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data with SIMD (AVX2) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (AVX512) [AVX512BW]
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data with SIMD (AVX512) by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#endif

		// ----------------------------------------------------------------
		// FindData (Auto)
		// ----------------------------------------------------------------

		/// <summary>
		/// Finding for a data in data without/with SIMD by address and size.
		/// </summary>
		/// <param name='pAddress'>Data address.</param>
		/// <param name='unSize'>The size of the data in bytes.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without/with SIMD by module handle.
		/// </summary>
		/// <param name='hModule'>Module handle.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

		/// <summary>
		/// Finding for a data in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);

#ifdef UNICODE
		/// <summary>
		/// Finding for a data in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
#else
		/// <summary>
		/// Finding for a data in data without/with SIMD by module name.
		/// </summary>
		/// <param name='szModuleName'>Module name.</param>
		/// <param name='pData'>Desired data.</param>
		/// <param name='unDataSize'>Size of desired data in bytes</param>
		/// <returns>Returns address of data from data on success, null otherwise.</returns>
		const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize);
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
		const void* const FindRTTI(const void* const pAddress, const size_t unSize, const char* const szRTTI);

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
		// Memory Protections Flags
		// ----------------------------------------------------------------

		enum MemoryProtectionsFlags : unsigned char {
			MEMORYPROTECTION_READWRITE = 0,
			MEMORYPROTECTION_READWRITE_EXECUTE = 1
		};

		// ----------------------------------------------------------------
		// Smart Memory Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Smart memory protection that automatically restores protection.
		/// </summary>
		class SmartMemoryProtection {
		public:
			/// <summary>
			/// Smart memory protection that automatically restores protection.
			/// </summary>
			/// <param name='pAddress'>Memory address.</param>
			/// <param name='unSize'>Memory size.</param>
			SmartMemoryProtection(const void* const pAddress, const size_t unSize);
			~SmartMemoryProtection();

		public:
			/// <summary>
			/// Change memory protection.
			/// </summary>
			/// <param name='unFlag'>Memory protection flag.</param>
			/// <returns>Returns True on success, False otherwise.</returns>
			bool ChangeProtection(const unsigned char unFlag = MEMORYPROTECTION_READWRITE);

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

		private:
			const void* const m_pAddress;
			const size_t m_unSize;
			DWORD m_unOriginalProtection;
		};

		// ----------------------------------------------------------------
		// Manual Memory Protection
		// ----------------------------------------------------------------

		/// <summary>
		/// Change memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		/// <param name='unSize'>Memory size.</param>
		/// <param name='unFlag'>Memory protection flag.</param>
		/// <returns>Returns True on success, False otherwise.</returns>
		bool ChangeMemoryProtection(const void* const pAddress, const size_t unSize, const unsigned char unFlag = MEMORYPROTECTION_READWRITE);

		/// <summary>
		/// Restore memory protection.
		/// </summary>
		/// <param name='pAddress'>Memory address.</param>
		bool RestoreMemoryProtection(const void* const pAddress);
	}
}

#endif // !_DETOURS_H_

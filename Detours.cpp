#include "Detours.h"

// Default
#include <tchar.h>

// Advanced
#include <intrin.h>

// STL
#include <vector>
#include <memory>

// C++
#include <cstdio>

// General definitions
static unsigned __int32 inline __ctz32(unsigned __int32 unValue) {
	unsigned __int32 unTrailingZero = 0;
	if (BitScanForward(reinterpret_cast<PDWORD>(&unTrailingZero), unValue)) {
		return unTrailingZero;
	}
	return sizeof(__int32) * 8;
}

static unsigned __int64 inline __ctz64(unsigned __int64 unValue) {
	unsigned __int64 unTrailingZero = 0;
	if (BitScanForward64(reinterpret_cast<PDWORD>(&unTrailingZero), unValue)) {
		return unTrailingZero;
	}
	return static_cast<unsigned __int64>(sizeof(__int64)) * 8;
}

// ----------------------------------------------------------------
// DetoursUtils
// ----------------------------------------------------------------
namespace DetoursUtils {
	// ----------------------------------------------------------------
	// Encode/Decode HEX
	// ----------------------------------------------------------------

	// HEX Table
	static const char nHexTable[2][16] = {{
			// Lowercase
			'0', '1', '2', '3',
			'4', '5', '6', '7',
			'8', '9', 'a', 'b',
			'c', 'd', 'e', 'f'
		}, {
			// Uppercase
			'0', '1', '2', '3',
			'4', '5', '6', '7',
			'8', '9', 'A', 'B',
			'C', 'D', 'E', 'F'
		}
	};

	// ASCII => HEX
	static const unsigned char unHexTableLower[256] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	// ASCII => HEX << 4
	static const unsigned char unHexTableUpper[256] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	bool EncodeToHexA(const unsigned char* const pData, const size_t unDataSize, char* szHex, const bool bUseUpperCase) {
		if (!pData) {
			return false;
		}

		if (!unDataSize) {
			return false;
		}

		if (!szHex) {
			return false;
		}

		for (size_t i = 0; i < unDataSize; ++i) {
			const unsigned char unSymbol = pData[i];
			*(szHex++) = nHexTable[bUseUpperCase][unSymbol >> 4];
			*(szHex++) = nHexTable[bUseUpperCase][unSymbol & 0xF];
		}

		return true;
	}

	bool EncodeToHexW(const unsigned char* const pData, const size_t unDataSize, wchar_t* szHex, const bool bUseUpperCase) {
		if (!pData) {
			return false;
		}

		if (!unDataSize) {
			return false;
		}

		if (!szHex) {
			return false;
		}

		for (size_t i = 0; i < unDataSize; ++i) {
			const unsigned char unSymbol = pData[i];
			*(szHex++) = static_cast<wchar_t>(nHexTable[bUseUpperCase][unSymbol >> 4]);
			*(szHex++) = static_cast<wchar_t>(nHexTable[bUseUpperCase][unSymbol & 0xF]);
		}

		return true;
	}

#ifdef UNICODE
	bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, wchar_t* szHex, const bool bUseUpperCase) {
		return EncodeToHexW(pData, unDataSize, szHex, bUseUpperCase);
	}
#else
	bool EncodeToHex(const unsigned char* const pData, const size_t unDataSize, char* szHex, const bool bUseUpperCase) {
		return EncodeToHexA(pData, unDataSize, szHex, bUseUpperCase);
	}
#endif

	bool DecodeFromHexA(const char* const szHex, const size_t unHexSize, unsigned char* pData) {
		if (!szHex) {
			return false;
		}

		if (!pData) {
			return false;
		}

		if (!unHexSize) {
			return false;
		}

		if ((unHexSize % 2) != 0) {
			return false;
		}

		for (size_t i = 0; i < unHexSize / 2; ++i) {
			const unsigned char unHigh = szHex[i];
			const unsigned char unLow = szHex[i + 1];
			pData[i] = unHexTableUpper[unHigh] | unHexTableLower[unLow];
		}

		return true;
	}

	bool DecodeFromHexW(const wchar_t* const szHex, const size_t unHexSize, unsigned char* pData) {
		if (!szHex) {
			return false;
		}

		if (!pData) {
			return false;
		}

		if (!unHexSize) {
			return false;
		}

		if ((unHexSize % 2) != 0) {
			return false;
		}

		size_t k = 0;
		for (size_t i = 0; i < unHexSize / 2; ++i) {
			const unsigned char unHigh = static_cast<unsigned char>(szHex[k]);
			const unsigned char unLow = static_cast<unsigned char>(szHex[k + 1]);
			pData[i] = unHexTableUpper[unHigh] | unHexTableLower[unLow];
			k += 2;
		}

		return true;
	}

#ifdef UNICODE
	bool DecodeFromHex(const wchar_t* const szHex, const size_t unHexSize, unsigned char* pData) {
		return DecodeFromHexW(szHex, unHexSize, pData);
	}
#else
	bool DecodeFromHex(const char* const szHex, const size_t unHexSize, unsigned char* pData) {
		return DecodeFromHexA(szHex, unHexSize, pData);
	}
#endif
}

// ----------------------------------------------------------------
// MemoryScan
// ----------------------------------------------------------------
namespace MemoryScan {
	// ----------------------------------------------------------------
	// FindSignature (Native)
	// ----------------------------------------------------------------

	const void* const FindSignatureNative(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const size_t unSignatureLength = strnlen_s(szSignature, DETOURS_MAX_STRSIZE);
		if (!unSignatureLength) {
			return nullptr;
		}

		if (unSize <= unSignatureLength) {
			return nullptr;
		}

		const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
		const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

		const size_t unDataBytes = unSize - unSignatureLength;
		for (size_t unIndex = 0; unIndex < unDataBytes; ++unIndex) {
			size_t unSignatureIndex = 0;
			for (; unSignatureIndex < unSignatureLength; ++unSignatureIndex) {
				const unsigned char unSignatureByte = pSignature[unSignatureIndex];
				if (unSignatureByte == unIgnoredByte) {
					continue;
				} else if (pData[unIndex + unSignatureIndex] != unSignatureByte) {
					unIndex += unSignatureIndex;
					break;
				}
			}
			if (unSignatureIndex == unSignatureLength) {
				return pData + unIndex;
			}
		}

		return nullptr;
	}

	const void* const FindSignatureNative(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignatureNative(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureNativeA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureNative(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureNative(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureNativeW(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignatureNative(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureNativeA(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (SSE2)
	// ----------------------------------------------------------------

	const void* const FindSignatureSSE2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const size_t unSignatureLength = strnlen_s(szSignature, DETOURS_MAX_STRSIZE);
		if (!unSignatureLength) {
			return nullptr;
		}

		if (unSize <= unSignatureLength) {
			return nullptr;
		}

		const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
		const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

		const size_t unDataBytes = unSize - unSignatureLength;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 16.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pData) + unCycle * 16, _MM_HINT_NTA);
			unsigned __int16 unFound = 0xFFFFui16;
			for (size_t unSignatureIndex = 0; (unSignatureIndex < unSignatureLength) && (unFound != 0); ++unSignatureIndex) {
				const unsigned char unSignatureByte = pSignature[unSignatureIndex];
				if (unSignatureByte == unIgnoredByte) {
					continue;
				} else {
					const __m128i xmm1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pData + unCycle * 16 + unSignatureIndex));
					const __m128i xmm2 = _mm_set1_epi8(static_cast<char>(unSignatureByte));
					const __m128i xmm3 = _mm_cmpeq_epi8(xmm1, xmm2);
					unFound &= _mm_movemask_epi8(xmm3);
				}
			}
			if (unFound != 0) {
				return pData + unCycle * 16 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 16;
		if (unDataBytesLeft) {
			return FindSignatureNative(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
		}

		return nullptr;
	}

	const void* const FindSignatureSSE2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignatureSSE2(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureSSE2(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureSSE2(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureSSE2W(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignatureSSE2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureSSE2A(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX)
	// ----------------------------------------------------------------

	const void* const FindSignatureAVX(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const size_t unSignatureLength = strnlen_s(szSignature, DETOURS_MAX_STRSIZE);
		if (!unSignatureLength) {
			return nullptr;
		}

		if (unSize <= unSignatureLength) {
			return nullptr;
		}

		const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
		const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

		const size_t unDataBytes = unSize - unSignatureLength;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 32.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pData) + unCycle * 32, _MM_HINT_NTA);
			unsigned __int32 unFound = 0xFFFFFFFFui32;
			for (size_t unSignatureIndex = 0; (unSignatureIndex < unSignatureLength) && (unFound != 0); ++unSignatureIndex) {
				const unsigned char unSignatureByte = pSignature[unSignatureIndex];
				if (unSignatureByte == unIgnoredByte) {
					continue;
				} else {
					const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pData + unCycle * 32 + unSignatureIndex));
					const __m256i ymm1 = _mm256_set1_epi8(static_cast<char>(unSignatureByte));

					const __m128i xmm0 = _mm_cmpeq_epi8(reinterpret_cast<const __m128i*>(&ymm0)[0], reinterpret_cast<const __m128i*>(&ymm1)[0]);
					const __m128i xmm1 = _mm_cmpeq_epi8(reinterpret_cast<const __m128i*>(&ymm0)[1], reinterpret_cast<const __m128i*>(&ymm1)[1]);

					const __m256i ymm2 = _mm256_loadu2_m128i(&xmm1, &xmm0);
					reinterpret_cast<__int16*>(&unFound)[0] &= _mm_movemask_epi8(reinterpret_cast<const __m128i*>(&ymm2)[0]);
					reinterpret_cast<__int16*>(&unFound)[1] &= _mm_movemask_epi8(reinterpret_cast<const __m128i*>(&ymm2)[1]);
				}
			}
			if (unFound != 0) {
				return pData + unCycle * 32 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 32;
		if (unDataBytesLeft) {
			return FindSignatureNative(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
		}

		return nullptr;
	}

	const void* const FindSignatureAVX(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignatureAVX(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVXA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVXW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignatureAVX(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVXW(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignatureAVX(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVXA(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX2)
	// ----------------------------------------------------------------

	const void* const FindSignatureAVX2(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const size_t unSignatureLength = strnlen_s(szSignature, DETOURS_MAX_STRSIZE);
		if (!unSignatureLength) {
			return nullptr;
		}

		if (unSize <= unSignatureLength) {
			return nullptr;
		}

		const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
		const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

		const size_t unDataBytes = unSize - unSignatureLength;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 32.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pData) + unCycle * 32, _MM_HINT_NTA);
			unsigned __int32 unFound = 0xFFFFFFFFui32;
			for (size_t unSignatureIndex = 0; (unSignatureIndex < unSignatureLength) && (unFound != 0); ++unSignatureIndex) {
				const unsigned char unSignatureByte = pSignature[unSignatureIndex];
				if (unSignatureByte == unIgnoredByte) {
					continue;
				} else {
					const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pData + unCycle * 32 + unSignatureIndex));
					const __m256i ymm1 = _mm256_set1_epi8(static_cast<char>(unSignatureByte));

					const __m256i ymm3 = _mm256_cmpeq_epi8(ymm0, ymm1);

					unFound &= _mm256_movemask_epi8(ymm3);
				}
			}
			if (unFound != 0) {
				return pData + unCycle * 32 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 32;
		if (unDataBytesLeft) {
			return FindSignatureNative(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
		}

		return nullptr;
	}

	const void* const FindSignatureAVX2(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignatureAVX2(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX2(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX2(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVX2W(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignatureAVX2(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVX2A(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX-512) [AVX512BW]
	// ----------------------------------------------------------------

	const void* const FindSignatureAVX512(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const size_t unSignatureLength = strnlen_s(szSignature, DETOURS_MAX_STRSIZE);
		if (!unSignatureLength) {
			return nullptr;
		}

		if (unSize <= unSignatureLength) {
			return nullptr;
		}

		const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
		const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

		const size_t unDataBytes = unSize - unSignatureLength;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 64.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pData) + unCycle * 64, _MM_HINT_NTA);
			unsigned __int64 unFound = 0xFFFFFFFFFFFFFFFFui64;
			for (size_t unSignatureIndex = 0; (unSignatureIndex < unSignatureLength) && (unFound != 0); ++unSignatureIndex) {
				const unsigned char unSignatureByte = pSignature[unSignatureIndex];
				if (unSignatureByte == unIgnoredByte) {
					continue;
				} else {
					const __m512i zmm0 = _mm512_loadu_si512(reinterpret_cast<const __m256i*>(pData + unCycle * 64 + unSignatureIndex));
					const __m512i zmm1 = _mm512_set1_epi8(static_cast<char>(unSignatureByte));

					unFound &= _mm512_cmpeq_epi8_mask(zmm0, zmm1);
				}
			}
			if (unFound != 0) {
				return pData + unCycle * 64 + __ctz64(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 64;
		if (unDataBytesLeft) {
			return FindSignatureNative(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
		}

		return nullptr;
	}

	const void* const FindSignatureAVX512(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignatureAVX512(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX512(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignatureAVX512(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVX512W(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignatureAVX512(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureAVX512A(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (Auto)
	// ----------------------------------------------------------------

	static bool bOnceInitialization = false;
	static bool bProcessorFeatureSSE2 = false;
	static bool bProcessorFeatureAVX = false;
	static bool bProcessorFeatureAVX2 = false;
	static bool bProcessorFeatureAVX512BW = false;

	const void* const FindSignature(const void* const pAddress, const size_t unSize, const char* const szSignature, const unsigned char unIgnoredByte) {

		if (!bOnceInitialization) {
			bOnceInitialization = true;
			int nProcessorIDs[4];
			__cpuid(nProcessorIDs, 0x00000000);
			const int nIDs = nProcessorIDs[0];
			if (nIDs >= 1) {
				__cpuid(nProcessorIDs, 0x00000001);
				bProcessorFeatureSSE2 = (nProcessorIDs[3] & (1 << 26)) != 0;
				bProcessorFeatureAVX = (nProcessorIDs[2] & (1 << 28)) != 0;
				if (nIDs >= 7) {
					__cpuid(nProcessorIDs, 0x00000007);
					bProcessorFeatureAVX2 = (nProcessorIDs[1] & (1 << 5)) != 0;
					bProcessorFeatureAVX512BW = (nProcessorIDs[1] & (1 << 30)) != 0;
				}
			}
		}

		if (bProcessorFeatureAVX512BW) {
			return FindSignatureAVX512(pAddress, unSize, szSignature, unIgnoredByte);
		} else if (bProcessorFeatureAVX2) {
			return FindSignatureAVX2(pAddress, unSize, szSignature, unIgnoredByte);
		} else if (bProcessorFeatureAVX) {
			return FindSignatureAVX(pAddress, unSize, szSignature, unIgnoredByte);
		} else if (bProcessorFeatureSSE2) {
			return FindSignatureSSE2(pAddress, unSize, szSignature, unIgnoredByte);
		} else {
			return FindSignatureNative(pAddress, unSize, szSignature, unIgnoredByte);
		}
	}

	const void* const FindSignature(const HMODULE hModule, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindSignature(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureA(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignature(hMod, szSignature, unIgnoredByte);
	}

	const void* const FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindSignature(hMod, szSignature, unIgnoredByte);
	}

#ifdef UNICODE
	const void* const FindSignature(const wchar_t* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureW(szModuleName, szSignature, unIgnoredByte);
	}
#else
	const void* const FindSignature(const char* const szModuleName, const char* const szSignature, const unsigned char unIgnoredByte) {
		return FindSignatureA(szModuleName, szSignature, unIgnoredByte);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (Native)
	// ----------------------------------------------------------------

	const void* const FindDataNative(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		if (unSize <= unDataSize) {
			return nullptr;
		}

		const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

		const size_t unDataBytes = unSize - unDataSize;
		for (size_t unIndex = 0; unIndex < unDataBytes; ++unIndex) {
			size_t unDataIndex = 0;
			for (; unDataIndex < unDataSize; ++unDataIndex) {
				if (pSourceData[unIndex + unDataIndex] != pData[unDataIndex]) {
					unIndex += unDataIndex;
					break;
				}
			}
			if (unDataIndex == unDataSize) {
				return pSourceData + unIndex;
			}
		}

		return nullptr;
	}

	const void* const FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindDataNative(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataNative(hMod, pData, unDataSize);
	}

	const void* const FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataNative(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataNativeW(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataNativeA(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (SSE2)
	// ----------------------------------------------------------------

	const void* const FindDataSSE2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		if (unSize <= unDataSize) {
			return nullptr;
		}

		const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

		const size_t unDataBytes = unSize - unDataSize;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 16.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pSourceData) + unCycle * 16, _MM_HINT_NTA);
			unsigned __int16 unFound = 0xFFFFui16;
			for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
				const __m128i xmm1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pSourceData + unCycle * 16 + unDataIndex));
				const __m128i xmm2 = _mm_set1_epi8(static_cast<char>(pData[unDataIndex]));
				const __m128i xmm3 = _mm_cmpeq_epi8(xmm1, xmm2);
				unFound &= _mm_movemask_epi8(xmm3);
			}
			if (unFound != 0) {
				return pSourceData + unCycle * 16 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 16;
		if (unDataBytesLeft) {
			return FindDataNative(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
		}

		return nullptr;
	}

	const void* const FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindDataSSE2(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataSSE2(hMod, pData, unDataSize);
	}

	const void* const FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataSSE2(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataSSE2W(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataSSE2A(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (AVX)
	// ----------------------------------------------------------------

	const void* const FindDataAVX(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		if (unSize <= unDataSize) {
			return nullptr;
		}

		const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

		const size_t unDataBytes = unSize - unDataSize;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 32.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pSourceData) + unCycle * 32, _MM_HINT_NTA);
			unsigned __int32 unFound = 0xFFFFFFFFui32;
			for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
				const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pSourceData + unCycle * 32 + unDataIndex));
				const __m256i ymm1 = _mm256_set1_epi8(static_cast<char>(pData[unDataIndex]));

				const __m128i xmm0 = _mm_cmpeq_epi8(reinterpret_cast<const __m128i*>(&ymm0)[0], reinterpret_cast<const __m128i*>(&ymm1)[0]);
				const __m128i xmm1 = _mm_cmpeq_epi8(reinterpret_cast<const __m128i*>(&ymm0)[1], reinterpret_cast<const __m128i*>(&ymm1)[1]);

				const __m256i ymm2 = _mm256_loadu2_m128i(&xmm1, &xmm0);
				reinterpret_cast<__int16*>(&unFound)[0] &= _mm_movemask_epi8(reinterpret_cast<const __m128i*>(&ymm2)[0]);
				reinterpret_cast<__int16*>(&unFound)[1] &= _mm_movemask_epi8(reinterpret_cast<const __m128i*>(&ymm2)[1]);
			}
			if (unFound != 0) {
				return pSourceData + unCycle * 32 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 32;
		if (unDataBytesLeft) {
			return FindDataNative(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
		}

		return nullptr;
	}

	const void* const FindDataAVX(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindDataAVX(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataAVXA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX(hMod, pData, unDataSize);
	}

	const void* const FindDataAVXW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindDataAVX(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVXW(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindDataAVX(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVXA(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (AVX2)
	// ----------------------------------------------------------------

	const void* const FindDataAVX2(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		if (unSize <= unDataSize) {
			return nullptr;
		}

		const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

		const size_t unDataBytes = unSize - unDataSize;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 32.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pSourceData) + unCycle * 32, _MM_HINT_NTA);
			unsigned __int32 unFound = 0xFFFFFFFFui32;
			for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
				const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pSourceData + unCycle * 32 + unDataIndex));
				const __m256i ymm1 = _mm256_set1_epi8(static_cast<char>(pData[unDataIndex]));

				const __m256i ymm3 = _mm256_cmpeq_epi8(ymm0, ymm1);

				unFound &= _mm256_movemask_epi8(ymm3);
			}
			if (unFound != 0) {
				return pSourceData + unCycle * 32 + __ctz32(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 32;
		if (unDataBytesLeft) {
			return FindDataNative(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
		}

		return nullptr;
	}

	const void* const FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindDataAVX2(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX2(hMod, pData, unDataSize);
	}

	const void* const FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX2(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX2W(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX2A(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (AVX-512) [AVX512BW]
	// ----------------------------------------------------------------

	const void* const FindDataAVX512(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		if (unSize <= unDataSize) {
			return nullptr;
		}

		const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

		const size_t unDataBytes = unSize - unDataSize;
		const size_t unDataBytesCycles = static_cast<size_t>(ceil(static_cast<double>(unDataBytes) / 64.0)) - 1;
		for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
			_mm_prefetch(reinterpret_cast<const char*>(pSourceData) + unCycle * 64, _MM_HINT_NTA);
			unsigned __int64 unFound = 0xFFFFFFFFFFFFFFFFui64;
			for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
				const __m512i zmm0 = _mm512_loadu_si512(reinterpret_cast<const __m256i*>(pSourceData + unCycle * 64 + unDataIndex));
				const __m512i zmm1 = _mm512_set1_epi8(static_cast<char>(pData[unDataIndex]));

				unFound &= _mm512_cmpeq_epi8_mask(zmm0, zmm1);
			}
			if (unFound != 0) {
				return pSourceData + unCycle * 64 + __ctz64(unFound);
			}
		}

		const size_t unDataBytesLeft = unDataBytes - unDataBytesCycles * 64;
		if (unDataBytesLeft) {
			return FindDataNative(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
		}

		return nullptr;
	}

	const void* const FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindDataAVX512(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX512(hMod, pData, unDataSize);
	}

	const void* const FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindDataAVX512(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX512W(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX512A(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (Auto)
	// ----------------------------------------------------------------

	const void* const FindData(const void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {

		if (!bOnceInitialization) {
			bOnceInitialization = true;
			int nProcessorIDs[4];
			__cpuid(nProcessorIDs, 0x00000000);
			const int nIDs = nProcessorIDs[0];
			if (nIDs >= 1) {
				__cpuid(nProcessorIDs, 0x00000001);
				bProcessorFeatureSSE2 = (nProcessorIDs[3] & (1 << 26)) != 0;
				bProcessorFeatureAVX = (nProcessorIDs[2] & (1 << 28)) != 0;
				if (nIDs >= 7) {
					__cpuid(nProcessorIDs, 0x00000007);
					bProcessorFeatureAVX2 = (nProcessorIDs[1] & (1 << 5)) != 0;
					bProcessorFeatureAVX512BW = (nProcessorIDs[1] & (1 << 30)) != 0;
				}
			}
		}

		if (bProcessorFeatureAVX512BW) {
			return FindDataAVX512(pAddress, unSize, pData, unDataSize);
		} else if (bProcessorFeatureAVX2) {
			return FindDataAVX2(pAddress, unSize, pData, unDataSize);
		} else if (bProcessorFeatureAVX) {
			return FindDataAVX(pAddress, unSize, pData, unDataSize);
		} else if (bProcessorFeatureSSE2) {
			return FindDataSSE2(pAddress, unSize, pData, unDataSize);
		} else {
			return FindDataNative(pAddress, unSize, pData, unDataSize);
		}
	}

	const void* const FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindData(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, pData, unDataSize);
	}

	const void* const FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindData(hMod, pData, unDataSize);
	}

	const void* const FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindData(hMod, pData, unDataSize);
	}

#ifdef UNICODE
	const void* const FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataW(szModuleName, pData, unDataSize);
	}
#else
	const void* const FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataA(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindRTTI
	// ----------------------------------------------------------------

	const void* const FindRTTI(const void* const pAddress, const size_t unSize, const char* const szRTTI) {
		if (!pAddress) {
			return nullptr;
		}

		if (!unSize) {
			return nullptr;
		}

		if (!szRTTI) {
			return nullptr;
		}

		const size_t unRTTILength = strnlen_s(szRTTI, DETOURS_MAX_STRSIZE);
		if (!unRTTILength) {
			return nullptr;
		}

		if (unSize <= unRTTILength) {
			return nullptr;
		}

#pragma pack(push, rttidata, 1)
		typedef const struct _PMD {
			int mdisp;
			int pdisp;
			int vdisp;
		} PMD, *PPMD;

		typedef const struct _TYPE_DESCRIPTOR {
			void* pVTable;
			void* pSpare;
			char szName[1];
		} TYPE_DESCRIPTOR, *PTYPE_DESCRIPTOR;

		typedef const struct _RTTI_BASE_CLASS_DESCRIPTOR {
#ifdef _M_X64
			unsigned int pTypeDescriptor;
#elif _M_IX86
			PTYPE_DESCRIPTOR pTypeDescriptor;
#endif
			unsigned int unNumberOfContainedBases;
			PMD Where;
			unsigned int unAttributes;
		} RTTI_BASE_CLASS_DESCRIPTOR, *PRTTI_BASE_CLASS_DESCRIPTOR;

		typedef const struct _RTTI_BASE_CLASS_ARRAY {
#ifdef _M_X64
			unsigned int pBaseClassDescriptors;
#elif _M_IX86
			PRTTI_BASE_CLASS_DESCRIPTOR pBaseClassDescriptors[1];
#endif
		} RTTI_BASE_CLASS_ARRAY, *PRTTI_BASE_CLASS_ARRAY;

		typedef const struct _RTTI_CLASS_HIERARCHY_DESCRIPTOR {
			unsigned int unSignature;
			unsigned int unAttributes;
			unsigned int unNumberOfBaseClasses;
#ifdef _M_X64
			unsigned int pBaseClassArray;
#elif _M_IX86
			PRTTI_BASE_CLASS_ARRAY pBaseClassArray;
#endif
		} RTTI_CLASS_HIERARCHY_DESCRIPTOR, *PRTTI_CLASS_HIERARCHY_DESCRIPTOR;

		typedef const struct _RTTI_COMPLETE_OBJECT_LOCATOR {
			unsigned int unSignature;
			unsigned int unOffset;
			unsigned int unConstructorOffset;
#ifdef _M_X64
			unsigned int pTypeDescriptor;
			unsigned int pClassHierarchyDescriptor;
#elif _M_IX86
			PTYPE_DESCRIPTOR pTypeDescriptor;
			PRTTI_CLASS_HIERARCHY_DESCRIPTOR pClassHierarchyDescriptor;
#endif
		} RTTI_COMPLETE_OBJECT_LOCATOR, *PRTTI_COMPLETE_OBJECT_LOCATOR;
#pragma pack(pop, rttidata)

		const void* pReference = pAddress;
		const void* pEndAddress = reinterpret_cast<const unsigned char*>(pAddress) + unSize;
		while (pReference && (pReference < pEndAddress)) {
			pReference = FindData(pReference, reinterpret_cast<size_t>(pEndAddress) - reinterpret_cast<size_t>(pReference), reinterpret_cast<const unsigned char* const>(szRTTI), unRTTILength);
			if (!pReference) {
				break;
			}

			PTYPE_DESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPE_DESCRIPTOR>(reinterpret_cast<const unsigned char*>(pReference) - sizeof(void*) * 2);
			if ((pTypeDescriptor->pVTable < pAddress) || (pTypeDescriptor->pVTable >= pEndAddress)) {
				pReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pReference) + 1);
				continue;
			}
			if (pTypeDescriptor->pSpare) {
				pReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pReference) + 1);
				continue;
			}

			const void* pTypeDescriptorReference = pAddress;
			while (pTypeDescriptorReference && (pTypeDescriptorReference < pEndAddress)) {
#ifdef _M_X64
				const size_t unTypeDescriptorOffsetTemp = reinterpret_cast<size_t>(pTypeDescriptor) - reinterpret_cast<size_t>(pAddress);
				const unsigned int unTypeDescriptorOffset = (*(reinterpret_cast<const unsigned int*>(&unTypeDescriptorOffsetTemp)));
				pTypeDescriptorReference = FindData(pTypeDescriptorReference, reinterpret_cast<size_t>(pEndAddress) - reinterpret_cast<size_t>(pTypeDescriptorReference), reinterpret_cast<const unsigned char* const>(&unTypeDescriptorOffset), sizeof(int));
				if (!pTypeDescriptorReference) {
					break;
				}
#elif _M_IX86
				pTypeDescriptorReference = FindData(pTypeDescriptorReference, reinterpret_cast<size_t>(pEndAddress) - reinterpret_cast<size_t>(pTypeDescriptorReference), reinterpret_cast<const unsigned char* const>(&pTypeDescriptor), sizeof(int));
				if (!pTypeDescriptorReference) {
					break;
				}
#endif

				const PRTTI_COMPLETE_OBJECT_LOCATOR pCompleteObjectLocation = reinterpret_cast<PRTTI_COMPLETE_OBJECT_LOCATOR>(reinterpret_cast<const unsigned char*>(pTypeDescriptorReference) - sizeof(int) * 3);
#ifdef _M_X64
				const PRTTI_CLASS_HIERARCHY_DESCRIPTOR pClassHierarchyDescriptor = reinterpret_cast<PRTTI_CLASS_HIERARCHY_DESCRIPTOR>(reinterpret_cast<size_t>(pAddress) + pCompleteObjectLocation->pClassHierarchyDescriptor);
#elif _M_IX86
				const PRTTI_CLASS_HIERARCHY_DESCRIPTOR pClassHierarchyDescriptor = pCompleteObjectLocation->pClassHierarchyDescriptor;
#endif
				if ((pClassHierarchyDescriptor < pAddress) || (pClassHierarchyDescriptor >= pEndAddress)) {
					pTypeDescriptorReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pTypeDescriptorReference) + 1);
					continue;
				}

#ifdef _M_X64
				const PRTTI_BASE_CLASS_ARRAY pBaseClassArray = reinterpret_cast<PRTTI_BASE_CLASS_ARRAY>(reinterpret_cast<size_t>(pAddress) + pClassHierarchyDescriptor->pBaseClassArray);
#elif _M_IX86
				const PRTTI_BASE_CLASS_ARRAY pBaseClassArray = pClassHierarchyDescriptor->pBaseClassArray;
#endif
				if ((pBaseClassArray < pAddress) || (pBaseClassArray >= pEndAddress)) {
					pTypeDescriptorReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pTypeDescriptorReference) + 1);
					continue;
				}

#ifdef _M_X64
				const PRTTI_BASE_CLASS_DESCRIPTOR pBaseClassDescriptors = reinterpret_cast<PRTTI_BASE_CLASS_DESCRIPTOR>(reinterpret_cast<size_t>(pAddress) + pBaseClassArray->pBaseClassDescriptors);
#elif _M_IX86
				const PRTTI_BASE_CLASS_DESCRIPTOR pBaseClassDescriptors = pBaseClassArray->pBaseClassDescriptors[0];
#endif
				if ((pBaseClassDescriptors < pAddress) || (pBaseClassDescriptors >= pEndAddress)) {
					pTypeDescriptorReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pTypeDescriptorReference) + 1);
					continue;
				}

				for (unsigned int i = 0; i < pClassHierarchyDescriptor->unNumberOfBaseClasses; ++i) {
					PRTTI_BASE_CLASS_DESCRIPTOR pBaseClassDescriptor = (&pBaseClassDescriptors)[i];
					if (!pBaseClassDescriptor) {
						continue;
					}
#ifdef _M_X64
					if (reinterpret_cast<void*>(reinterpret_cast<size_t>(pAddress) + pBaseClassDescriptor->pTypeDescriptor) == pTypeDescriptor) {
#elif _M_IX86
					if (pBaseClassDescriptor->pTypeDescriptor == pTypeDescriptor) {
#endif
						const void* const pCompleteObject = FindData(pAddress, unSize, reinterpret_cast<const unsigned char* const>(&pCompleteObjectLocation), sizeof(void*));
						if (!pCompleteObject) {
							return nullptr;
						}
						return reinterpret_cast<const void* const>(reinterpret_cast<const unsigned char* const>(pCompleteObject) + sizeof(void*));
					}
				}

				pTypeDescriptorReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pTypeDescriptorReference) + 1);
			}

			pReference = reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(pReference) + 1);
		}

		return nullptr;
	}

	const void* const FindRTTI(const HMODULE hModule, const char* const szRTTI) {
		if (!hModule) {
			return nullptr;
		}

		if (!szRTTI) {
			return nullptr;
		}

		const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
		const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

		return FindRTTI(reinterpret_cast<void*>(hModule), static_cast<size_t>(pOH->SizeOfImage) - 1, szRTTI);
	}

	const void* const FindRTTIA(const char* const szModuleName, const char* const szRTTI) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szRTTI) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleA(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindRTTI(hMod, szRTTI);
	}

	const void* const FindRTTIW(const wchar_t* const szModuleName, const char* const szRTTI) {
		if (!szModuleName) {
			return nullptr;
		}

		if (!szRTTI) {
			return nullptr;
		}

		const HMODULE hMod = GetModuleHandleW(szModuleName);
		if (!hMod) {
			return nullptr;
		}

		return FindRTTI(hMod, szRTTI);
	}

#ifdef UNICODE
	const void* const FindRTTI(const wchar_t* const szModuleName, const char* const szRTTI) {
		return FindRTTIW(szModuleName, szRTTI);
	}
#else
	const void* const FindRTTI(const char* const szModuleName, const char* const szRTTI) {
		return FindRTTIA(szModuleName, szRTTI);
	}
#endif
}

// ----------------------------------------------------------------
// MemoryProtections
// ----------------------------------------------------------------
namespace MemoryProtections {
	// ----------------------------------------------------------------
	// Smart Memory Protection
	// ----------------------------------------------------------------

	SmartMemoryProtection::SmartMemoryProtection(void* const pAddress, const size_t unSize) {
		m_pAddress = pAddress;
		m_unSize = unSize;
		m_unOriginalProtection = 0;

		if (!pAddress) {
			return;
		}

		if (!unSize) {
			return;
		}

		MEMORY_BASIC_INFORMATION meminf;
		memset(&meminf, 0, sizeof(MEMORY_BASIC_INFORMATION));

		if (!VirtualQuery(pAddress, &meminf, sizeof(MEMORY_BASIC_INFORMATION))) {
			return;
		}

		m_unOriginalProtection = meminf.Protect;
	}

	SmartMemoryProtection::~SmartMemoryProtection() {
		if (!m_pAddress) {
			return;
		}

		if (!m_unSize) {
			return;
		}

		DWORD unProtection = 0;
		VirtualProtect(m_pAddress, m_unSize, m_unOriginalProtection, &unProtection);
	}

	bool SmartMemoryProtection::ChangeProtection(const unsigned char unFlags) {
		if (!m_pAddress) {
			return false;
		}

		if (!m_unSize) {
			return false;
		}

		DWORD unProtection = 0;
		if (unFlags == MEMORYPROTECTION_READONLY) {
			if (!VirtualProtect(m_pAddress, m_unSize, PAGE_READONLY, &unProtection)) {
				return false;
			}
		} else if (unFlags == MEMORYPROTECTION_READWRITE) {
			if (!VirtualProtect(m_pAddress, m_unSize, PAGE_READWRITE, &unProtection)) {
				return false;
			}
		} else if (unFlags == MEMORYPROTECTION_READWRITE_EXECUTE) {
			if (!VirtualProtect(m_pAddress, m_unSize, PAGE_EXECUTE_READWRITE, &unProtection)) {
				return false;
			}
		}

		return true;
	}

	bool SmartMemoryProtection::RestoreProtection() {
		if (!m_pAddress) {
			return false;
		}

		if (!m_unSize) {
			return false;
		}

		DWORD unProtection = 0;
		if (!VirtualProtect(m_pAddress, m_unSize, m_unOriginalProtection, &unProtection)) {
			return false;
		}

		return true;
	}

	void* SmartMemoryProtection::GetAddress() {
		return m_pAddress;
	}

	size_t SmartMemoryProtection::GetSize() {
		return m_unSize;
	}

	// ----------------------------------------------------------------
	// Manual Memory Protection
	// ----------------------------------------------------------------

	static std::vector<std::unique_ptr<SmartMemoryProtection>> g_vecManualMemoryProtections;

	bool ChangeMemoryProtection(void* const pAddress, const size_t unSize, const unsigned char unFlags) {
		if (!pAddress) {
			return false;
		}

		if (!unSize) {
			return false;
		}

		std::unique_ptr<SmartMemoryProtection> memSMP = std::make_unique<SmartMemoryProtection>(pAddress, unSize);
		if (!memSMP) {
			return false;
		}

		if (!memSMP->ChangeProtection(unFlags)) {
			return false;
		}

		g_vecManualMemoryProtections.push_back(std::move(memSMP));

		return true;
	}

	bool RestoreMemoryProtection(void* const pAddress) {
		if (!pAddress) {
			return false;
		}

		for (std::vector<std::unique_ptr<SmartMemoryProtection>>::iterator it = g_vecManualMemoryProtections.begin(); it != g_vecManualMemoryProtections.end(); ++it) {
			if (pAddress != (*it)->GetAddress()) {
				continue;
			}

			g_vecManualMemoryProtections.erase(it);
			return true;
		}

		return false;
	}
}

int _tmain() {
	_tprintf_s(_T("[ OK ]\n"));
	return 0;
}

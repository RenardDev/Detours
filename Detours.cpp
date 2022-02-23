#include "Detours.h"

// Default
#include <Psapi.h>
#include <tchar.h>

// Advanced
#include <intrin.h>

// STL
#include <vector>
#include <memory>

// C++
#include <cstdio>

// ----------------------------------------------------------------
// MemoryUtils
// ----------------------------------------------------------------
namespace MemoryUtils {
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

	bool DecodeFromHexA(const char* szHex, const size_t unHexSize, unsigned char* const pData) {
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

		for (size_t i = 0; i < unHexSize; ++i) {
			const unsigned char unHigh = *(szHex++);
			const unsigned char unLow = *(szHex++);
			pData[i] = unHexTableUpper[unHigh] | unHexTableLower[unLow];
		}

		return true;
	}

	bool DecodeFromHexW(const wchar_t* szHex, const size_t unHexSize, unsigned char* const pData) {
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

		for (size_t i = 0; i < unHexSize; ++i) {
			const unsigned char unHigh = static_cast<unsigned char>(*(szHex++));
			const unsigned char unLow = static_cast<unsigned char>(*(szHex++));
			pData[i] = unHexTableUpper[unHigh] | unHexTableLower[unLow];
		}

		return true;
	}

#ifdef UNICODE
	bool DecodeFromHex(const wchar_t* szHex, const size_t unHexSize, unsigned char* const pData) {
		return DecodeFromHexW(szHex, unHexSize, pData);
	}
#else
	bool DecodeFromHex(const char* szHex, const size_t unHexSize, unsigned char* const pData) {
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

	void* FindSignatureNative(void* const pAddress, const size_t unSize, const char* const szSignature) {
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

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		for (; pBegin < pEnd; ++pBegin) {
			size_t unNextStart = 0;
			size_t unResult = 0;
			bool bSuccess = true;

			for (size_t j = 0; j < unSignatureLength; ++j) {
				if (reinterpret_cast<const unsigned char*>(szSignature)[j] == 0x2A) {
					continue;
				}

				const unsigned char unSymbol = pBegin[j];
				if (unSymbol == reinterpret_cast<const unsigned char*>(szSignature)[0]) {
					unNextStart = j;
				}

				if (unSymbol != reinterpret_cast<const unsigned char*>(szSignature)[j]) {
					unResult = unNextStart;
					bSuccess = false;
					break;
				}
			}

			if (bSuccess) {
				return pBegin;
			} else {
				pBegin += unResult;
			}
		}

		return nullptr;
	}

	void* FindSignatureNative(const HMODULE hModule, const char* const szSignature) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindSignatureNative(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, szSignature);
	}

	void* FindSignatureNativeA(const char* const szModuleName, const char* const szSignature) {
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

		return FindSignatureNative(hMod, szSignature);
	}

	void* FindSignatureNativeW(const wchar_t* const szModuleName, const char* const szSignature) {
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

		return FindSignatureNative(hMod, szSignature);
	}

#ifdef UNICODE
	void* FindSignatureNative(const wchar_t* const szModuleName, const char* const szSignature) {
		return FindSignatureNativeW(szModuleName, szSignature);
	}
#else
	void* FindSignatureNative(const char* const szModuleName, const char* const szSignature) {
		return FindSignatureNativeA(szModuleName, szSignature);
	}
#endif

#if defined(_M_IX86) || defined(_M_X64)
	// ----------------------------------------------------------------
	// FindSignature (SSE2)
	// ----------------------------------------------------------------

	void* FindSignatureSSE2(void* const pAddress, const size_t unSize, const char* const szSignature) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unSignatureLength) / 16.f));

		unsigned int pSignatures[32];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 16, 16)) - 1; j >= 0; --j) {
				if (reinterpret_cast<const unsigned char*>(szSignature)[i * 16 + j] != 0x2A) {
					pSignatures[i] |= 1 << j;
				}
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m128i xmm0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 64), _MM_HINT_NTA)) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
				if ((_mm_movemask_epi8(_mm_cmpeq_epi8(xmm0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin + i * 16)), _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature + i * 16)))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindSignatureSSE2(const HMODULE hModule, const char* const szSignature) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindSignatureSSE2(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, szSignature);
	}

	void* FindSignatureSSE2A(const char* const szModuleName, const char* const szSignature) {
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

		return FindSignatureSSE2(hMod, szSignature);
	}

	void* FindSignatureSSE2W(const wchar_t* const szModuleName, const char* const szSignature) {
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

		return FindSignatureSSE2(hMod, szSignature);
	}

#ifdef UNICODE
	void* FindSignatureSSE2(const wchar_t* const szModuleName, const char* const szSignature) {
		return FindSignatureSSE2W(szModuleName, szSignature);
	}
#else
	void* FindSignatureSSE2(const char* const szModuleName, const char* const szSignature) {
		return FindSignatureSSE2A(szModuleName, szSignature);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX2)
	// ----------------------------------------------------------------

	void* FindSignatureAVX2(void* const pAddress, const size_t unSize, const char* const szSignature) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unSignatureLength) / 32.f));

		unsigned int pSignatures[64];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 32, 32)) - 1; j >= 0; --j) {
				if (reinterpret_cast<const unsigned char*>(szSignature)[i * 32 + j] != 0x2A) {
					pSignatures[i] |= 1 << j;
				}
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 128), _MM_HINT_NTA)) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
				if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(ymm0, _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin + i * 32)), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature + i * 32)))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindSignatureAVX2(const HMODULE hModule, const char* const szSignature) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindSignatureAVX2(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, szSignature);
	}

	void* FindSignatureAVX2A(const char* const szModuleName, const char* const szSignature) {
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

		return FindSignatureAVX2(hMod, szSignature);
	}

	void* FindSignatureAVX2W(const wchar_t* const szModuleName, const char* const szSignature) {
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

		return FindSignatureAVX2(hMod, szSignature);
	}

#ifdef UNICODE
	void* FindSignatureAVX2(const wchar_t* const szModuleName, const char* const szSignature) {
		return FindSignatureAVX2W(szModuleName, szSignature);
	}
#else
	void* FindSignatureAVX2(const char* const szModuleName, const char* const szSignature) {
		return FindSignatureAVX2A(szModuleName, szSignature);
	}
#endif

	// ----------------------------------------------------------------
	// FindSignature (AVX512)
	// ----------------------------------------------------------------

	void* FindSignatureAVX512(void* const pAddress, const size_t unSize, const char* const szSignature) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unSignatureLength) / 64.f));

		unsigned int pSignatures[128];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 64, 64)) - 1; j >= 0; --j) {
				if (reinterpret_cast<const unsigned char*>(szSignature)[i * 64 + j] != 0x2A) {
					pSignatures[i] |= 1 << j;
				}
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m512i zmm0 = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(szSignature));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 256), _MM_HINT_NTA)) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
				if ((_mm512_cmpeq_epi8_mask(zmm0, _mm512_loadu_si512(reinterpret_cast<const __m512i*>(pBegin))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm512_cmpeq_epi8_mask(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(pBegin + i * 64)), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(szSignature + i * 64))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindSignatureAVX512(const HMODULE hModule, const char* const szSignature) {
		if (!hModule) {
			return nullptr;
		}

		if (!szSignature) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindSignatureAVX512(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, szSignature);
	}

	void* FindSignatureAVX512A(const char* const szModuleName, const char* const szSignature) {
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

		return FindSignatureAVX512(hMod, szSignature);
	}

	void* FindSignatureAVX512W(const wchar_t* const szModuleName, const char* const szSignature) {
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

		return FindSignatureAVX512(hMod, szSignature);
	}

#ifdef UNICODE
	void* FindSignatureAVX512(const wchar_t* const szModuleName, const char* const szSignature) {
		return FindSignatureAVX512W(szModuleName, szSignature);
	}
#else
	void* FindSignatureAVX512(const char* const szModuleName, const char* const szSignature) {
		return FindSignatureAVX512A(szModuleName, szSignature);
	}
#endif
#endif // _M_IX86 || _M_X64

	// ----------------------------------------------------------------
	// FindSignature (Auto)
	// ----------------------------------------------------------------

#if defined(_M_IX86) || defined(_M_X64)
	static bool g_bIsCheckedFeatures = false;
	static bool g_bIsAvailableFeatureSSE2 = false;
	static bool g_bIsAvailableFeatureAVX2 = false;
	static bool g_bIsAvailableFeatureAVX512BW = false;
#endif // _M_IX86 || _M_X64

	void* FindSignature(void* const pAddress, const size_t unSize, const char* const szSignature) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindSignatureAVX512(pAddress, unSize, szSignature);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindSignatureAVX2(pAddress, unSize, szSignature);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindSignatureSSE2(pAddress, unSize, szSignature);
		} else {
#endif // _M_IX86 || _M_X64
			return FindSignatureNative(pAddress, unSize, szSignature);
#if defined(_M_IX86) || defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindSignature(const HMODULE hModule, const char* const szSignature) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindSignatureAVX512(hModule, szSignature);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindSignatureAVX2(hModule, szSignature);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindSignatureSSE2(hModule, szSignature);
		} else {
#endif // _M_IX86 || _M_X64
			return FindSignatureNative(hModule, szSignature);
#if defined(_M_IX86) | defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindSignatureA(const char* const szModuleName, const char* const szSignature) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindSignatureAVX512A(szModuleName, szSignature);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindSignatureAVX2A(szModuleName, szSignature);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindSignatureSSE2A(szModuleName, szSignature);
		} else {
#endif // _M_IX86 || _M_X64
			return FindSignatureNativeA(szModuleName, szSignature);
#if defined(_M_IX86) || defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindSignatureW(const wchar_t* const szModuleName, const char* const szSignature) {
#if defined(_M_IX86) | defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindSignatureAVX512W(szModuleName, szSignature);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindSignatureAVX2W(szModuleName, szSignature);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindSignatureSSE2W(szModuleName, szSignature);
		} else {
#endif // _M_IX86 || _M_X64
			return FindSignatureNativeW(szModuleName, szSignature);
#if defined(_M_IX86) | defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

#ifdef UNICODE
	void* FindSignature(const wchar_t* const szModuleName, const char* const szSignature) {
		return FindSignatureW(szModuleName, szSignature);
	}
#else
	void* FindSignature(const char* const szModuleName, const char* const szSignature) {
		return FindSignatureA(szModuleName, szSignature);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (Native)
	// ----------------------------------------------------------------

	void* FindDataNative(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
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

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		for (; pBegin < pEnd; ++pBegin) {
			size_t unNextStart = 0;
			size_t unResult = 0;
			bool bSuccess = true;

			for (size_t j = 0; j < unDataSize; ++j) {
				const unsigned char unSymbol = pBegin[j];
				if (unSymbol == reinterpret_cast<const unsigned char*>(pData)[0]) {
					unNextStart = j;
				}

				if (unSymbol != reinterpret_cast<const unsigned char*>(pData)[j]) {
					unResult = unNextStart;
					bSuccess = false;
					break;
				}
			}

			if (bSuccess) {
				return pBegin;
			} else {
				pBegin += unResult;
			}
		}

		return nullptr;
	}

	void* FindDataNative(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindDataNative(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, pData, unDataSize);
	}

	void* FindDataNativeA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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

	void* FindDataNativeW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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
	void* FindDataNative(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataNativeW(szModuleName, pData, unDataSize);
	}
#else
	void* FindDataNative(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataNativeA(szModuleName, pData, unDataSize);
	}
#endif

#if defined(_M_IX86) || defined(_M_X64)
	// ----------------------------------------------------------------
	// FindData (SSE2)
	// ----------------------------------------------------------------

	void* FindDataSSE2(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unDataSize) / 16.f));

		unsigned int pSignatures[32];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (size_t j = 0; j <= unDataSize - 1; ++j) {
				pSignatures[i] |= 1 << j;
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m128i xmm0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pData));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 64), _MM_HINT_NTA)) {
			if (pData[0] == pBegin[0]) {
				if ((_mm_movemask_epi8(_mm_cmpeq_epi8(xmm0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin + i * 16)), _mm_loadu_si128(reinterpret_cast<const __m128i*>(pData + i * 16)))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindDataSSE2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindDataSSE2(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, pData, unDataSize);
	}

	void* FindDataSSE2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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

	void* FindDataSSE2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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
	void* FindDataSSE2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataSSE2W(szModuleName, pData, unDataSize);
	}
#else
	void* FindDataSSE2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataSSE2A(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (AVX2)
	// ----------------------------------------------------------------

	void* FindDataAVX2(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unDataSize) / 32.f));

		unsigned int pSignatures[64];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (size_t j = 0; j <= unDataSize - 1; ++j) {
				pSignatures[i] |= 1 << j;
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pData));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 128), _MM_HINT_NTA)) {
			if (reinterpret_cast<const unsigned char*>(pData)[0] == pBegin[0]) {
				if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(ymm0, _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin + i * 32)), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pData + i * 32)))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindDataAVX2(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindDataAVX2(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, pData, unDataSize);
	}

	void* FindDataAVX2A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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

	void* FindDataAVX2W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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
	void* FindDataAVX2(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX2W(szModuleName, pData, unDataSize);
	}
#else
	void* FindDataAVX2(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX2A(szModuleName, pData, unDataSize);
	}
#endif

	// ----------------------------------------------------------------
	// FindData (AVX512)
	// ----------------------------------------------------------------

	void* FindDataAVX512(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
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

		const size_t unSignaturesCount = static_cast<size_t>(ceil(static_cast<float>(unDataSize) / 64.f));

		unsigned int pSignatures[128];
		memset(pSignatures, 0, sizeof(pSignatures));
		for (size_t i = 0; i < unSignaturesCount; ++i) {
			for (size_t j = 0; j <= unDataSize - 1; ++j) {
				pSignatures[i] |= 1 << j;
			}
		}

		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pAddress);
		const void* const pEnd = pBegin + unSize;
		const __m512i zmm0 = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(pData));
		for (; pBegin < pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 256), _MM_HINT_NTA)) {
			if (reinterpret_cast<const unsigned char*>(pData)[0] == pBegin[0]) {
				if ((_mm512_cmpeq_epi8_mask(zmm0, _mm512_loadu_si512(reinterpret_cast<const __m512i*>(pBegin))) & pSignatures[0]) == pSignatures[0]) {
					for (size_t i = 1; i < unSignaturesCount; ++i) {
						if ((_mm512_cmpeq_epi8_mask(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(pBegin + i * 64)), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(pData + i * 64))) & pSignatures[i]) == pSignatures[i]) {
							if ((i + 1) == unSignaturesCount) {
								return pBegin;
							}
						}
					}
					return pBegin;
				}
			}
		}

		return nullptr;
	}

	void* FindDataAVX512(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
		if (!hModule) {
			return nullptr;
		}

		if (!pData) {
			return nullptr;
		}

		if (!unDataSize) {
			return nullptr;
		}

		MODULEINFO modinf;
		if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
			return nullptr;
		}

		return FindDataAVX512(reinterpret_cast<void*>(modinf.lpBaseOfDll), modinf.SizeOfImage, pData, unDataSize);
	}

	void* FindDataAVX512A(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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

	void* FindDataAVX512W(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
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
	void* FindDataAVX512(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX512W(szModuleName, pData, unDataSize);
	}
#else
	void* FindDataAVX512(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataAVX512A(szModuleName, pData, unDataSize);
	}
#endif
#endif // _M_IX86 || _M_X64

	// ----------------------------------------------------------------
	// FindData (Auto)
	// ----------------------------------------------------------------

	void* FindData(void* const pAddress, const size_t unSize, const unsigned char* const pData, const size_t unDataSize) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindDataAVX512(pAddress, unSize, pData, unDataSize);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindDataAVX2(pAddress, unSize, pData, unDataSize);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindDataSSE2(pAddress, unSize, pData, unDataSize);
		} else {
#endif // _M_IX86 || _M_X64
			return FindDataNative(pAddress, unSize, pData, unDataSize);
#if defined(_M_IX86) || defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindData(const HMODULE hModule, const unsigned char* const pData, const size_t unDataSize) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindDataAVX512(hModule, pData, unDataSize);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindDataAVX2(hModule, pData, unDataSize);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindDataSSE2(hModule, pData, unDataSize);
		} else {
#endif // _M_IX86 || _M_X64
			return FindDataNative(hModule, pData, unDataSize);
#if defined(_M_IX86) | defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindDataA(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
#if defined(_M_IX86) || defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindDataAVX512A(szModuleName, pData, unDataSize);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindDataAVX2A(szModuleName, pData, unDataSize);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindDataSSE2A(szModuleName, pData, unDataSize);
		} else {
#endif // _M_IX86 || _M_X64
			return FindDataNativeA(szModuleName, pData, unDataSize);
#if defined(_M_IX86) || defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

	void* FindDataW(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
#if defined(_M_IX86) | defined(_M_X64)
		if (!g_bIsCheckedFeatures) {
			g_bIsCheckedFeatures = true;

			int nCPUInf[4];
			__cpuid(nCPUInf, 0x00000000);
			const int nIDs = nCPUInf[0];
			if (nIDs >= 0x00000001) {
				__cpuid(nCPUInf, 0x00000001);
				g_bIsAvailableFeatureSSE2 = (nCPUInf[3] & (1 << 26)) != 0;
				if (nIDs >= 0x00000007) {
					__cpuid(nCPUInf, 0x00000007);
					g_bIsAvailableFeatureAVX2 = (nCPUInf[1] & (1 << 5)) != 0;
					g_bIsAvailableFeatureAVX512BW = (nCPUInf[1] & (1 << 30)) != 0;
				}
			}
		}

		if (g_bIsAvailableFeatureAVX512BW) {
			return FindDataAVX512W(szModuleName, pData, unDataSize);
		} else if (g_bIsAvailableFeatureAVX2) {
			return FindDataAVX2W(szModuleName, pData, unDataSize);
		} else if (g_bIsAvailableFeatureSSE2) {
			return FindDataSSE2W(szModuleName, pData, unDataSize);
		} else {
#endif // _M_IX86 || _M_X64
			return FindDataNativeW(szModuleName, pData, unDataSize);
#if defined(_M_IX86) | defined(_M_X64)
		}
#endif // _M_IX86 || _M_X64
	}

#ifdef UNICODE
	void* FindData(const wchar_t* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataW(szModuleName, pData, unDataSize);
	}
#else
	void* FindData(const char* const szModuleName, const unsigned char* const pData, const size_t unDataSize) {
		return FindDataA(szModuleName, pData, unDataSize);
	}
#endif
}

// ----------------------------------------------------------------
// MemoryProtection
// ----------------------------------------------------------------
namespace MemoryProtection {
	// ----------------------------------------------------------------
	// Smart Memory Protect
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

	DWORD SmartMemoryProtection::GetOriginalProtection() {
		return m_unOriginalProtection;
	}

	// ----------------------------------------------------------------
	// Manual MemoryProtect
	// ----------------------------------------------------------------

	static std::vector<std::unique_ptr<SmartMemoryProtection>> g_vecSmartMemoryProtections;

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

		g_vecSmartMemoryProtections.push_back(std::move(memSMP));

		return true;
	}

	bool RestoreMemoryProtection(void* const pAddress) {
		if (!pAddress) {
			return false;
		}

		for (std::vector<std::unique_ptr<SmartMemoryProtection>>::iterator it = g_vecSmartMemoryProtections.begin(); it != g_vecSmartMemoryProtections.end(); ++it) {
			if (pAddress == (*it)->GetAddress()) {
				g_vecSmartMemoryProtections.erase(it);
				return true;
			}
		}

		return false;
	}
}

int _tmain() {

	printf("FindDataNative = %08X\n", (UINT)MemoryScan::FindDataNativeA("ntdll.dll", (unsigned char*)"DbgPrint", 8));
	printf("FindDataSSE2 = %08X\n", (UINT)MemoryScan::FindDataSSE2A("ntdll.dll", (unsigned char*)"DbgPrint", 8));
	printf("FindDataAVX2 = %08X\n", (UINT)MemoryScan::FindDataAVX2A("ntdll.dll", (unsigned char*)"DbgPrint", 8));
	printf("FindDataAVX512 = %08X\n", (UINT)MemoryScan::FindDataAVX512A("ntdll.dll", (unsigned char*)"DbgPrint", 8));

	_tprintf_s(_T("[ OK ]\n"));
	return 0;
}

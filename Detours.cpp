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

		// HEX Table
		static const char nHexTable[2][16] = {
			{
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

		bool EncodeToHexA(const unsigned char* const pData, const size_t unDataSize, char* const szHex, const bool bUseUpperCase) {
			if (!pData) {
				return false;
			}

			if (!unDataSize) {
				return false;
			}

			if (!szHex) {
				return false;
			}

			for (size_t i = 0; i < unDataSize * 2; i += 2) {
				const unsigned char unSymbol = pData[i / 2];
				szHex[i] = nHexTable[bUseUpperCase][unSymbol >> 4];
				szHex[i + 1] = nHexTable[bUseUpperCase][unSymbol & 0xF];
			}

			return true;
		}

		bool EncodeToHexW(const unsigned char* const pData, const size_t unDataSize, wchar_t* const szHex, const bool bUseUpperCase) {
			if (!pData) {
				return false;
			}

			if (!unDataSize) {
				return false;
			}

			if (!szHex) {
				return false;
			}

			for (size_t i = 0; i < unDataSize * 2; i += 2) {
				const unsigned char unSymbol = pData[i / 2];
				szHex[i] = static_cast<wchar_t>(nHexTable[bUseUpperCase][unSymbol >> 4]);
				szHex[i + 1] = static_cast<wchar_t>(nHexTable[bUseUpperCase][unSymbol & 0xF]);
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

		bool DecodeFromHexA(const char* const szHex, const size_t unDecodeBytes, unsigned char* const pData) {
			if (!szHex) {
				return false;
			}

			if (!pData) {
				return false;
			}

			if (!unDecodeBytes) {
				return false;
			}

			for (size_t i = 0; i < unDecodeBytes * 2; i += 2) {
				const unsigned char unHigh = unHexTableUpper[static_cast<unsigned char>(szHex[i])];
				const unsigned char unLow = unHexTableLower[static_cast<unsigned char>(szHex[i + 1])];
				if ((unHigh == 0xFF) || (unLow == 0xFF)) {
					return false;
				}
				pData[i / 2] = unHigh | unLow;
			}

			return true;
		}

		bool DecodeFromHexW(const wchar_t* const szHex, const size_t unDecodeBytes, unsigned char* const pData) {
			if (!szHex) {
				return false;
			}

			if (!pData) {
				return false;
			}

			if (!unDecodeBytes) {
				return false;
			}

			for (size_t i = 0; i < unDecodeBytes * 2; i += 2) {
				const unsigned char unHigh = unHexTableUpper[static_cast<unsigned char>(szHex[i])];
				const unsigned char unLow = unHexTableLower[static_cast<unsigned char>(szHex[i + 1])];
				if ((unHigh == 0xFF) || (unLow == 0xFF)) {
					return false;
				}
				pData[i / 2] = unHigh | unLow;
			}

			return true;
		}

#ifdef UNICODE
		bool DecodeFromHex(const wchar_t* const szHex, const size_t unDecodeBytes, unsigned char* const pData) {
			return DecodeFromHexW(szHex, unDecodeBytes, pData);
		}
#else
		bool DecodeFromHex(const char* const szHex, const size_t unDecodeBytes, unsigned char* const  pData) {
			return DecodeFromHexA(szHex, unDecodeBytes, pData);
		}
#endif
	}


	// ----------------------------------------------------------------
	// Scan
	// ----------------------------------------------------------------
	namespace Scan {

		// ----------------------------------------------------------------
		// Bit scan
		// ----------------------------------------------------------------

		static const unsigned __int16 inline __bsf16(const unsigned __int16 unValue) {
			for (unsigned char i = 0; i < 16; ++i) {
				if (((unValue >> i) & 1) != 0) {
					return i;
				}
			}
			return 16;
		}

		static const unsigned __int32 inline __bsf32(const unsigned __int32 unValue) {
			for (unsigned char i = 0; i < 32; ++i) {
				if (((unValue >> i) & 1) != 0) {
					return i;
				}
			}
			return 32;
		}

		static const unsigned __int64 inline __bsf64(const unsigned __int64 unValue) {
			for (unsigned char i = 0; i < 64; ++i) {
				if (((unValue >> i) & 1) != 0) {
					return i;
				}
			}
			return 64;
		}

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

			for (size_t unIndex = 0; unIndex < unSize; ++unIndex) {
				size_t unSignatureIndex = 0;
				for (; unSignatureIndex < unSignatureLength; ++unSignatureIndex) {
					const unsigned char unSignatureByte = pSignature[unSignatureIndex];
					if (unSignatureByte == unIgnoredByte) {
						continue;
					} else if (pData[unIndex + unSignatureIndex] != unSignatureByte) {
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

			if (unSize < unSignatureLength) {
				return nullptr;
			}

			const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
			const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 16.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
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
					return pData + unCycle * 16 + __bsf16(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 16;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unSignatureLength) {
					return FindSignatureNative(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
				}
				return FindSignatureNative(pData + unSize - unDataBytesLeft, unDataBytesLeft, szSignature);
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

			if (unSize < unSignatureLength) {
				return nullptr;
			}

			const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
			const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 32.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
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
					return pData + unCycle * 32 + __bsf32(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 32;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unSignatureLength) {
					return FindSignatureSSE2(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
				}
				return FindSignatureSSE2(pData + unSize - unDataBytesLeft, unDataBytesLeft, szSignature);
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

			if (unSize < unSignatureLength) {
				return nullptr;
			}

			const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
			const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 32.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
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
					return pData + unCycle * 32 + __bsf32(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 32;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unSignatureLength) {
					return FindSignatureAVX(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
				}
				return FindSignatureAVX(pData + unSize - unDataBytesLeft, unDataBytesLeft, szSignature);
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

			if (unSize < unSignatureLength) {
				return nullptr;
			}

			const unsigned char* const pData = reinterpret_cast<const unsigned char* const>(pAddress);
			const unsigned char* const pSignature = reinterpret_cast<const unsigned char* const>(szSignature);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 64.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
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
					return pData + unCycle * 64 + __bsf64(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 64;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unSignatureLength) {
					return FindSignatureAVX2(pData + unSize - unDataBytesLeft - unSignatureLength, unDataBytesLeft + unSignatureLength, szSignature);
				}
				return FindSignatureAVX2(pData + unSize - unDataBytesLeft, unDataBytesLeft, szSignature);
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

			if (unSize < unDataSize) {
				return nullptr;
			}

			const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

			for (size_t unIndex = 0; unIndex < unSize; ++unIndex) {
				size_t unDataIndex = 0;
				for (; unDataIndex < unDataSize; ++unDataIndex) {
					if (pSourceData[unIndex + unDataIndex] != pData[unDataIndex]) {
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

			if (unSize < unDataSize) {
				return nullptr;
			}

			const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 16.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
				unsigned __int16 unFound = 0xFFFFui16;
				for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
					const __m128i xmm1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pSourceData + unCycle * 16 + unDataIndex));
					const __m128i xmm2 = _mm_set1_epi8(static_cast<char>(pData[unDataIndex]));

					const __m128i xmm3 = _mm_cmpeq_epi8(xmm1, xmm2);

					unFound &= _mm_movemask_epi8(xmm3);
				}
				if (unFound != 0) {
					return pSourceData + unCycle * 16 + __bsf16(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 16;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unDataSize) {
					return FindDataNative(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
				}
				return FindDataNative(pSourceData + unSize - unDataBytesLeft, unDataBytesLeft, pData, unDataSize);
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

			if (unSize < unDataSize) {
				return nullptr;
			}

			const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 32.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
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
					return pSourceData + unCycle * 32 + __bsf32(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 32;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unDataSize) {
					return FindDataSSE2(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
				}
				return FindDataSSE2(pSourceData + unSize - unDataBytesLeft, unDataBytesLeft, pData, unDataSize);
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

			if (unSize < unDataSize) {
				return nullptr;
			}

			const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 32.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
				unsigned __int32 unFound = 0xFFFFFFFFui32;
				for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
					const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pSourceData + unCycle * 32 + unDataIndex));
					const __m256i ymm1 = _mm256_set1_epi8(static_cast<char>(pData[unDataIndex]));

					const __m256i ymm3 = _mm256_cmpeq_epi8(ymm0, ymm1);

					unFound &= _mm256_movemask_epi8(ymm3);
				}
				if (unFound != 0) {
					return pSourceData + unCycle * 32 + __bsf32(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 32;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unDataSize) {
					return FindDataAVX(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
				}
				return FindDataAVX(pSourceData + unSize - unDataBytesLeft, unDataBytesLeft, pData, unDataSize);
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

			if (unSize < unDataSize) {
				return nullptr;
			}

			const unsigned char* const pSourceData = reinterpret_cast<const unsigned char* const>(pAddress);

			const size_t unDataBytesCycles = static_cast<size_t>(floor(static_cast<double>(unSize) / 64.0));
			for (size_t unCycle = 0; unCycle < unDataBytesCycles; ++unCycle) {
				unsigned __int64 unFound = 0xFFFFFFFFFFFFFFFFui64;
				for (size_t unDataIndex = 0; (unDataIndex < unDataSize) && (unFound != 0); ++unDataIndex) {
					const __m512i zmm0 = _mm512_loadu_si512(reinterpret_cast<const __m256i*>(pSourceData + unCycle * 64 + unDataIndex));
					const __m512i zmm1 = _mm512_set1_epi8(static_cast<char>(pData[unDataIndex]));

					unFound &= _mm512_cmpeq_epi8_mask(zmm0, zmm1);
				}
				if (unFound != 0) {
					return pSourceData + unCycle * 64 + __bsf64(unFound);
				}
			}

			const size_t unDataBytesLeft = unSize - unDataBytesCycles * 64;
			if (unDataBytesLeft) {
				if (unDataBytesLeft < unDataSize) {
					return FindDataAVX2(pSourceData + unSize - unDataBytesLeft - unDataSize, unDataBytesLeft + unDataSize, pData, unDataSize);
				}
				return FindDataAVX2(pSourceData + unSize - unDataBytesLeft, unDataBytesLeft, pData, unDataSize);
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

		static const void* const _FindRTTI(const void* const pAddress, const size_t unSize, const char* const szRTTI) {
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

#pragma pack(push, r1, 1)
			typedef const struct _PMD {
				int mdisp;
				int pdisp;
				int vdisp;
			} PMD, *PPMD;

			typedef const struct _TYPE_DESCRIPTOR {
				void* pVFTable;
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
#pragma pack(pop, r1)

			const void* pReference = pAddress;
			const void* pEndAddress = reinterpret_cast<const unsigned char*>(pAddress) + unSize;
			while (pReference && (pReference < pEndAddress)) {
				pReference = FindData(pReference, reinterpret_cast<size_t>(pEndAddress) - reinterpret_cast<size_t>(pReference), reinterpret_cast<const unsigned char* const>(szRTTI), unRTTILength);
				if (!pReference) {
					break;
				}

				PTYPE_DESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPE_DESCRIPTOR>(reinterpret_cast<const unsigned char*>(pReference) - sizeof(void*) * 2);
				if ((pTypeDescriptor->pVFTable < pAddress) || (pTypeDescriptor->pVFTable >= pEndAddress)) {
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

		// Ren: Fixes bug with Visual Studio static code analyzer...
		const void* const FindRTTI(const void* const pAddress, const size_t unSize, const char* const szRTTI) {
			return _FindRTTI(pAddress, unSize, szRTTI);
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
	// Memory
	// ----------------------------------------------------------------
	namespace Memory {

		// ----------------------------------------------------------------
		// Smart Protection
		// ----------------------------------------------------------------

		SmartProtection::SmartProtection(const void* const pAddress, const size_t unSize) : m_pAddress(pAddress), m_unSize(unSize) {
			m_unOriginalProtection = 0;

			if (!pAddress) {
				return;
			}

			if (!unSize) {
				return;
			}

			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));

			if (!VirtualQuery(pAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
				return;
			}

			m_unOriginalProtection = mbi.Protect;
		}

		SmartProtection::~SmartProtection() {
			if (!m_pAddress) {
				return;
			}

			if (!m_unSize) {
				return;
			}

			DWORD unProtection = 0;
			VirtualProtect(const_cast<void* const>(m_pAddress), m_unSize, m_unOriginalProtection, &unProtection);
		}

		bool SmartProtection::ChangeProtection(const DWORD unNewProtection) {
			if (!m_pAddress) {
				return false;
			}

			if (!m_unSize) {
				return false;
			}

			DWORD unProtection = 0;
			if (!VirtualProtect(const_cast<void* const>(m_pAddress), m_unSize, unNewProtection, &unProtection)) {
				return false;
			}

			return true;
		}

		bool SmartProtection::RestoreProtection() {
			if (!m_pAddress) {
				return false;
			}

			if (!m_unSize) {
				return false;
			}

			DWORD unProtection = 0;
			if (!VirtualProtect(const_cast<void* const>(m_pAddress), m_unSize, m_unOriginalProtection, &unProtection)) {
				return false;
			}

			return true;
		}

		const void* const SmartProtection::GetAddress() {
			return m_pAddress;
		}

		const size_t SmartProtection::GetSize() {
			return m_unSize;
		}

		DWORD SmartProtection::GetOriginalProtection() {
			return m_unOriginalProtection;
		}

		// ----------------------------------------------------------------
		// Manual Protection
		// ----------------------------------------------------------------

		static std::vector<std::unique_ptr<SmartProtection>> g_vecManualProtections;

		bool ChangeProtection(const void* const pAddress, const size_t unSize, const DWORD unNewProtection) {
			if (!pAddress) {
				return false;
			}

			if (!unSize) {
				return false;
			}

			auto pMemory = std::make_unique<SmartProtection>(pAddress, unSize);
			if (!pMemory) {
				return false;
			}

			if (!pMemory->ChangeProtection(unNewProtection)) {
				return false;
			}

			g_vecManualProtections.push_back(std::move(pMemory));
			return true;
		}

		bool RestoreProtection(const void* const pAddress) {
			if (!pAddress) {
				return false;
			}

			for (auto it = g_vecManualProtections.begin(); it != g_vecManualProtections.end(); ++it) {
				if (pAddress != (*it)->GetAddress()) {
					continue;
				}

				g_vecManualProtections.erase(it);
				return true;
			}

			return false;
		}
	}

	// ----------------------------------------------------------------
	// Hook
	// ----------------------------------------------------------------
	namespace Hook {

		// ----------------------------------------------------------------
		// Smart Import Hook
		// ----------------------------------------------------------------

		SmartImportHook::SmartImportHook(const HMODULE hModule, const char* const szImportName, const char* const szImportModuleName) {
			m_pAddress = nullptr;
			m_pOriginalAddress = nullptr;
			m_pHookAddress = nullptr;

			if (!hModule) {
				return;
			}

			if (!szImportName) {
				return;
			}

			const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
			const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

			const PIMAGE_DATA_DIRECTORY pImportDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
			const PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char*>(hModule) + pImportDD->VirtualAddress);
			for (size_t i = 0; pImportDesc[i].Name != 0; ++i) {
				if (szImportModuleName) {
					if (strncmp(reinterpret_cast<char*>(hModule) + pImportDesc[i].Name, szImportModuleName, 0x100) != 0) {
						continue;
					}
				}

				const PIMAGE_THUNK_DATA pThunkDataImportNameTable = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(hModule) + pImportDesc[i].OriginalFirstThunk);
				const PIMAGE_THUNK_DATA pThunkDataImportAddressTable = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char*>(hModule) + pImportDesc[i].FirstThunk);
				for (size_t j = 0; pThunkDataImportNameTable[j].u1.AddressOfData != 0; ++j) {
					if (pThunkDataImportNameTable[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						continue;
					} else {
						const PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<char*>(hModule) + pThunkDataImportNameTable[j].u1.AddressOfData);
						if (strncmp(pImportByName->Name, szImportName, 0x7FFu) == 0) {
							m_pAddress = reinterpret_cast<const void**>(&(pThunkDataImportAddressTable[j].u1.Function));
							m_pOriginalAddress = *m_pAddress;
						}
					}
				}
			}
		}

		SmartImportHook::~SmartImportHook() {
			UnHook();
		}

		bool SmartImportHook::Hook(const void* const pHookAddress) {
			if (!m_pAddress) {
				return false;
			}

			if (*m_pAddress != m_pOriginalAddress) {
				return false;
			}

			Detours::Memory::SmartProtection Memory(m_pAddress, sizeof(void*));
			if (Memory.ChangeProtection(PAGE_READWRITE)) {
				*m_pAddress = pHookAddress;
				m_pHookAddress = pHookAddress;
				return true;
			}

			return false;
		}

		bool SmartImportHook::UnHook() {
			if (!m_pAddress) {
				return false;
			}

			if (*m_pAddress == m_pOriginalAddress) {
				return false;
			}

			Detours::Memory::SmartProtection Memory(m_pAddress, sizeof(void*));
			if (Memory.ChangeProtection(PAGE_READWRITE)) {
				*m_pAddress = m_pOriginalAddress;
				m_pHookAddress = nullptr;
				return true;
			}

			return false;
		}

		const void* SmartImportHook::GetOriginalAddress() {
			return m_pOriginalAddress;
		}

		const void* SmartImportHook::GetHookAddress() {
			return m_pHookAddress;
		}

		// ----------------------------------------------------------------
		// Manual Import Hook
		// ----------------------------------------------------------------

		static std::vector<std::unique_ptr<SmartImportHook>> g_vecManualImportHooks;

		bool HookImport(const HMODULE hModule, const char* const szImportName, const void* const pHookAddress) {
			if (!hModule) {
				return false;
			}

			if (!szImportName) {
				return false;
			}

			if (!pHookAddress) {
				return false;
			}

			auto pHook = std::make_unique<SmartImportHook>(hModule, szImportName);
			if (!pHook) {
				return false;
			}

			if (!pHook->Hook(pHookAddress)) {
				return false;
			}

			g_vecManualImportHooks.push_back(std::move(pHook));
			return true;
		}

		bool UnHookImport(const void* const pHookAddress) {
			if (!pHookAddress) {
				return false;
			}

			for (auto it = g_vecManualImportHooks.begin(); it != g_vecManualImportHooks.end(); ++it) {
				if (pHookAddress != (*it)->GetHookAddress()) {
					continue;
				}

				g_vecManualImportHooks.erase(it);
				return true;
			}

			return false;
		}

		// ----------------------------------------------------------------
		// Smart Export Hook
		// ----------------------------------------------------------------

		SmartExportHook::SmartExportHook(const HMODULE hModule, const char* const szExportName) {
			m_hModule = nullptr;
			m_pAddress = nullptr;
			m_unOriginalAddress = 0;
			m_pHookAddress = nullptr;

			if (!hModule) {
				return;
			}

			m_hModule = hModule;

			if (!szExportName) {
				return;
			}

			const PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			const PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(hModule) + pDH->e_lfanew);
			const PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);

			const PIMAGE_DATA_DIRECTORY pExportDD = &(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
			const PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(hModule) + pExportDD->VirtualAddress);

			const PDWORD pExportAddresses = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(hModule) + pExportDirectory->AddressOfFunctions);
			const PWORD pExportOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<char*>(hModule) + pExportDirectory->AddressOfNameOrdinals);
			const PDWORD pExportNames = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(hModule) + pExportDirectory->AddressOfNames);

			const size_t unAddressOfFunctions = pExportDirectory->NumberOfFunctions;
			for (size_t i = 0; i < unAddressOfFunctions; ++i) {
				if (strncmp(szExportName, reinterpret_cast<char*>(hModule) + pExportNames[i], 0x7FF) == 0) {
					m_pAddress = reinterpret_cast<PDWORD>(&(pExportAddresses[pExportOrdinals[i]]));
					m_unOriginalAddress = *m_pAddress;
				}
			}

		}

		SmartExportHook::~SmartExportHook() {
			UnHook();
		}

		bool SmartExportHook::Hook(const void* const pHookAddress) {
			if (!m_hModule) {
				return false;
			}

			if (!m_pAddress) {
				return false;
			}

			if (*m_pAddress != m_unOriginalAddress) {
				return false;
			}

			const size_t unNewAddress = reinterpret_cast<size_t>(pHookAddress) - reinterpret_cast<size_t>(m_hModule);
			if (unNewAddress >= 0xFFFFFFFFui32) {
				return false;
			}

			Detours::Memory::SmartProtection Memory(m_pAddress, sizeof(DWORD));
			if (Memory.ChangeProtection(PAGE_READWRITE)) {
				*m_pAddress = static_cast<DWORD>(unNewAddress);
				m_pHookAddress = pHookAddress;
				return true;
			}

			return false;
		}

		bool SmartExportHook::UnHook() {
			if (!m_hModule) {
				return false;
			}

			if (!m_pAddress) {
				return false;
			}

			if (*m_pAddress == m_unOriginalAddress) {
				return false;
			}

			Detours::Memory::SmartProtection Memory(m_pAddress, sizeof(DWORD));
			if (Memory.ChangeProtection(PAGE_READWRITE)) {
				*m_pAddress = m_unOriginalAddress;
				m_pHookAddress = nullptr;
				return true;
			}

			return false;
		}

		const void* SmartExportHook::GetOriginalAddress() {
			if (!m_hModule) {
				return nullptr;
			}
			return reinterpret_cast<const void*>(reinterpret_cast<char*>(m_hModule) + m_unOriginalAddress);
		}

		const void* SmartExportHook::GetHookAddress() {
			return m_pHookAddress;
		}

		// ----------------------------------------------------------------
		// Manual Import Hook
		// ----------------------------------------------------------------

		static std::vector<std::unique_ptr<SmartExportHook>> g_vecManualExportHooks;

		bool HookExport(const HMODULE hModule, const char* const szExportName, const void* const pHookAddress) {
			if (!hModule) {
				return false;
			}

			if (!szExportName) {
				return false;
			}

			if (!pHookAddress) {
				return false;
			}

			auto pHook = std::make_unique<SmartExportHook>(hModule, szExportName);
			if (!pHook) {
				return false;
			}

			if (!pHook->Hook(pHookAddress)) {
				return false;
			}

			g_vecManualExportHooks.push_back(std::move(pHook));
			return true;
		}

		bool UnHookExport(const void* const pHookAddress) {
			if (!pHookAddress) {
				return false;
			}

			for (auto it = g_vecManualExportHooks.begin(); it != g_vecManualExportHooks.end(); ++it) {
				if (pHookAddress != (*it)->GetHookAddress()) {
					continue;
				}

				g_vecManualExportHooks.erase(it);
				return true;
			}

			return false;
		}
	}
}

int _tmain() {
	_tprintf_s(_T("[ OK ]\n"));
	return 0;
}

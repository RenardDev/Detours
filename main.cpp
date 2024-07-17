
// Default
#include <Windows.h>
#include <tchar.h>

// Advanced
#include <intrin.h>

// C++
#include <cstdio>
#include <typeinfo>
#include <iostream>
#include <bitset>

// Detours
#include "Detours.h"

// interrupts.asm
#ifdef _M_X64
extern "C" unsigned long long __cdecl CallInterrupt(unsigned long long unRAX, unsigned long long unRCX, unsigned long long unRDX, unsigned long long unRBX, unsigned long long unRBP, unsigned long long unRSI, unsigned long long unRDI, unsigned long long unR8, unsigned long long unR9, unsigned long long unR10, unsigned long long unR11, unsigned long long unR12, unsigned long long unR13, unsigned long long unR14, unsigned long long unR15);
#elif _M_IX86
extern "C" unsigned int __cdecl CallInterrupt(unsigned int unEAX, unsigned int unECX, unsigned int unEDX, unsigned int unEBX, unsigned int unEBP, unsigned int unESI, unsigned int unEDI);
#endif

enum TEST_MODES : unsigned int {
	TEST_NONE = 0,
	TEST_KUSER_SHARED_DATA = 1 << 0,
	TEST_KUSER_QPC_SHARED_DATA = 1 << 1,
	TEST_PEB = 1 << 2,
	TEST_TEB = 1 << 3,
	TEST_LDR = 1 << 4,
	TEST_CODEC = 1 << 5,
	TEST_HEXADECIMAL = 1 << 6,
	TEST_SCAN = 1 << 7,
	TEST_RTTI = 1 << 8,
	TEST_SYNC = 1 << 9,
	TEST_PIPE = 1 << 10,
	TEST_PARALLEL = 1 << 11,
	TEST_MEMORY = 1 << 12,
	TEST_EXCEPTION = 1 << 13,
	TEST_RDDISADM = 1 << 14,
	TEST_HOOK = 1 << 15,
	TEST_ALL = 0xFFFFFFFF
};

int _tmain(int nArguments, PTCHAR* pArguments) {

	unsigned int unTestModes = TEST_MODES::TEST_NONE;

	if (nArguments > 1) {
		for (int i = 0; i < nArguments; ++i) {
			PTCHAR pArgument = pArguments[i];

			if (_tcscmp(pArgument, _T("/test-kusd")) == 0) {
				unTestModes |= TEST_MODES::TEST_KUSER_SHARED_DATA;
			}

			if (_tcscmp(pArgument, _T("/test-qpc-kusd")) == 0) {
				unTestModes |= TEST_MODES::TEST_KUSER_QPC_SHARED_DATA;
			}

			if (_tcscmp(pArgument, _T("/test-peb")) == 0) {
				unTestModes |= TEST_MODES::TEST_PEB;
			}

			if (_tcscmp(pArgument, _T("/test-teb")) == 0) {
				unTestModes |= TEST_MODES::TEST_TEB;
			}

			if (_tcscmp(pArgument, _T("/test-ldr")) == 0) {
				unTestModes |= TEST_MODES::TEST_LDR;
			}

			if (_tcscmp(pArgument, _T("/test-codec")) == 0) {
				unTestModes |= TEST_MODES::TEST_CODEC;
			}

			if (_tcscmp(pArgument, _T("/test-hexadecimal")) == 0) {
				unTestModes |= TEST_MODES::TEST_HEXADECIMAL;
			}

			if (_tcscmp(pArgument, _T("/test-scan")) == 0) {
				unTestModes |= TEST_MODES::TEST_SCAN;
			}

			if (_tcscmp(pArgument, _T("/test-rtti")) == 0) {
				unTestModes |= TEST_MODES::TEST_RTTI;
			}

			if (_tcscmp(pArgument, _T("/test-sync")) == 0) {
				unTestModes |= TEST_MODES::TEST_SYNC;
			}

			if (_tcscmp(pArgument, _T("/test-pipe")) == 0) {
				unTestModes |= TEST_MODES::TEST_PIPE;
			}

			if (_tcscmp(pArgument, _T("/test-parallel")) == 0) {
				unTestModes |= TEST_MODES::TEST_PARALLEL;
			}

			if (_tcscmp(pArgument, _T("/test-memory")) == 0) {
				unTestModes |= TEST_MODES::TEST_MEMORY;
			}

			if (_tcscmp(pArgument, _T("/test-rddisasm")) == 0) {
				unTestModes |= TEST_MODES::TEST_RDDISADM;
			}

			if (_tcscmp(pArgument, _T("/test-hook")) == 0) {
				unTestModes |= TEST_MODES::TEST_HOOK;
			}

			if (_tcscmp(pArgument, _T("/test-all")) == 0) {
				unTestModes = TEST_MODES::TEST_ALL;
			}
		}
	}

	if (unTestModes) {
		return 0;
	}

	return 0;
}

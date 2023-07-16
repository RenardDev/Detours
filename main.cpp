
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

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

typedef struct _SHARED_MEMORY {
	bool m_bStop;
	DWORD m_unTick;
} SHARED_MEMORY, *PSHARED_MEMORY;

class TestingRTTI {
public:
	TestingRTTI() {
		m_bFoo = true;
		m_bBoo = false;
	}

	virtual bool foo() { return m_bFoo; }
	virtual bool boo() { return m_bBoo; }

private:
	bool m_bFoo;
	bool m_bBoo;
};

DATA_SECTION_BEGIN(r1, ".dat"); // Will be in a new `.dat` segment
__declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;
DATA_SECTION_END(r1);

DWORD GetUBR() {
	HKEY hKey = nullptr;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion"), &hKey)) {
		return 0;
	}

	if (!hKey) {
		return 0;
	}

	DWORD unUBR = 0;
	DWORD unLengthUBR = sizeof(unUBR);
	if (RegQueryValueEx(hKey, _T("UBR"), nullptr, nullptr, reinterpret_cast<LPBYTE>(&unUBR), &unLengthUBR)) {
		RegCloseKey(hKey);
		return 0;
	}

	RegCloseKey(hKey);
	return unUBR;
}

bool OnException(const EXCEPTION_RECORD& Exception, const PCONTEXT pCTX) {
	if (Exception.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
		return false;
	}

	const unsigned char* const pAddress = reinterpret_cast<const unsigned char* const>(Exception.ExceptionAddress);
	if (!pAddress) {
		return false;
	}

	if (pAddress[0] != 0xCD) {
		return false;
	}

	if ((pAddress[1] != 0x7D) && (pAddress[1] != 0x7E)) {
		return false;
	}

	_tprintf_s(_T("[OnException] Called `int 0x%02X`\n"), pAddress[1]);
#ifdef _M_X64
	_tprintf_s(_T("  -> RAX = 0x%016llX\n"), pCTX->Rax);
	_tprintf_s(_T("  -> RCX = 0x%016llX\n"), pCTX->Rcx);
	_tprintf_s(_T("  -> RDX = 0x%016llX\n"), pCTX->Rdx);
	_tprintf_s(_T("  -> RBX = 0x%016llX\n"), pCTX->Rbx);
	_tprintf_s(_T("  -> RBP = 0x%016llX\n"), pCTX->Rbp);
	_tprintf_s(_T("  -> RSI = 0x%016llX\n"), pCTX->Rsi);
	_tprintf_s(_T("  -> RDI = 0x%016llX\n"), pCTX->Rdi);
	_tprintf_s(_T("  ->  R8 = 0x%016llX\n"), pCTX->R8);
	_tprintf_s(_T("  ->  R9 = 0x%016llX\n"), pCTX->R9);
	_tprintf_s(_T("  -> R10 = 0x%016llX\n"), pCTX->R10);
	_tprintf_s(_T("  -> R11 = 0x%016llX\n"), pCTX->R11);
	_tprintf_s(_T("  -> R12 = 0x%016llX\n"), pCTX->R12);
	_tprintf_s(_T("  -> R13 = 0x%016llX\n"), pCTX->R13);
	_tprintf_s(_T("  -> R14 = 0x%016llX\n"), pCTX->R14);
	_tprintf_s(_T("  -> R15 = 0x%016llX\n"), pCTX->R15);
#elif _M_IX86
	_tprintf_s(_T("  -> EAX = 0x%08X\n"), pCTX->Eax);
	_tprintf_s(_T("  -> ECX = 0x%08X\n"), pCTX->Ecx);
	_tprintf_s(_T("  -> EDX = 0x%08X\n"), pCTX->Edx);
	_tprintf_s(_T("  -> EBX = 0x%08X\n"), pCTX->Ebx);
	_tprintf_s(_T("  -> EBP = 0x%08X\n"), pCTX->Ebp);
	_tprintf_s(_T("  -> ESI = 0x%08X\n"), pCTX->Esi);
	_tprintf_s(_T("  -> EDI = 0x%08X\n"), pCTX->Edi);
#endif

#ifdef _M_X64
	pCTX->Rip += 2;
#elif _M_IX86
	pCTX->Eip += 2;
#else
#error Unknown platform
#endif

	return true;
}

bool Sleep_MemoryHook(const std::unique_ptr<Detours::Hook::MemoryHook>& pHook, const PCONTEXT pCTX) {
	_CRT_UNUSED(pHook);

	_tprintf_s(_T("[Sleep_MemoryHook] Called!\n"));
#ifdef _M_X64
	pCTX->Rip = *reinterpret_cast<PDWORD64>(pCTX->Rsp); // [SP] = RETURN ADDRESS
	pCTX->Rsp += 8; // Clearing stack (RETURN ADDRESS)
#elif _M_IX86
	pCTX->Eip = *reinterpret_cast<PDWORD>(pCTX->Esp); // [SP] = RETURN ADDRESS
	pCTX->Esp += 8; // Clearing stack (RETURN ADDRESS + ARGUMENT)
#endif
	return true;
}

bool InterruptHook(const std::unique_ptr<Detours::Hook::InterruptHook>& pHook, const PCONTEXT pCTX) {
	_CRT_UNUSED(pHook);

	_tprintf_s(_T("[InterruptHook] Called `int 0x%02X`\n"), pHook->GetInterrupt());
#ifdef _M_X64
	_tprintf_s(_T("  -> RAX = 0x%016llX\n"), pCTX->Rax);
	_tprintf_s(_T("  -> RCX = 0x%016llX\n"), pCTX->Rcx);
	_tprintf_s(_T("  -> RDX = 0x%016llX\n"), pCTX->Rdx);
	_tprintf_s(_T("  -> RBX = 0x%016llX\n"), pCTX->Rbx);
	_tprintf_s(_T("  -> RBP = 0x%016llX\n"), pCTX->Rbp);
	_tprintf_s(_T("  -> RSI = 0x%016llX\n"), pCTX->Rsi);
	_tprintf_s(_T("  -> RDI = 0x%016llX\n"), pCTX->Rdi);
	_tprintf_s(_T("  ->  R8 = 0x%016llX\n"), pCTX->R8);
	_tprintf_s(_T("  ->  R9 = 0x%016llX\n"), pCTX->R9);
	_tprintf_s(_T("  -> R10 = 0x%016llX\n"), pCTX->R10);
	_tprintf_s(_T("  -> R11 = 0x%016llX\n"), pCTX->R11);
	_tprintf_s(_T("  -> R12 = 0x%016llX\n"), pCTX->R12);
	_tprintf_s(_T("  -> R13 = 0x%016llX\n"), pCTX->R13);
	_tprintf_s(_T("  -> R14 = 0x%016llX\n"), pCTX->R14);
	_tprintf_s(_T("  -> R15 = 0x%016llX\n"), pCTX->R15);
#elif _M_IX86
	_tprintf_s(_T("  -> EAX = 0x%08X\n"), pCTX->Eax);
	_tprintf_s(_T("  -> ECX = 0x%08X\n"), pCTX->Ecx);
	_tprintf_s(_T("  -> EDX = 0x%08X\n"), pCTX->Edx);
	_tprintf_s(_T("  -> EBX = 0x%08X\n"), pCTX->Ebx);
	_tprintf_s(_T("  -> EBP = 0x%08X\n"), pCTX->Ebp);
	_tprintf_s(_T("  -> ESI = 0x%08X\n"), pCTX->Esi);
	_tprintf_s(_T("  -> EDI = 0x%08X\n"), pCTX->Edi);
#endif

	return true;
}

typedef bool(__fastcall* fnFooOriginal)(void* pThis, void* /* unused */);
typedef bool(__fastcall* fnBooOriginal)(void* pThis, void* /* unused */);

Detours::Hook::VTableFunctionHook fooHook;
bool __fastcall foo_Hook(void* pThis, void* /* unused */) {
	using fnType = bool(__fastcall*)(void*, void*);
	_tprintf_s(_T("[foo_Hook] Called!\n"));
	return reinterpret_cast<fnType>(fooHook.GetOriginal())(pThis, nullptr);
}

Detours::Hook::VTableFunctionHook booHook;
bool __fastcall boo_Hook(void* pThis, void* /* unused */) {
	using fnType = bool(__fastcall*)(void*, void*);
	_tprintf_s(_T("[boo_Hook] Called!\n"));
	return reinterpret_cast<fnType>(booHook.GetOriginal())(pThis, nullptr);
}

Detours::Hook::VTableHook NewTestingRTTIVTable;

bool __fastcall foo_Hook2(void* pThis, void* /* unused */) {
	using fnType = bool(__fastcall*)(void*, void*);
	_tprintf_s(_T("[foo_Hook2] Called!\n"));
	return reinterpret_cast<fnType>(NewTestingRTTIVTable.GetHookingFunctions()[0]->GetOriginal())(pThis, nullptr);
}

bool __fastcall boo_Hook2(void* pThis, void* /* unused */) {
	using fnType = bool(__fastcall*)(void*, void*);
	_tprintf_s(_T("[boo_Hook2] Called!\n"));
	return reinterpret_cast<fnType>(NewTestingRTTIVTable.GetHookingFunctions()[1]->GetOriginal())(pThis, nullptr);
}

Detours::Hook::InlineHook InlineSleepHook;
void WINAPI Sleep_Hook(DWORD dwMilliseconds) {
	_tprintf_s(_T("[Sleep_Hook] Hook called!\n"));
	using fnType = void(WINAPI*)(DWORD);
	return reinterpret_cast<fnType>(InlineSleepHook.GetTrampoline())(dwMilliseconds);
}

Detours::Hook::RawHook RawSleepHook;
bool __cdecl Sleep_RawHook(Detours::Hook::PRAW_HOOK_CONTEXT pCTX) {
	_tprintf_s(_T("[Sleep_RawHook] Hook called!\n"));

	int cpuinfo[4];
	__cpuid(cpuinfo, 1);

	const bool bHaveFPU = (cpuinfo[3] & 1) != 0;
	const bool bHaveMMX = (cpuinfo[3] & (1 << 23)) != 0;
	const bool bHaveSSE = (cpuinfo[3] & (1 << 25)) != 0;
	const bool bHaveAVX = (cpuinfo[2] & (1 << 28)) != 0;

	__cpuidex(cpuinfo, 7, 0);

	const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

#ifdef _M_X64
	_tprintf_s(_T("  -> RFLAGS = 0x%08X\n"), pCTX->m_unEFLAGS);
#elif _M_IX86
	_tprintf_s(_T("  -> EFLAGS = 0x%08X\n"), pCTX->m_unEFLAGS);
#endif
	_tprintf_s(_T("     -> CF   = %hhu\n"), pCTX->m_unCF);
	_tprintf_s(_T("     -> PF   = %hhu\n"), pCTX->m_unPF);
	_tprintf_s(_T("     -> AF   = %hhu\n"), pCTX->m_unAF);
	_tprintf_s(_T("     -> ZF   = %hhu\n"), pCTX->m_unZF);
	_tprintf_s(_T("     -> SF   = %hhu\n"), pCTX->m_unSF);
	_tprintf_s(_T("     -> TF   = %hhu\n"), pCTX->m_unTF);
	_tprintf_s(_T("     -> IF   = %hhu\n"), pCTX->m_unIF);
	_tprintf_s(_T("     -> DF   = %hhu\n"), pCTX->m_unDF);
	_tprintf_s(_T("     -> OF   = %hhu\n"), pCTX->m_unOF);
	_tprintf_s(_T("     -> IOPL = %hhu\n"), pCTX->m_unIOPL);
	_tprintf_s(_T("     -> NT   = %hhu\n"), pCTX->m_unNT);
	_tprintf_s(_T("     -> MD   = %hhu\n"), pCTX->m_unMD);
	_tprintf_s(_T("     -> RF   = %hhu\n"), pCTX->m_unRF);
	_tprintf_s(_T("     -> VM   = %hhu\n"), pCTX->m_unVM);
	_tprintf_s(_T("     -> AC   = %hhu\n"), pCTX->m_unAC);
	_tprintf_s(_T("     -> VIF  = %hhu\n"), pCTX->m_unVIF);
	_tprintf_s(_T("     -> VIP  = %hhu\n"), pCTX->m_unVIP);
	_tprintf_s(_T("     -> ID   = %hhu\n"), pCTX->m_unID);
	_tprintf_s(_T("     -> AI   = %hhu\n"), pCTX->m_unAI);

	_tprintf_s(_T("  -> CS = 0x%04X\n"), pCTX->m_unCS);
	_tprintf_s(_T("  -> DS = 0x%04X\n"), pCTX->m_unDS);
	_tprintf_s(_T("  -> SS = 0x%04X\n"), pCTX->m_unSS);
	_tprintf_s(_T("  -> ES = 0x%04X\n"), pCTX->m_unES);
	_tprintf_s(_T("  -> FS = 0x%04X\n"), pCTX->m_unFS);
	_tprintf_s(_T("  -> GS = 0x%04X\n"), pCTX->m_unGS);

#ifdef _M_X64
	_tprintf_s(_T("  -> RAX = 0x%016llX\n"), pCTX->m_unRAX);
	_tprintf_s(_T("  -> RCX = 0x%016llX\n"), pCTX->m_unRCX);
	_tprintf_s(_T("  -> RDX = 0x%016llX\n"), pCTX->m_unRDX);
	_tprintf_s(_T("  -> RBX = 0x%016llX\n"), pCTX->m_unRBX);
	_tprintf_s(_T("  -> RSP = 0x%016llX\n"), pCTX->m_unRSP);
	_tprintf_s(_T("  -> RBP = 0x%016llX\n"), pCTX->m_unRBP);
	_tprintf_s(_T("  -> RSI = 0x%016llX\n"), pCTX->m_unRSI);
	_tprintf_s(_T("  -> RDI = 0x%016llX\n"), pCTX->m_unRDI);
	_tprintf_s(_T("  -> R8  = 0x%016llX\n"), pCTX->m_unR8);
	_tprintf_s(_T("  -> R9  = 0x%016llX\n"), pCTX->m_unR9);
	_tprintf_s(_T("  -> R10 = 0x%016llX\n"), pCTX->m_unR10);
	_tprintf_s(_T("  -> R11 = 0x%016llX\n"), pCTX->m_unR11);
	_tprintf_s(_T("  -> R12 = 0x%016llX\n"), pCTX->m_unR12);
	_tprintf_s(_T("  -> R13 = 0x%016llX\n"), pCTX->m_unR13);
	_tprintf_s(_T("  -> R14 = 0x%016llX\n"), pCTX->m_unR14);
	_tprintf_s(_T("  -> R15 = 0x%016llX\n"), pCTX->m_unR15);
#elif _M_IX86
	_tprintf_s(_T("  -> EAX = 0x%08X\n"), pCTX->m_unEAX);
	_tprintf_s(_T("  -> ECX = 0x%08X\n"), pCTX->m_unECX);
	_tprintf_s(_T("  -> EDX = 0x%08X\n"), pCTX->m_unEDX);
	_tprintf_s(_T("  -> EBX = 0x%08X\n"), pCTX->m_unEBX);
	_tprintf_s(_T("  -> ESP = 0x%08X\n"), pCTX->m_unESP);
	_tprintf_s(_T("  -> EBP = 0x%08X\n"), pCTX->m_unEBP);
	_tprintf_s(_T("  -> ESI = 0x%08X\n"), pCTX->m_unESI);
	_tprintf_s(_T("  -> EDI = 0x%08X\n"), pCTX->m_unEDI);
#endif

	if (bHaveFPU) {
		for (unsigned char j = 0; j < 8; ++j) {
			_tprintf_s(_T("  -> ST(%hhu) = 0x"), j);
			for (int i = 9; i >= 0; --i) {
				_tprintf_s(_T("%02X"), pCTX->m_FPU.m_Registers[j].m_pRAW[i]);
			}
			_tprintf_s(_T("\n"));
		}
	}

	if (bHaveMMX) {
		_tprintf_s(_T("  -> MM0 = 0x%016llX\n"), pCTX->m_MM0.m_un64);
		_tprintf_s(_T("  -> MM1 = 0x%016llX\n"), pCTX->m_MM1.m_un64);
		_tprintf_s(_T("  -> MM2 = 0x%016llX\n"), pCTX->m_MM2.m_un64);
		_tprintf_s(_T("  -> MM3 = 0x%016llX\n"), pCTX->m_MM3.m_un64);
		_tprintf_s(_T("  -> MM4 = 0x%016llX\n"), pCTX->m_MM4.m_un64);
		_tprintf_s(_T("  -> MM5 = 0x%016llX\n"), pCTX->m_MM5.m_un64);
		_tprintf_s(_T("  -> MM6 = 0x%016llX\n"), pCTX->m_MM6.m_un64);
		_tprintf_s(_T("  -> MM7 = 0x%016llX\n"), pCTX->m_MM7.m_un64);
	}

	if (bHaveAVX512) {
		_tprintf_s(_T("  -> ZMM0  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM0.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM1  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM1.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM2  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM2.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM3  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM3.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM3  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM3.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM4  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM4.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM5  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM5.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM6  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM6.m_un8[i]);
		}
		_tprintf_s(_T("\n"));


		_tprintf_s(_T("  -> ZMM7  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM7.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

#ifdef _M_X64
		_tprintf_s(_T("  -> ZMM8  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM8.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM9  = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM9.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM10 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM10.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM11 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM11.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM12 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM12.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM13 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM13.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM14 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM14.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM15 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM15.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM16 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM16.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM17 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM17.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM18 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM18.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM19 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM19.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM20 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM20.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM21 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM21.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM22 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM22.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM23 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM23.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM24 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM24.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM25 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM25.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM26 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM26.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM27 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM27.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM28 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM28.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM29 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM29.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM30 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM30.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> ZMM31 = 0x"));
		for (int i = 63; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_ZMM31.m_un8[i]);
		}
		_tprintf_s(_T("\n"));
#endif
	} else if (bHaveAVX) {
		_tprintf_s(_T("  -> YMM0  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM0.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM1  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM1.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM2  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM2.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM3  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM3.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM4  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM4.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM5  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM5.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM6  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM6.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM7  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM7.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

#ifdef _M_X64
		_tprintf_s(_T("  -> YMM8  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM8.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM9  = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM9.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM10 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM10.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM11 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM11.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM12 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM12.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM13 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM13.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM14 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM14.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> YMM15 = 0x"));
		for (int i = 31; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_YMM15.m_un8[i]);
		}
		_tprintf_s(_T("\n"));
#endif
	} else if (bHaveSSE) {
		_tprintf_s(_T("  -> XMM0  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM0.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM1  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM1.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM2  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM2.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM3  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM3.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM3  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM3.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM4  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM4.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM5  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM5.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM6  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM6.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM7  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM7.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

#ifdef _M_X64
		_tprintf_s(_T("  -> XMM8  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM8.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM9  = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM9.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM10 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM10.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM11 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM11.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM12 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM12.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM13 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM13.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM14 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM14.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("  -> XMM15 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), pCTX->m_XMM15.m_un8[i]);
		}
		_tprintf_s(_T("\n"));
#endif
	}

#ifdef _M_X64
	pCTX->m_unRDX = 0;
	*reinterpret_cast<unsigned int*>(pCTX->m_unRSP + 0x8) = pCTX->m_unEBX;
	*reinterpret_cast<unsigned int*>(pCTX->m_unRSP + 0x10) = 0;
	pCTX->m_unRBX = *reinterpret_cast<unsigned long long*>(pCTX->m_unRSP + 0x10);
#elif _M_IX86
	unsigned int unIP = *reinterpret_cast<unsigned int*>(pCTX->m_unESP);
	pCTX->m_unESP += 4;
	*reinterpret_cast<unsigned int*>(pCTX->m_unESP) = unIP;
#endif

	return true;
}

int _tmain(int nArguments, PTCHAR* pArguments) {
	g_pTestingRTTI = new TestingRTTI();

	// ----------------------------------------------------------------
	// Memory Server & Client Example
	// ----------------------------------------------------------------

	if (nArguments > 1) {
		for (int i = 0; i < nArguments; ++i) {
			PTCHAR pArgument = pArguments[i];
			if (_tcscmp(pArgument, _T("/sv")) == 0) {
				Detours::Memory::Server sv(GetLargePageMinimum());
				PSHARED_MEMORY pMemory = reinterpret_cast<PSHARED_MEMORY>(sv.GetAddress());
				if (!pMemory) {
					return -1;
				}

#ifdef _M_X64
				_tprintf_s(_T("Memory: 0x%016llX\n"), reinterpret_cast<size_t>(pMemory));
#elif _M_IX86
				_tprintf_s(_T("Memory: 0x%08X\n"), reinterpret_cast<size_t>(pMemory));
#endif

				TCHAR szSessionName[64];
				if (!sv.GetSessionName(szSessionName)) {
					return -1;
				}

				_tprintf_s(_T("Server Session: %s\n"), szSessionName);

				while (!pMemory->m_bStop) {
					pMemory->m_unTick = GetTickCount64() & 0xFFFFFFFFi32;
					Sleep(1);
				}

				_tprintf_s(_T("Stopped\n"));

				return 0;
			}

			if ((nArguments > 2) && (_tcscmp(pArgument, _T("/cl")) == 0)) {
				PTCHAR pSessionName = pArguments[i + 1];
				if (_tcslen(pSessionName) != 41) {
					return -1;
				}

				_tprintf_s(_T("Connecting to `%s`\n"), pSessionName);

				Detours::Memory::Client cl(pSessionName);
				PSHARED_MEMORY pMemory = reinterpret_cast<PSHARED_MEMORY>(cl.GetAddress());
				if (!pMemory) {
					return -1;
				}

#ifdef _M_X64
				_tprintf_s(_T("Memory: 0x%016llX\n"), reinterpret_cast<size_t>(pMemory));
#elif _M_IX86
				_tprintf_s(_T("Memory: 0x%08X\n"), reinterpret_cast<size_t>(pMemory));
#endif

				DWORD unTick = pMemory->m_unTick + 5000;
				while (pMemory->m_unTick < unTick) {
					_tprintf_s(_T("Tick: %lu\n"), pMemory->m_unTick);
					Sleep(5);
				}

				pMemory->m_bStop = true;
				_tprintf_s(_T("Stopped\n"));

				return 0;
			}
		}
	}

	// ----------------------------------------------------------------
	// Kernel-User Shared Data Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Kernel-User Shared Data Example\n\n"));

	_tprintf_s(_T("SystemCall = 0x%08X\n"), Detours::KUserSharedData.SystemCall);
	_tprintf_s(_T("Cookie = 0x%08X\n"), Detours::KUserSharedData.Cookie);

	const ULONG unLowPartTime = Detours::KUserSharedData.SystemTime.LowPart;
	_tprintf_s(_T("SystemTime = %lu\n"), unLowPartTime);

	_tprintf_s(_T("Sleeping 1200 ms...\n")); Sleep(1200);

	_tprintf_s(_T("ElapsedTime = %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unLowPartTime) / 10000);
	_tprintf_s(_T("DbgSecureBootEnabled = %lu\n"), Detours::KUserSharedData.DbgSecureBootEnabled); // Secure Boot
	_tprintf_s(_T("ActiveProcessorCount = %lu\n"), Detours::KUserSharedData.ActiveProcessorCount); // CPU threads

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// PEB & TEB Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("PEB & TEB Example\n\n"));

	auto pPEB = Detours::GetPEB();
	if (!pPEB) {
		return -1;
	}

	auto pTEB = Detours::GetTEB();
	if (!pTEB) {
		return -1;
	}

	_tprintf_s(_T("Microsoft Windows [Version %lu.%lu.%05lu.%lu]\n"), pPEB->OSMajorVersion, pPEB->OSMinorVersion, pPEB->OSBuildNumber, GetUBR());

	auto pProcessParameters = pPEB->ProcessParameters;
	if (pProcessParameters) {
		if (pProcessParameters->CommandLine.Length) {
#ifdef UNICODE
			_tprintf_s(_T("CommandLine = `%s`\n"), pPEB->ProcessParameters->CommandLine.Buffer);
#else
			_tprintf_s(_T("CommandLine = `%ws`\n"), pPEB->ProcessParameters->CommandLine.Buffer);
#endif
		}
	}

#ifdef _M_X64
	_tprintf_s(_T("Process ID = %llu\n"), pTEB->ClientId.UniqueProcess);
	_tprintf_s(_T("Thread  ID = %llu\n"), pTEB->ClientId.UniqueThread);
	_tprintf_s(_T("Real Process ID = %llu\n"), pTEB->RealClientId.UniqueProcess);
	_tprintf_s(_T("Real Thread  ID = %llu\n"), pTEB->RealClientId.UniqueThread);
#elif _M_IX86
	_tprintf_s(_T("Process ID = %lu\n"), pTEB->ClientId.UniqueProcess);
	_tprintf_s(_T("Thread  ID = %lu\n"), pTEB->ClientId.UniqueThread);
	_tprintf_s(_T("Real Process ID = %lu\n"), pTEB->RealClientId.UniqueProcess);
	_tprintf_s(_T("Real Thread  ID = %lu\n"), pTEB->RealClientId.UniqueThread);
#endif

	SetLastError(0x11223344);

	_tprintf_s(_T("LastError = 0x%08X\n"), pTEB->LastErrorValue);
	_tprintf_s(_T("LastStatus = 0x%08X\n"), pTEB->LastStatusValue);

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Codec Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Codec Example\n\n"));

	int nEncodeSize = Detours::Codec::Encode(CP_UTF8, "Hello, World!");
	if (nEncodeSize > 0) {
		HANDLE hHeap = GetProcessHeap();
		if (!hHeap || (hHeap == INVALID_HANDLE_VALUE)) {
			return -1;
		}

		wchar_t* pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t)));
		if (!pBuffer) {
			return -1;
		}

		memset(pBuffer, 0, static_cast<size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t));

		if (Detours::Codec::Encode(CP_UTF8, "Hello, World!", pBuffer, nEncodeSize) <= 0) {
			return -1;
		}

#ifdef UNICODE
		_tprintf_s(_T("Encode: `%s`\n"), pBuffer);
#else
		_tprintf_s(_T("Encode: `%ws`\n"), pBuffer);
#endif

		HeapFree(hHeap, NULL, pBuffer);
	}

	int nDecodeSize = Detours::Codec::Decode(CP_UTF8, L"Hello, World!");
	if (nDecodeSize > 0) {
		HANDLE hHeap = GetProcessHeap();
		if (!hHeap || (hHeap == INVALID_HANDLE_VALUE)) {
			return -1;
		}

		char* pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<size_t>(nDecodeSize) * sizeof(char) + sizeof(char)));
		if (!pBuffer) {
			return -1;
		}

		memset(pBuffer, 0, static_cast<size_t>(nDecodeSize) * sizeof(char) + sizeof(char));

		if (Detours::Codec::Decode(CP_UTF8, L"Hello, World!", pBuffer, nDecodeSize) <= 0) {
			return -1;
		}

		_tprintf_s(_T("Decode: `%hs`\n"), pBuffer);

		HeapFree(hHeap, NULL, pBuffer);
	}

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Hexadecimal Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Hexadecimal Example\n\n"));

	TCHAR szHex[32];
	memset(szHex, 0, sizeof(szHex));
	if (Detours::Hexadecimal::Encode(reinterpret_cast<const void* const>("Hello, World!"), 14, szHex, 0x00)) {
		_tprintf_s(_T("Encode: `%s`\n"), szHex);
	}

	char szData[16];
	memset(szData, 0, sizeof(szData));
	if (Detours::Hexadecimal::Decode(szHex, reinterpret_cast<void*>(szData), 0x00)) {
#ifdef UNICODE
		_tprintf_s(_T("Decode: `%hs`\n"), szData);
#else
		_tprintf_s(_T("Decode: `%s`\n"), szData);
#endif
	}

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Scan Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Scan Example\n\n"));

	void* pSectionNTDLL = nullptr;
	size_t unSectionNTDLLSize = 0;
	if (Detours::Scan::FindSection(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSectionNTDLL, &unSectionNTDLLSize)) {
#ifdef _M_X64
		_tprintf_s(_T("FindSection(...) = 0x%08llX\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#elif _M_IX86
		_tprintf_s(_T("FindSection(...) = 0x%08X\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#endif
	}
	
	pSectionNTDLL = nullptr;
	unSectionNTDLLSize = 0;
	if (Detours::Scan::FindSectionPOGO(_T("ntdll.dll"), ".rdata", &pSectionNTDLL, &unSectionNTDLLSize)) {
#ifdef _M_X64
		_tprintf_s(_T("FindSection(...) = 0x%08llX\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#elif _M_IX86
		_tprintf_s(_T("FindSection(...) = 0x%08X\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#endif
	}

#ifdef _M_X64
	_tprintf_s(_T("FindSignature(...) = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x48\x8B\x41\x10\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75")));
#elif _M_IX86
	_tprintf_s(_T("FindSignature(...) = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x8B\xD1\x8B\x42\x08")));
#endif

#ifdef _M_X64
	_tprintf_s(_T("FindData(...) = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x48\x8B\x41\x10\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75"), 13)));
#elif _M_IX86
	_tprintf_s(_T("FindData(...) = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x8B\xD1\x8B\x42\x08"), 5)));
#endif

	void** pVTable = reinterpret_cast<void**>(const_cast<void*>(Detours::Scan::FindRTTI(_T("Detours.exe"), ".?AVTestingRTTI@@")));

#ifdef _M_X64
#ifdef UNICODE
	_tprintf_s(_T("> FindRTTI(...) '%hs' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
	_tprintf_s(_T("> FindRTTI(...) '%s' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
#elif _M_IX86
#ifdef UNICODE
	_tprintf_s(_T("> FindRTTI(...) '%hs' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
	_tprintf_s(_T("> FindRTTI(...) '%s' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
#endif

	if (pVTable) {
		// __thiscall - 1st arg (this) = ecx
		// __fastcall - 1st arg = ecx, 2nd arg = edx
		using fnFoo = bool(__fastcall*)(void* pThis, void* /* unused */);
		using fnBoo = bool(__fastcall*)(void* pThis, void* /* unused */);

		_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr));
	}

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Memory Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Memory Example\n\n"));

	Detours::Memory::Storage Storage;
	unsigned char* pCodeMemory = reinterpret_cast<unsigned char*>(Storage.Alloc(3));
	if (pCodeMemory) {
		_tprintf_s(_T("Storage.GetCapacity() = %d\n"), static_cast<int>(Storage.GetCapacity()));
		_tprintf_s(_T("Storage.GetSize() = %d\n"), static_cast<int>(Storage.GetSize()));

		// mov al, 0x01
		// retn

		pCodeMemory[0] = 0xB0;
		pCodeMemory[1] = 0x01;
		pCodeMemory[2] = 0xC3;

		Detours::Memory::Protection(pCodeMemory, 3, false).ChangeProtection(PAGE_EXECUTE_READ);

		using fnType = bool(__cdecl*)();
		_tprintf_s(_T("pCodeMemory() = %d\n"), reinterpret_cast<fnType>(pCodeMemory)());

		Storage.DeAlloc(pCodeMemory);
	}

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Exception Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Exception Example\n\n"));
	_tprintf_s(_T("g_ExceptionListener.AddCallBack(...) = %d\n"), Detours::Exception::g_ExceptionListener.AddCallBack(OnException));
#ifdef _M_X64
	CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#elif _M_IX86
	CallInterrupt(1, 2, 3, 4, 5, 6, 7);
#endif
	_tprintf_s(_T("g_ExceptionListener.RemoveCallBack(...) = %d\n"), Detours::Exception::g_ExceptionListener.RemoveCallBack(OnException));
	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Hook Example
	// ----------------------------------------------------------------

	_tprintf_s(_T("Hook Example\n\n"));

	// MemoryHook

	_tprintf_s(_T("HookMemory = %d\n"), Detours::Hook::HookMemory(reinterpret_cast<void*>(Sleep), Sleep_MemoryHook));
	Sleep(1000);
	_tprintf_s(_T("UnHookMemory = %d\n"), Detours::Hook::UnHookMemory(Sleep_MemoryHook));
	_tprintf_s(_T("\n"));

	// InterruptHook

	_tprintf_s(_T("HookInterrupt = %d\n"), Detours::Hook::HookInterrupt(InterruptHook, 0x7E));
#ifdef _M_X64
	CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#elif _M_IX86
	CallInterrupt(1, 2, 3, 4, 5, 6, 7);
#endif
	_tprintf_s(_T("UnHookInterrupt = %d\n"), Detours::Hook::UnHookInterrupt(InterruptHook));
	_tprintf_s(_T("\n"));

	// VTableFunctionHook & VTableHook

	void** pHookingVTable = reinterpret_cast<void**>(const_cast<void*>(Detours::Scan::FindRTTI(_T("Detours.exe"), ".?AVTestingRTTI@@")));

#ifdef _M_X64
#ifdef UNICODE
	_tprintf_s(_T("> '%hs' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#else
	_tprintf_s(_T("> '%s' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#endif
#elif _M_IX86
#ifdef UNICODE
	_tprintf_s(_T("> '%hs' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#else
	_tprintf_s(_T("> '%s' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#endif
#endif

	if (pHookingVTable) {
		// __thiscall - 1st arg (this) = ecx
		// __fastcall - 1st arg = ecx, 2nd arg = edx
		using fnFoo = bool(__fastcall*)(void* pThis, void* /* unused */);
		using fnBoo = bool(__fastcall*)(void* pThis, void* /* unused */);

		_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));

		_tprintf_s(_T("fooHook.Set(...) = %d\n"), fooHook.Set(pHookingVTable, 0));
		_tprintf_s(_T("fooHook.Hook(...) = %d\n"), fooHook.Hook(reinterpret_cast<void*>(foo_Hook)));
		_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("fooHook.UnHook() = %d\n"), fooHook.UnHook());

		_tprintf_s(_T("booHook.Set(...) = %d\n"), booHook.Set(pHookingVTable, 1));
		_tprintf_s(_T("booHook.Hook(...) = %d\n"), booHook.Hook(reinterpret_cast<void*>(boo_Hook)));
		_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("booHook.UnHook() = %d\n"), booHook.UnHook());

		void* pNewVTable[2] = {
			reinterpret_cast<void*>(foo_Hook2),
			reinterpret_cast<void*>(boo_Hook2)
		};

		_tprintf_s(_T("NewTestingRTTIVTable.Set(...) = %d\n"), NewTestingRTTIVTable.Set(pHookingVTable, 2));
		_tprintf_s(_T("NewTestingRTTIVTable.Hook(...) = %d\n"), NewTestingRTTIVTable.Hook(pNewVTable));
		_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("NewTestingRTTIVTable.UnHook() = %d\n"), NewTestingRTTIVTable.UnHook());
	}

	_tprintf_s(_T("\n"));

	// InlineHook

	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 && (hKernel32 != INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("InlineSleepHook.Set = %d\n"), InlineSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))));
		_tprintf_s(_T("InlineSleepHook.Hook = %d\n"), InlineSleepHook.Hook(reinterpret_cast<void*>(Sleep_Hook)));
		Sleep(1000);
		_tprintf_s(_T("InlineSleepHook.UnHook = %d\n"), InlineSleepHook.UnHook());
	}

	_tprintf_s(_T("\n"));

	// RawHook

	if (hKernel32 && (hKernel32 != INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("RawSleepHook.Set = %d\n"), RawSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))));
		_tprintf_s(_T("RawSleepHook.Hook = %d\n"), RawSleepHook.Hook(Sleep_RawHook));
		Sleep(1000);
		_tprintf_s(_T("RawSleepHook.UnHook = %d\n"), RawSleepHook.UnHook());
	}

	_tprintf_s(_T("\n"));

	_tprintf_s(_T("[ FINISHED ]\n"));
	return 0;
}

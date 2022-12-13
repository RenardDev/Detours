
// Default
#include <Windows.h>
#include <tchar.h>

// Advanced
#include <intrin.h>

// C++
#include <cstdio>
#include <typeinfo>

// Detours
#include "Detours.h"

// interrupts.asm
extern "C" void _int7D();
extern "C" void _int7E();

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

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

DATA_SECTION_BEGIN(r1, ".dat");
__declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;
DATA_SECTION_END(r1);

bool __fastcall Sleep_MemoryHook(std::unique_ptr<Detours::Hook::MemoryHook>& pHook, const PCONTEXT pCTX) {
	_tprintf_s(_T("[Hook] Called!\n"));
#ifdef _M_X64
	pCTX->Rip = *reinterpret_cast<PDWORD64>(pCTX->Rsp); // [SP] = RETURN ADDRESS
	pCTX->Rsp += 8; // Clearing stack (RETURN ADDRESS)
#elif _M_IX86
	pCTX->Eip = *reinterpret_cast<PDWORD>(pCTX->Esp); // [SP] = RETURN ADDRESS
	pCTX->Esp += 8; // Clearing stack (RETURN ADDRESS + ARGUMENT)
#endif
	return true;
}

bool __fastcall OnException(const EXCEPTION_RECORD& Exception, const PCONTEXT pCTX) {
	if (Exception.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
		return false;
	}

	const unsigned char* const pAddress = reinterpret_cast<const unsigned char* const>(Exception.ExceptionAddress);
	if (!pAddress) {
		return false;
	}

	if (pAddress[0] == 0xCD) {
		_tprintf_s(_T("[OnException] Called `int 0x%02X`\n"), pAddress[1]);
	}

#ifdef _WIN64
	pCTX->Rip += 2;
#elif _WIN32
	pCTX->Eip += 2;
#else
#error Unknown platform
#endif

	return true;
}

int _tmain(int nArguments, PTCHAR* pArguments) {
	g_pTestingRTTI = new TestingRTTI();
	if (!g_pTestingRTTI) {
		return -1;
	}

	// ----------------------------------------------------------------
	// FindSignature
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindSignature Example\n"));

#ifdef _M_X64
	_tprintf_s(_T("48 8B 41 10 33 D2 4C 8B C1 48 85 C0 75 [.text] = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x48\x8B\x41\x10\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75")));
#elif _M_IX86
	_tprintf_s(_T("8B D1 8B 42 08 [.text] = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x8B\xD1\x8B\x42\x08")));
#endif

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// FindData
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindData Example\n"));	

#ifdef _M_X64
	_tprintf_s(_T("48 8B 41 10 33 D2 4C 8B C1 48 85 C0 75 = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x48\x8B\x41\x10\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75"), 13)));
#elif _M_IX86
	_tprintf_s(_T("8B D1 8B 42 08 = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x8B\xD1\x8B\x42\x08"), 5)));
#endif

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// FindRTTI
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindRTTI Example\n"));

	void** pVTable = reinterpret_cast<void**>(const_cast<void*>(Detours::Scan::FindRTTI(_T("Detours.exe"), ".?AVTestingRTTI@@")));
#ifdef _M_X64
#ifdef UNICODE
	_tprintf_s(_T("> '%hs' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
	_tprintf_s(_T("> '%s' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
#elif _M_IX86
#ifdef UNICODE
	_tprintf_s(_T("> '%hs' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
	_tprintf_s(_T("> '%s' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif

#endif
	if (pVTable) {
		// __fastcall - 1st arg = ecx, 2nd arg = edx
		using fnFoo = bool(__fastcall*)(void* pThis, void* /* unused */);
		using fnBoo = bool(__fastcall*)(void* pThis, void* /* unused */);

		_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr));
	}

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Hook with memory rights
	// ----------------------------------------------------------------

	_tprintf_s(_T("Hook Memory Example\n"));

	_tprintf_s(_T("HookMemory = %d\n"), Detours::Hook::HookMemory(Sleep, Sleep_MemoryHook));

	Sleep(1000);

	_tprintf_s(_T("UnHookMemory = %d\n"), Detours::Hook::UnHookMemory(Sleep_MemoryHook));

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Global exception handler
	// ----------------------------------------------------------------

	_tprintf_s(_T("Global Exception Example\n"));

	_tprintf_s(_T("AddCallBack = %d\n"), Detours::Exception::g_ExceptionListener.AddCallBack(OnException));

	_int7D();
	_int7E();

	_tprintf_s(_T("RemoveCallBack = %d\n"), Detours::Exception::g_ExceptionListener.RemoveCallBack(OnException));

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Kernel-User Shared Data
	// ----------------------------------------------------------------

	_tprintf_s(_T("Kernel-User Shared Data Example\n"));

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
	// PEB & TEB
	// ----------------------------------------------------------------

	_tprintf_s(_T("PEB & TEB Example\n"));

	auto pPEB = Detours::GetPEB();
	if (!pPEB) {
		return -1;
	}

	auto pTEB = Detours::GetTEB();
	if (!pTEB) {
		return -1;
	}

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

	_tprintf_s(_T("\n"));

	delete g_pTestingRTTI;
	_tprintf_s(_T("[ OK ]\n"));
	return 0;
}

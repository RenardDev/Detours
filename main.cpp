
// Default
#include <Windows.h>
#include <tchar.h>

// C++
#include <cstdio>
#include <typeinfo>

// Detours
#include "Detours.h"

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

__declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;

typedef void(WINAPI* fnSleep)(DWORD dwMilliseconds);
void WINAPI Sleep_Hook(DWORD dwMilliseconds) {
	_tprintf_s(_T("[Hook] Called!\n"));

	Detours::Hook::EnableHookMemory(Sleep_Hook); // This is only needed for memory hook.
}

int _tmain() {
	g_pTestingRTTI = new TestingRTTI();
	if (!g_pTestingRTTI) {
		return -1;
	}

	// ----------------------------------------------------------------
	// FindSignature
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindSignature Example\n"));
#ifdef _M_X64
	printf("Sleep = 0x%08llX\n", reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("kernelbase.dll"), "\x33\xD2\xE9\x2A\x2A\x2A\x2A\xCC\x71\x28")));
#elif _M_IX86
	printf("Sleep = 0x%08X\n", reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("kernelbase.dll"), "\x8B\xFF\x55\x8B\xEC\x6A\x2A\xFF\x75\x08\xE8\x2A\x2A\x2A\x2A\x5D\xC2")));
#endif
	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// FindData
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindData Example\n"));
#ifdef _M_X64
	printf("Sleep = 0x%08llX\n", reinterpret_cast<size_t>(Detours::Scan::FindData(_T("kernelbase.dll"), reinterpret_cast<const unsigned char* const>("\x55\x90"), 2)));
#elif _M_IX86
	printf("Sleep = 0x%08X\n", reinterpret_cast<size_t>(Detours::Scan::FindData(_T("kernelbase.dll"), reinterpret_cast < const unsigned char* const>("\x55\x90"), 2)));
#endif
	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// FindRTTI
	// ----------------------------------------------------------------

	_tprintf_s(_T("FindRTTI Example\n"));
	void** pVTable = reinterpret_cast<void**>(const_cast<void*>(Detours::Scan::FindRTTI(_T("Detours.exe"), ".?AVTestingRTTI@@")));
#ifdef _M_X64
	printf("'%s' = 0x%08llX\n", typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#elif _M_IX86
	printf("'%s' = 0x%08X\n", typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
	if (pVTable) {

		typedef bool(__fastcall* fnFoo)(void* pThis, void* /* unused */);
		typedef bool(__fastcall* fnBoo)(void* pThis, void* /* unused */);

		_tprintf_s(_T("foo() = %d\n"), reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr));
		_tprintf_s(_T("boo() = %d\n"), reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr));
	}
	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Hook Import/Export
	// ----------------------------------------------------------------

	_tprintf_s(_T("Hook Import/Export Example\n"));

	HMODULE hKernel = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel) {
		return -1;
	}

	_tprintf_s(_T("HookImport = %d\n"), Detours::Hook::HookImport(hKernel, "Sleep", Sleep_Hook));

	Sleep(1000);

	_tprintf_s(_T("UnHookImport = %d\n"), Detours::Hook::UnHookImport(Sleep_Hook));

	_tprintf_s(_T("HookExport = %d\n"), Detours::Hook::HookExport(hKernel, "Sleep", Sleep_Hook));

	fnSleep fSleep = reinterpret_cast<fnSleep>(GetProcAddress(hKernel, "Sleep"));
	fSleep(1000);

	_tprintf_s(_T("UnHookExport = %d\n"), Detours::Hook::UnHookExport(Sleep_Hook));

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// Hook with memory rights
	// ----------------------------------------------------------------

	_tprintf_s(_T("Hook Memory Example\n"));

	_tprintf_s(_T("HookMemory = %d\n"), Detours::Hook::HookMemory(Sleep, Sleep_Hook, true));

	Sleep(1000);

	_tprintf_s(_T("UnHookMemory = %d\n"), Detours::Hook::UnHookMemory(Sleep_Hook));

	_tprintf_s(_T("\n"));

	delete g_pTestingRTTI;
	_tprintf_s(_T("[ OK ]\n"));
	return 0;
}


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

class BaseMessage {
public:
	virtual ~BaseMessage() {}
	virtual void Message() const {
		_tprintf_s(_T("Hello, World!\n"));
	}
};

class MessageOne : public BaseMessage {
public:
	void Message() const override {
		_tprintf_s(_T("> Hello, World!\n"));
	}

	void PrintName() const {
#ifdef _UNICODE
		_tprintf_s(_T("> '%hs'\n"), typeid(MessageOne).raw_name());
#else
		_tprintf_s(_T("> '%s'\n"), typeid(MessageOne).raw_name());
#endif
	}
};

class MessageTwo : public BaseMessage {
public:
	void Message() const override {
		_tprintf_s(_T("> Hello, World!\n"));
	}

	void PrintName() const {
#ifdef _UNICODE
		_tprintf_s(_T("> '%hs'\n"), typeid(MessageTwo).raw_name());
#else
		_tprintf_s(_T("> '%s'\n"), typeid(MessageTwo).raw_name());
#endif
	}
};

class BaseTestingRTTI {
public:
	virtual bool foo() { return false; }
	virtual bool boo() { return true; }
};

class TestingRTTI : public BaseTestingRTTI {
public:
	TestingRTTI() {
		m_bFoo = true;
		m_bBoo = false;
	}

	bool foo() override { return m_bFoo; }
	bool boo() override { return m_bBoo; }

private:
	bool m_bFoo;
	bool m_bBoo;
};

DECLARE_SECTION(".cdata")
DEFINE_SECTION(".cdata", SECTION_READWRITE)

DEFINE_IN_SECTION(".cdata") __declspec(dllexport) BaseTestingRTTI* g_pBaseTestingRTTI = nullptr;
DEFINE_IN_SECTION(".cdata") __declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;

void TestFindSignature() {
	unsigned char pAlignEmptyArray[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignBeginArray[]  = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray1[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray1[]  = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray2[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray2[]  = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureNative(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureSSE2(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));
	
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindSignatureAVX2(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));
}

void TestFindData() {
	unsigned char pAlignEmptyArray[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignBeginArray[]  = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray1[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray1[]  = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray2[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray2[]  = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60 ? _T("OK") : _T("FAIL"));

	unsigned char pEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataNative(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataSSE2(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));

	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37 ? _T("OK") : _T("FAIL"));
	_tprintf_s(_T("TEST - %s\n"), Detours::Scan::FindDataAVX2(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61 ? _T("OK") : _T("FAIL"));
}

int TestMode() {

	_tprintf_s(_T("FindSignature Test\n"));
	TestFindSignature();

	_tprintf_s(_T("FindData Test\n"));
	TestFindData();

	return 0;
}

int BenchmarkMode() {
	auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
	if (!pRandomData) {
		return -1;
	}

	memset(pRandomData.get(), 0, 0x800000);

	pRandomData[0x800000 - 4] = 0xDE;
	pRandomData[0x800000 - 3] = 0xED;
	pRandomData[0x800000 - 2] = 0xBE;
	pRandomData[0x800000 - 1] = 0xEF;

	_tprintf_s(_T("FindSignature Benchmark\n"));

	ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindSignatureNative(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindSignatureNative - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindSignatureSSE2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindSignatureSSE2 - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindSignatureAVX2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindSignatureAVX2 - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	_tprintf_s(_T("FindData Benchmark\n"));

	unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindDataNative(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindDataNative - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindDataSSE2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindDataSSE2 - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	unBegin = Detours::KUserSharedData.SystemTime.LowPart;
	for (unsigned int i = 0; i < 1'000; ++i) {
		if (!Detours::Scan::FindDataAVX2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
			_tprintf_s(_T("NOT FOUND\n"));
			break;
		}
	}
	_tprintf_s(_T("FindDataAVX2 - Elapsed Time: %lu ms\n"), (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000);

	return 0;
}

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

void DumpObject(void* pAddress, Detours::RTTI::Object* pObject, unsigned int unLevel = 0) {
	if (!pAddress || !pObject) {
		return;
	}

	if (!unLevel) {
		_tprintf_s(_T("Dumping object:\n"));
	}

	for (unsigned int i = 0; i < unLevel; ++i) {
		_tprintf_s(_T(" "));
	}

#ifdef _M_X64
#ifdef _UNICODE
	_tprintf_s(_T("> '%hs' = 0x%016llX\n"), pObject->GetTypeDescriptor()->m_szName, reinterpret_cast<size_t>(pObject->GetVTable()));
#else
	_tprintf_s(_T("> '%s' = 0x%016llX\n"), pObject->GetTypeDescriptor()->m_szName, reinterpret_cast<size_t>(pObject->GetVTable()));
#endif
#elif _M_IX86
#ifdef _UNICODE
	_tprintf_s(_T("> '%hs' = 0x%08X\n"), pObject->GetTypeDescriptor()->m_szName, reinterpret_cast<size_t>(pObject->GetVTable()));
#else
	_tprintf_s(_T("> '%s' = 0x%08X\n"), pObject->GetTypeDescriptor()->m_szName, reinterpret_cast<size_t>(pObject->GetVTable()));
#endif
#endif

	for (auto& BaseObject : pObject->GetBaseObjects()) {
		DumpObject(pAddress, BaseObject.get(), unLevel + 1);
	}

	if (!unLevel) {
		_tprintf_s(_T("\n"));
	}
}

void ProcessMessage(BaseMessage* pMessage) {
	MessageOne* Msg1 = dynamic_cast<MessageOne*>(pMessage);
	MessageTwo* Msg2 = dynamic_cast<MessageTwo*>(pMessage);

	if (Msg1) {
		Msg1->Message();
		Msg1->PrintName();
	} else if (Msg2) {
		Msg2->Message();
		Msg2->PrintName();
	}
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
#ifdef _M_X64
bool __fastcall Sleep_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
bool __cdecl Sleep_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
#if defined(_DEBUG) || !defined(_M_X64) // NOTE: Using a stack inside a RawHook callback will produce unpredictable results.
	_tprintf_s(_T("[Sleep_RawHook] Hook called!\n"));

	int cpuinfo[4];
	__cpuid(cpuinfo, 1);

	const bool bHaveFPU = (cpuinfo[3] & 1) != 0;
	const bool bHaveSSE = (cpuinfo[3] & (1 << 25)) != 0;
	const bool bHaveAVX = (cpuinfo[2] & (1 << 28)) != 0;

	__cpuidex(cpuinfo, 7, 0);

	const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

#ifdef _M_X64
	_tprintf_s(_T("  -> RFLAGS = 0x%016llX\n"), pCTX->m_unRFLAGS);
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

	if (bHaveAVX512) {
		_tprintf_s(_T("  -> MXCSR  = 0x%08X\n"), pCTX->m_unMXCSR);
		
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
		_tprintf_s(_T("  -> MXCSR  = 0x%08X\n"), pCTX->m_unMXCSR);

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
		_tprintf_s(_T("  -> MXCSR  = 0x%08X\n"), pCTX->m_unMXCSR);

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
#endif // _DEBUG || !_M_X64

#ifdef _M_X64
	pCTX->Stack.push(RawSleepHook.GetTrampoline());
#elif _M_IX86
	void* pReturnAddress = pCTX->Stack.pop();
	pCTX->Stack.pop();
	pCTX->Stack.push(pReturnAddress);
#endif

	return true;
}

Detours::Hook::RAW_CONTEXT_M128 g_LastXMM7;

#ifdef _M_X64
bool __fastcall Sleep_RawHookMod(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
bool __cdecl Sleep_RawHookMod(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
	g_LastXMM7 = pCTX->m_XMM7;
	pCTX->m_XMM7.m_un64[0] = 0x1122334455667788;
	pCTX->m_XMM7.m_un64[1] = 0x1122334455667788;

#ifdef _M_X64
	pCTX->Stack.push(RawSleepHook.GetTrampoline());
#elif _M_IX86
	void* pReturnAddress = pCTX->Stack.pop();
	pCTX->Stack.pop();
	pCTX->Stack.push(pReturnAddress);
#endif

	return true;
}

Detours::Hook::RawHook RawCPUIDHook;

#ifdef _M_X64
bool __fastcall CPUID_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
bool __cdecl CPUID_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif

	pCTX->m_unEBX = 0x11223344;
	pCTX->Stack.push(reinterpret_cast<char*>(RawCPUIDHook.GetTrampoline()) + RawCPUIDHook.GetFirstInstructionSize());

	return true;
}

void DemoRawHook() { SELF_EXPORT("DemoHook");
	_tprintf_s(_T("rddisasm + RawHook Example\n"));

	Detours::rddisasm::INSTRUCTION ins;
	size_t unOffset = 0;
	void* pFoundCPUID = nullptr;
	while (unOffset < 0x1000) {
#ifdef _M_X64
		if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(DemoRawHook) + unOffset, RD_DATA_64, RD_DATA_64))) {
#elif _M_IX86
		if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(DemoRawHook) + unOffset, RD_DATA_32, RD_DATA_32))) {
#endif
			return;
		}

		if (ins.Instruction == Detours::rddisasm::RD_INS_CLASS::RD_INS_CPUID) {
			_tprintf_s(_T("Found `cpuid` instruction!\n"));
			pFoundCPUID = reinterpret_cast<void*>(reinterpret_cast<char*>(DemoRawHook) + unOffset);
			break;
		}

		unOffset += ins.Length;
	}

	if (!pFoundCPUID) {
		return;
	}

	_tprintf_s(_T("RawCPUIDHook.Set = %d\n"), RawCPUIDHook.Set(pFoundCPUID));
	_tprintf_s(_T("RawCPUIDHook.Hook = %d\n"), RawCPUIDHook.Hook(CPUID_RawHook, true));

	int cpuinfo[4];
	__cpuidex(cpuinfo, 7, 0); // Hooking `cpuid` in this function.
	_tprintf_s(_T("cpuinfo[1] = 0x%08X\n"), cpuinfo[1]);

	_tprintf_s(_T("RawCPUIDHook.UnHook = %d\n"), RawCPUIDHook.UnHook());

	_tprintf_s(_T("\n"));
}

#ifdef _M_X64
bool __fastcall new_foo(void* pThis) {
#elif _M_IX86
bool __stdcall new_foo(void* pThis) {
#endif

#ifdef _M_X64
	_tprintf_s(_T("[new_foo] pThis = 0x%016llX\n"), reinterpret_cast<unsigned long long>(pThis));
#elif _M_IX86
	_tprintf_s(_T("[new_foo] pThis = 0x%08X\n"), reinterpret_cast<unsigned int>(pThis));
#endif

	return false;
}

Detours::Hook::RawHook RawHook_CallConv_Convert;
#ifdef _M_X64
bool __fastcall CallConv_Convert_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
bool __cdecl CallConv_Convert_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif

	// Converting __thiscall to __fastcall/__stdcall and redirect it

#ifdef _M_X64
	pCTX->m_unRSP -= 8;
	*reinterpret_cast<unsigned long long*>(pCTX->m_unRSP) = reinterpret_cast<unsigned long long>(new_foo);
#elif _M_IX86
	void* pReturnAddress = pCTX->Stack.pop();
	pCTX->Stack.push(pCTX->m_unECX);
	pCTX->Stack.push(pReturnAddress);
	pCTX->Stack.push(new_foo);
#endif

	return true;
}

int _tmain(int nArguments, PTCHAR* pArguments) {
	g_pBaseTestingRTTI = new BaseTestingRTTI();
	g_pTestingRTTI = new TestingRTTI();

	// ----------------------------------------------------------------
	// Memory Server & Client Example
	// ----------------------------------------------------------------

	if (nArguments > 1) {
		for (int i = 0; i < nArguments; ++i) {
			PTCHAR pArgument = pArguments[i];

			if (_tcscmp(pArgument, _T("/test")) == 0) {
				return TestMode();
			}

			if (_tcscmp(pArgument, _T("/benchmark")) == 0) {
				return BenchmarkMode();
			}

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
#ifdef _UNICODE
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

#ifdef _UNICODE
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
	if (Detours::Hexadecimal::Encode(reinterpret_cast<void const* const>("Hello, World!"), 14, szHex, 0x00)) {
		_tprintf_s(_T("Encode: `%s`\n"), szHex);
	}

	char szData[16];
	memset(szData, 0, sizeof(szData));
	if (Detours::Hexadecimal::Decode(szHex, reinterpret_cast<void*>(szData), 0x00)) {
#ifdef _UNICODE
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
		_tprintf_s(_T("FindSection(...) = 0x%016llX\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#elif _M_IX86
		_tprintf_s(_T("FindSection(...) = 0x%08X\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#endif
	}
	
	pSectionNTDLL = nullptr;
	unSectionNTDLLSize = 0;
	if (Detours::Scan::FindSectionPOGO(_T("ntdll.dll"), ".rdata", &pSectionNTDLL, &unSectionNTDLLSize)) {
#ifdef _M_X64
		_tprintf_s(_T("FindSection(...) = 0x%016llX\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#elif _M_IX86
		_tprintf_s(_T("FindSection(...) = 0x%08X\n"), reinterpret_cast<size_t>(pSectionNTDLL));
#endif
	}

#ifdef _M_X64
	_tprintf_s(_T("FindSignature(...) = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x48\x8B\x41\x2A\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75", 0, 0x20C2003D)));
#elif _M_IX86
	_tprintf_s(_T("FindSignature(...) = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindSignature(_T("ntdll.dll"), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, "\x8B\xD1\x8B\x42", 0, 0xF3780028)));
#endif

#ifdef _M_X64
	_tprintf_s(_T("FindData(...) = 0x%016llX\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x48\x8B\x41\x10\x33\xD2\x4C\x8B\xC1\x48\x85\xC0\x75"), 13)));
#elif _M_IX86
	_tprintf_s(_T("FindData(...) = 0x%08X\n"), reinterpret_cast<size_t>(Detours::Scan::FindData(_T("ntdll.dll"), reinterpret_cast<const unsigned char* const>("\x8B\xD1\x8B\x42\x08"), 5)));
#endif

	_tprintf_s(_T("\n"));

	// ----------------------------------------------------------------
	// RTTI
	// ----------------------------------------------------------------

	_tprintf_s(_T("RTTI Example\n\n"));

	const auto& pObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVTestingRTTI@@");
	if (pObject) {

		DumpObject(g_pTestingRTTI, pObject.get());

		const auto& pVTable = pObject->GetVTable();

#ifdef _M_X64
#ifdef _UNICODE
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
#elif _M_IX86
#ifdef _UNICODE
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#else
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pVTable));
#endif
#endif

		if (pVTable) {
			// __thiscall - 1st arg (this) = ecx
			// __fastcall - 1st arg = ecx, 2nd arg = edx
			using fnFoo = bool(__fastcall*)(void* pThis, void*);
			using fnBoo = bool(__fastcall*)(void* pThis, void*);

			_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr));
		}
	}

	const auto& pMsg1 = new MessageOne();
	const auto& pMsg2 = new MessageTwo();

	ProcessMessage(pMsg1);
	ProcessMessage(pMsg2);

	const auto& pBaseMessageObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVBaseMessage@@", false);
	const auto& pMessageOneObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVMessageOne@@");
	const auto& pMessageTwoObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVMessageTwo@@");

#ifdef _M_X64
#ifdef _UNICODE
	_tprintf_s(_T("> FindObject(...) '%hs' = 0x%016llX\n"), typeid(BaseMessage).raw_name(), reinterpret_cast<size_t>(pBaseMessageObject.get()));
	_tprintf_s(_T("> FindObject(...) '%hs' = 0x%016llX\n"), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMessageOneObject.get()));
	_tprintf_s(_T("> FindObject(...) '%hs' = 0x%016llX\n"), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMessageTwoObject.get()));
#else
	_tprintf_s(_T("> FindObject(...) '%s' = 0x%016llX\n"), typeid(BaseMessage).raw_name(), reinterpret_cast<size_t>(pBaseMessageObject.get()));
	_tprintf_s(_T("> FindObject(...) '%s' = 0x%016llX\n"), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMessageOneObject.get()));
	_tprintf_s(_T("> FindObject(...) '%s' = 0x%016llX\n"), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMessageTwoObject.get()));
#endif
#elif _M_IX86
#ifdef _UNICODE
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%08X\n"), typeid(BaseMessage).raw_name(), reinterpret_cast<size_t>(pBaseMessageObject.get()));
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%08X\n"), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMessageOneObject.get()));
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%08X\n"), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMessageTwoObject.get()));
#else
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%08X\n"), typeid(BaseMessage).raw_name(), reinterpret_cast<size_t>(pBaseMessageObject.get()));
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%08X\n"), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMessageOneObject.get()));
	_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%08X\n"), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMessageTwoObject.get()));
#endif
#endif

	if (pBaseMessageObject && pMessageOneObject && pMessageTwoObject) {
#ifdef _M_X64
#ifdef _UNICODE
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%hs' -> `%hs` = [0x%016llX -> 0x%016llX]\n"), typeid(BaseMessage).raw_name(), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageOneObject.get())));
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%hs' -> `%hs` = [0x%016llX -> 0x%016llX]\n"), typeid(BaseMessage).raw_name(), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageTwoObject.get())));
#else
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%s' -> `%s` = [0x%016llX -> 0x%016llX]\n"), typeid(BaseMessage).raw_name(), typeid(MessageOne).raw_name() reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageOneObject.get())));
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%s' -> `%s` = [0x%016llX -> 0x%016llX]\n"), typeid(BaseMessage).raw_name(),, typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageTwoObject.get())));
#endif
#elif _M_IX86
#ifdef _UNICODE
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%hs' -> `%hs` = [0x%08X -> 0x%08X]\n"), typeid(BaseMessage).raw_name(), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageOneObject.get())));
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%hs' -> `%hs` = [0x%08X -> 0x%08X]\n"), typeid(BaseMessage).raw_name(), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageTwoObject.get())));
#else
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%s' -> `%s` = [0x%08X -> 0x%08X]\n"), typeid(BaseMessage).raw_name(), typeid(MessageOne).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageOneObject.get())));
		_tprintf_s(_T("> BaseMessage->DynamicCast(...) '%s' -> `%s` = [0x%08X -> 0x%08X]\n"), typeid(BaseMessage).raw_name(), typeid(MessageTwo).raw_name(), reinterpret_cast<size_t>(pMsg1), reinterpret_cast<size_t>(pBaseMessageObject->DynamicCast(pMsg1, pMessageTwoObject.get())));
#endif
#endif
	}

	delete pMsg1;
	delete pMsg2;

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

	if (const auto& pHookingObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVTestingRTTI@@")) {
		void** pHookingVTable = pHookingObject->GetVTable();

#ifdef _M_X64
#ifdef _UNICODE
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#else
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%016llX\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#endif
#elif _M_IX86
#ifdef _UNICODE
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%hs' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#else
		_tprintf_s(_T("> FindObject(...)->GetVTable(...) '%s' = 0x%08X\n"), typeid(TestingRTTI).raw_name(), reinterpret_cast<size_t>(pHookingVTable));
#endif
#endif

		if (pHookingVTable) {
			// __thiscall - 1st arg (this) = ecx
			// __fastcall - 1st arg = ecx, 2nd arg = edx
			using fnFoo = bool(__fastcall*)(void* pThis, void*);
			using fnBoo = bool(__fastcall*)(void* pThis, void*);

			_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));

			_tprintf_s(_T("fooHook.Set(...) = %d\n"), fooHook.Set(pHookingVTable, 0));
			_tprintf_s(_T("fooHook.Hook(...) = %d\n"), fooHook.Hook(foo_Hook));
			_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("fooHook.UnHook() = %d\n"), fooHook.UnHook());

			_tprintf_s(_T("booHook.Set(...) = %d\n"), booHook.Set(pHookingVTable, 1));
			_tprintf_s(_T("booHook.Hook(...) = %d\n"), booHook.Hook(boo_Hook));
			_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("booHook.UnHook() = %d\n"), booHook.UnHook());

			void* pNewVTable[2] = {
				nullptr, // Will be skipped
				reinterpret_cast<void*>(boo_Hook2)
			};

			_tprintf_s(_T("NewTestingRTTIVTable.Set(...) = %d\n"), NewTestingRTTIVTable.Set(pHookingVTable, 2));
			_tprintf_s(_T("NewTestingRTTIVTable.Hook(...) = %d\n"), NewTestingRTTIVTable.Hook(pNewVTable));
			_tprintf_s(_T("  > foo() = %d\n"), reinterpret_cast<fnFoo>(pHookingVTable[0])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("  > boo() = %d\n"), reinterpret_cast<fnBoo>(pHookingVTable[1])(g_pTestingRTTI, nullptr));
			_tprintf_s(_T("NewTestingRTTIVTable.UnHook() = %d\n"), NewTestingRTTIVTable.UnHook());
		}

		_tprintf_s(_T("\n"));
	}

	// InlineHook

	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 && (hKernel32 != INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("InlineSleepHook.Set = %d\n"), InlineSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))));
		_tprintf_s(_T("InlineSleepHook.Hook = %d\n"), InlineSleepHook.Hook(reinterpret_cast<void*>(Sleep_Hook)));
		Sleep(1000);
		_tprintf_s(_T("InlineSleepHook.UnHook = %d\n"), InlineSleepHook.UnHook());
	}

	_tprintf_s(_T("\n"));

	// RawHook #1

	if (hKernel32 && (hKernel32 != INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("RawSleepHook.Set = %d\n"), RawSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))));
		_tprintf_s(_T("RawSleepHook.Hook = %d\n"), RawSleepHook.Hook(Sleep_RawHook));
		Sleep(1000);
		_tprintf_s(_T("RawSleepHook.UnHook = %d\n"), RawSleepHook.UnHook());
		_tprintf_s(_T("RawSleepHook.Release = %d\n"), RawSleepHook.Release());
	}

	// RawHook #2

	int cpuinfo[4];
	__cpuid(cpuinfo, 1);

	const bool bHaveSSE = (cpuinfo[3] & (1 << 25)) != 0;

	if (bHaveSSE && hKernel32 && (hKernel32 != INVALID_HANDLE_VALUE)) {
		_tprintf_s(_T("RawSleepHook.Set = %d\n"), RawSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))));
		_tprintf_s(_T("RawSleepHook.Hook = %d\n"), RawSleepHook.Hook(Sleep_RawHookMod));

		Sleep(1000); // Will record last XMM7 value and change it

		_tprintf_s(_T("LastXMM7 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), g_LastXMM7.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		Sleep(1000); // Will record last XMM7 value and change it

		_tprintf_s(_T("LastXMM7 = 0x"));
		for (int i = 15; i >= 0; --i) {
			_tprintf_s(_T("%02X"), g_LastXMM7.m_un8[i]);
		}
		_tprintf_s(_T("\n"));

		_tprintf_s(_T("RawSleepHook.UnHook = %d\n"), RawSleepHook.UnHook());
	}

	_tprintf_s(_T("\n"));

	// RawHook #3

	if (const auto& pHookingObject = Detours::RTTI::FindObject(_T("Detours.exe"), ".?AVTestingRTTI@@")) {
		void** pHookingVTable = pHookingObject->GetVTable();

		_tprintf_s(_T("RawHook_CallConv_Convert.Set = %d\n"), RawHook_CallConv_Convert.Set(pHookingVTable[0]));
		_tprintf_s(_T("RawHook_CallConv_Convert.Hook = %d\n"), RawHook_CallConv_Convert.Hook(CallConv_Convert_RawHook, true, 0x10));

		_tprintf_s(_T("g_pTestingRTTI->foo = %d\n"), g_pTestingRTTI->foo());

		_tprintf_s(_T("RawHook_CallConv_Convert.UnHook = %d\n"), RawHook_CallConv_Convert.UnHook());

		_tprintf_s(_T("\n"));
	}

	// RawHook + rddisasm

	DemoRawHook();

	_tprintf_s(_T("[ FINISHED ]\n"));
	_CRT_UNUSED(getchar());
	return 0;
}

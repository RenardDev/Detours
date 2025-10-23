
// Default
#include <Windows.h>
#include <tchar.h>

// Advanced
#include <intrin.h>

// C++
#include <cstdio>
#include <typeinfo>
#include <iostream>
#include <unordered_map>

// Detours
#include "Detours.h"

// doctest
#undef min
#undef max
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#include "doctest.h"

// interrupts32.asm/interrupts64.asm
#ifdef _M_X64
extern "C" unsigned long long __cdecl CallInterrupt(unsigned long long unRAX, unsigned long long unRCX, unsigned long long unRDX, unsigned long long unRBX, unsigned long long unRBP, unsigned long long unRSI, unsigned long long unRDI, unsigned long long unR8, unsigned long long unR9, unsigned long long unR10, unsigned long long unR11, unsigned long long unR12, unsigned long long unR13, unsigned long long unR14, unsigned long long unR15);
//extern "C" void __cdecl CallInrerruptReturn(unsigned long long unRIP, unsigned long long unCS, unsigned long long unRFLAGS, unsigned long long unRSP, unsigned long long unSS);
#elif _M_IX86
extern "C" unsigned int __cdecl CallInterrupt(unsigned int unEAX, unsigned int unECX, unsigned int unEDX, unsigned int unEBX, unsigned int unEBP, unsigned int unESI, unsigned int unEDI);
//extern "C" void __cdecl CallInrerruptReturn(unsigned int unEIP, unsigned int unCS, unsigned int unEFLAGS, unsigned int unESP, unsigned int unSS);
#endif

extern "C" unsigned char __cdecl TryRead(void* pData);

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

struct SI_Base {
	virtual ~SI_Base() {}
	virtual int id() { return 1; }
	virtual bool base_only() { return true; }
};

struct SI_Derived : SI_Base {
	~SI_Derived() override {}
	int id() override { return 2; }
	bool base_only() override { return false; }
};

struct MI_A {
	virtual ~MI_A() {}
	virtual int a() { return 10; }
};

struct MI_B {
	virtual ~MI_B() {}
	virtual int b() { return 20; }
};

struct MI_D : MI_A, MI_B {
	~MI_D() override {}
	int a() override { return 11; }
	int b() override { return 21; }
};

struct VI_V {
	virtual ~VI_V() {}
	virtual const char* v() { return "V"; }
};

struct VI_A : virtual VI_V {
	~VI_A() override {}
	const char* v() override { return "A"; }
};

struct VI_B : virtual VI_V {
	~VI_B() override {}
	const char* v() override { return "B"; }
};

struct VI_D : VI_A, VI_B {
	~VI_D() override {}
	const char* v() override { return "D"; }
};

struct PrivBase {
	virtual ~PrivBase() {}
	virtual int tag() { return 777; }
};

struct PrivDerived : private PrivBase {
public:
	~PrivDerived() override {}
	PrivBase* AsBase() { return static_cast<PrivBase*>(this); }
	int tag() override { return 888; }
};

template <typename T>
static inline const char* nameof() {
	return typeid(T).raw_name();
}

DEFINE_SECTION(".cdata", SECTION_READWRITE)
DEFINE_SECTION(".ctext", SECTION_EXECUTE_READ)

DEFINE_DATA_IN_SECTION(".cdata") __declspec(dllexport) BaseTestingRTTI* g_pBaseTestingRTTI = nullptr;
DEFINE_DATA_IN_SECTION(".cdata") __declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;

DEFINE_CODE_IN_SECTION(".ctext") __declspec(dllexport) int DemoSum(int nA, int nB) {
	return nA + nB / nA;
}

DWORD GetUBR() {
	static DWORD unKnownUBR = 0;
	if (unKnownUBR) {
		return unKnownUBR;
	}

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
	unKnownUBR = unUBR;
	return unUBR;
}

TEST_SUITE("Detours::KUserSharedData") {
	TEST_CASE("SystemTime") {
		const ULONG unLowPartTime = Detours::KUserSharedData.SystemTime.LowPart;
		Sleep(5250);
		const ULONG unElapsedTime = (Detours::KUserSharedData.SystemTime.LowPart - unLowPartTime) / 10000000;
		CHECK(unElapsedTime == 5);
	}

	TEST_CASE("Cookie") {
		CHECK(Detours::KUserSharedData.Cookie != 0);
	}

	TEST_CASE("ActiveProcessorCount") {
		CHECK(Detours::KUserSharedData.ActiveProcessorCount != 0);
	}
}

TEST_SUITE("Detours::GetPEB") {
	TEST_CASE("Windows Version") {
		auto pPEB = Detours::GetPEB();
		CHECK(pPEB != nullptr);
		char szBuffer[128];
		memset(szBuffer, 0, sizeof(szBuffer));
		CHECK(sprintf_s(szBuffer, sizeof(szBuffer), "Microsoft Windows [Version %lu.%lu.%05lu.%lu]\n", pPEB->OSMajorVersion, pPEB->OSMinorVersion, pPEB->OSBuildNumber, GetUBR()) > 0);
		MESSAGE(szBuffer);
	}

	TEST_CASE("ProcessParameters") {
		auto pPEB = Detours::GetPEB();
		CHECK(pPEB != nullptr);
		CHECK(pPEB->ProcessParameters != nullptr);
		CHECK(pPEB->ProcessParameters->CommandLine.Length > 0);
		CHECK(pPEB->ProcessParameters->CommandLine.Buffer != nullptr);
		char szBuffer[256];
		memset(szBuffer, 0, sizeof(szBuffer));
		CHECK(sprintf_s(szBuffer, sizeof(szBuffer), "CommandLine = `%ws`\n", pPEB->ProcessParameters->CommandLine.Buffer) > 0);
		MESSAGE(szBuffer);
	}
}

TEST_SUITE("Detours::GetTEB") {
	TEST_CASE("Process ID and Thread ID") {
		auto pTEB = Detours::GetTEB();
		CHECK(pTEB != nullptr);
		CHECK(pTEB->ClientId.UniqueProcess != 0);
		CHECK(pTEB->ClientId.UniqueThread != 0);
		CHECK(pTEB->RealClientId.UniqueProcess == pTEB->ClientId.UniqueProcess);
		CHECK(pTEB->RealClientId.UniqueThread == pTEB->ClientId.UniqueThread);
	}

	TEST_CASE("LastError") {
		auto pTEB = Detours::GetTEB();
		CHECK(pTEB != nullptr);
		SetLastError(0x11223344);
		CHECK(pTEB->LastErrorValue == 0x11223344);
	}
}

TEST_SUITE("Detours::LDR") {
	TEST_CASE("UnLink/ReLink modules") {
		HMODULE hKernelBase = GetModuleHandle(_T("KernelBase.dll"));
		CHECK(hKernelBase != nullptr);
		Detours::LDR::LINK_DATA ld;
		CHECK(Detours::LDR::UnLinkModule(hKernelBase, &ld) == true);
		CHECK(GetModuleHandle(_T("KernelBase.dll")) == nullptr);
		Detours::LDR::ReLinkModule(ld);
		CHECK(GetModuleHandle(_T("KernelBase.dll")) != nullptr);
	}
}

TEST_SUITE("Detours::Codec") {
	TEST_CASE("UpperCase") {
		char* szHelloWorld = _strdup("Hello, World!");
		CHECK(szHelloWorld != nullptr);
		const size_t unSize = strnlen(szHelloWorld, 0x7FF);
		CHECK(unSize != 0x7FF);
		CHECK(Detours::Codec::UpperCase(szHelloWorld, unSize) == true);
		CHECK(strcmp(szHelloWorld, "HELLO, WORLD!") == 0);
		free(szHelloWorld);
	}

	TEST_CASE("LowerCase") {
		char* szHelloWorld = _strdup("Hello, World!");
		CHECK(szHelloWorld != nullptr);
		const size_t unSize = strnlen(szHelloWorld, 0x7FF);
		CHECK(unSize != 0x7FF);
		CHECK(Detours::Codec::LowerCase(szHelloWorld, unSize) == true);
		CHECK(strcmp(szHelloWorld, "hello, world!") == 0);
		free(szHelloWorld);
	}

#pragma warning(push)
#pragma warning(disable: 6001)

	TEST_CASE("Encode") {
		int nEncodeSize = Detours::Codec::Encode(CP_UTF8, "Hello, World!");
		CHECK(nEncodeSize > 0);
		HANDLE hHeap = GetProcessHeap();
		CHECK(hHeap != nullptr);
		CHECK(hHeap != INVALID_HANDLE_VALUE);
		wchar_t* pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t)));
		CHECK(pBuffer != nullptr);
		memset(pBuffer, 0, static_cast<size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t));
		CHECK(Detours::Codec::Encode(CP_UTF8, "Hello, World!", pBuffer, nEncodeSize) > 0);
		CHECK(wcscmp(pBuffer, L"Hello, World!") == 0);
		CHECK(HeapFree(hHeap, NULL, pBuffer) == TRUE);
	}

	TEST_CASE("Decode") {
		int nDecodeSize = Detours::Codec::Decode(CP_UTF8, L"Hello, World!");
		CHECK(nDecodeSize > 0);
		HANDLE hHeap = GetProcessHeap();
		CHECK(hHeap != nullptr);
		CHECK(hHeap != INVALID_HANDLE_VALUE);
		char* pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<size_t>(nDecodeSize) * sizeof(char) + sizeof(char)));
		CHECK(pBuffer != nullptr);
		memset(pBuffer, 0, static_cast<size_t>(nDecodeSize) * sizeof(char) + sizeof(char));
		CHECK(Detours::Codec::Decode(CP_UTF8, L"Hello, World!", pBuffer, nDecodeSize) > 0);
		CHECK(strcmp(pBuffer, "Hello, World!") == 0);
		CHECK(HeapFree(hHeap, NULL, pBuffer) == TRUE);
	}

#pragma warning(pop)
}

TEST_SUITE("Detours::Hexadecimal") {
	TEST_CASE("Encode") {
		TCHAR szHex[32];
		memset(szHex, 0, sizeof(szHex));
		CHECK(Detours::Hexadecimal::Encode(reinterpret_cast<void const* const>("Hello, World!"), 14, szHex, 0x00) == true);
		CHECK(_tcscmp(szHex, _T("48656C6C6F2C20576F726C642100")) == 0);
	}

	TEST_CASE("Decode") {
		char szData[16];
		memset(szData, 0, sizeof(szData));
		CHECK(Detours::Hexadecimal::Decode(_T("48656C6C6F2C20576F726C642100"), reinterpret_cast<void*>(szData), 0x00) == true);
		CHECK(memcmp(szData, "Hello, World!", 14) == 0);
	}
}

TEST_SUITE("Detours::Scan") {
	TEST_CASE("FindSection") {
		void* pSection = nullptr;
		size_t unSectionSize = 0;
		CHECK(Detours::Scan::FindSection(GetModuleHandle(nullptr), {'.', 't', 'e', 'x', 't', 0, 0, 0}, &pSection, &unSectionSize) == true);
		CHECK(pSection != nullptr);
		CHECK(unSectionSize != 0);
	}

	TEST_CASE("FindSection [benchmark]" * doctest::skip() * doctest::timeout(1)) {
		void* pSection = nullptr;
		size_t unSectionSize = 0;
		HMODULE hModule = GetModuleHandle(nullptr);
		CHECK(hModule != nullptr);
		ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (size_t i = 0; i < 10'000; ++i) {
			if (!Detours::Scan::FindSection(hModule, { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize)) {
				FAIL("Fail in benckmark!");
			}
		}
		MESSAGE("Benckmark with 10 000 iterations: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSectionPOGO" * doctest::skip()) { // TODO: Fails on Windows Server 2025 (Probably because WS25 don't have it)
		void* pSection = nullptr;
		size_t unSectionSize = 0;
		CHECK(Detours::Scan::FindSectionPOGO(GetModuleHandle(nullptr), ".rdata", &pSection, &unSectionSize) == true);
		CHECK(pSection != nullptr);
		CHECK(unSectionSize != 0);
	}

	TEST_CASE("FindSectionPOGO [benchmark]" * doctest::skip() * doctest::timeout(1)) {
		void* pSection = nullptr;
		size_t unSectionSize = 0;
		HMODULE hModule = GetModuleHandle(nullptr);
		CHECK(hModule != nullptr);
		ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (size_t i = 0; i < 10'000; ++i) {
			if (!Detours::Scan::FindSectionPOGO(hModule, ".rdata", &pSection, &unSectionSize)) {
				FAIL("Fail in benckmark!");
			}
		}
		MESSAGE("Benckmark with 10 000 iterations: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSignature") {

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		const bool bHaveSSE2 = (cpuinfo[3] & (1 << 26)) != 0;

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX2 = (cpuinfo[1] & (1 << 5)) != 0;
		const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

		unsigned char pAlignEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignBeginArray[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray);
		CHECK(Detours::Scan::FindSignatureNative(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24);
		CHECK(Detours::Scan::FindSignatureNative(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28);
		CHECK(Detours::Scan::FindSignatureNative(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32);
		CHECK(Detours::Scan::FindSignatureNative(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36);
		CHECK(Detours::Scan::FindSignatureNative(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureSSE2(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureAVX2(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignEmptyArray, sizeof(pAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignBeginArray, sizeof(pAlignBeginArray), "\xDE\xED\x2A\xEF") == pAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureAVX512(pAlignEndArray, sizeof(pAlignEndArray), "\xDE\xED\x2A\xEF") == pAlignEndArray + 60);
		}

		unsigned char pEmptyArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray1[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindSignatureNative(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37);
		CHECK(Detours::Scan::FindSignatureNative(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureSSE2(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureAVX2(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(pEmptyArray1, sizeof(pEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pBeginArray1, sizeof(pBeginArray1), "\xDE\xED\x2A\xEF") == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleEndArray1, sizeof(pMiddleEndArray1), "\xDE\xED\x2A\xEF") == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureAVX512(pEndArray1, sizeof(pEndArray1), "\xDE\xED\x2A\xEF") == pEndArray1 + 61);
		}

		unsigned char pEmptyArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray2[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindSignatureNative(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36);
		CHECK(Detours::Scan::FindSignatureNative(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureSSE2(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureAVX2(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(pEmptyArray2, sizeof(pEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pBeginArray2, sizeof(pBeginArray2), "\xDE\xED\x2A\xEF") == pBeginArray2);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleEndArray2, sizeof(pMiddleEndArray2), "\xDE\xED\x2A\xEF") == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureAVX512(pEndArray2, sizeof(pEndArray2), "\xDE\xED\x2A\xEF") == pEndArray2 + 60);
		}

		unsigned char pEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33);
		CHECK(Detours::Scan::FindSignatureNative(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37);
		CHECK(Detours::Scan::FindSignatureNative(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureSSE2(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureSSE2(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureAVX2(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureAVX2(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(pEmptyArray3, sizeof(pEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pBeginArray3, sizeof(pBeginArray3), "\xDE\xED\x2A\xEF") == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureAVX512(pMiddleEndArray3, sizeof(pMiddleEndArray3), "\xDE\xED\x2A\xEF") == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureAVX512(pEndArray3, sizeof(pEndArray3), "\xDE\xED\x2A\xEF") == pEndArray3 + 61);
		}
	}

	TEST_CASE("FindSignatureNative [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (unsigned int i = 0; i < 1'000; ++i) {
			if (!Detours::Scan::FindSignatureNative(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
				FAIL("Fail in benckmark!");
			}
		}
		MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSignatureSSE2 [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		const bool bHaveSSE2 = (cpuinfo[3] & (1 << 26)) != 0;

		if (bHaveSSE2) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindSignatureSSE2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindSignatureAVX2 [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX2 = (cpuinfo[1] & (1 << 5)) != 0;

		if (bHaveAVX2) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindSignatureAVX2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindSignatureAVX512 [benckmark]" * doctest::skip() * doctest::timeout(5)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

		if (bHaveAVX512) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindSignatureAVX512(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindData") {
		CHECK(Detours::Scan::FindData(GetModuleHandle(nullptr), { '.', 'r', 'd', 'a', 't', 'a', 0, 0 }, reinterpret_cast<const unsigned char* const>("\xDE\xED\xBE\xEF"), 4) != nullptr);

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		const bool bHaveSSE2 = (cpuinfo[3] & (1 << 26)) != 0;

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX2 = (cpuinfo[1] & (1 << 5)) != 0;
		const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

		unsigned char pAlignEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignBeginArray[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray);
		CHECK(Detours::Scan::FindDataNative(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24);
		CHECK(Detours::Scan::FindDataNative(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28);
		CHECK(Detours::Scan::FindDataNative(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32);
		CHECK(Detours::Scan::FindDataNative(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36);
		CHECK(Detours::Scan::FindDataNative(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray);
			CHECK(Detours::Scan::FindDataSSE2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataSSE2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataSSE2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataSSE2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataSSE2(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray);
			CHECK(Detours::Scan::FindDataAVX2(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataAVX2(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataAVX2(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataAVX2(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataAVX2(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(pAlignEmptyArray, sizeof(pAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(pAlignBeginArray, sizeof(pAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignBeginArray);
			CHECK(Detours::Scan::FindDataAVX512(pAlignMiddleBeginArray, sizeof(pAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataAVX512(pAlignMiddleBeginLeftArray, sizeof(pAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataAVX512(pAlignMiddleBeginRightArray, sizeof(pAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataAVX512(pAlignMiddleEndArray, sizeof(pAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataAVX512(pAlignEndArray, sizeof(pAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pAlignEndArray + 60);
		}

		unsigned char pEmptyArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray1[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindDataNative(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33);
		CHECK(Detours::Scan::FindDataNative(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37);
		CHECK(Detours::Scan::FindDataNative(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataSSE2(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataAVX2(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(pEmptyArray1, sizeof(pEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(pBeginArray1, sizeof(pBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginArray1, sizeof(pMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginLeftArray1, sizeof(pMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginRightArray1, sizeof(pMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleEndArray1, sizeof(pMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataAVX512(pEndArray1, sizeof(pEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray1 + 61);
		}

		unsigned char pEmptyArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray2[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindDataNative(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32);
		CHECK(Detours::Scan::FindDataNative(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36);
		CHECK(Detours::Scan::FindDataNative(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataSSE2(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataAVX2(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(pEmptyArray2, sizeof(pEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(pBeginArray2, sizeof(pBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray2);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginArray2, sizeof(pMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginLeftArray2, sizeof(pMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginRightArray2, sizeof(pMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleEndArray2, sizeof(pMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataAVX512(pEndArray2, sizeof(pEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray2 + 60);
		}

		unsigned char pEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char pEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29);
		CHECK(Detours::Scan::FindDataNative(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33);
		CHECK(Detours::Scan::FindDataNative(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37);
		CHECK(Detours::Scan::FindDataNative(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataSSE2(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataSSE2(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataAVX2(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataAVX2(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(pEmptyArray3, sizeof(pEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(pBeginArray3, sizeof(pBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginArray3, sizeof(pMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginLeftArray3, sizeof(pMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleBeginRightArray3, sizeof(pMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataAVX512(pMiddleEndArray3, sizeof(pMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataAVX512(pEndArray3, sizeof(pEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == pEndArray3 + 61);
		}
	}

	TEST_CASE("FindDataNative [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (unsigned int i = 0; i < 1'000; ++i) {
			if (!Detours::Scan::FindDataNative(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
				FAIL("Fail in benckmark!");
			}
		}
		MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindDataSSE2 [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		const bool bHaveSSE2 = (cpuinfo[3] & (1 << 26)) != 0;

		if (bHaveSSE2) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindDataSSE2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindDataAVX2 [benckmark]" * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX2 = (cpuinfo[1] & (1 << 5)) != 0;

		if (bHaveAVX2) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindDataAVX2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindDataAVX512 [benckmark]" * doctest::skip() * doctest::timeout(10)) {
		auto pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		CHECK(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		int cpuinfo[4];
		__cpuid(cpuinfo, 1);

		__cpuidex(cpuinfo, 7, 0);

		const bool bHaveAVX512 = (cpuinfo[1] & (1 << 16)) != 0;

		if (bHaveAVX512) {
			ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
			for (unsigned int i = 0; i < 1'000; ++i) {
				if (!Detours::Scan::FindDataAVX512(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benckmark!");
				}
			}
			MESSAGE("Benckmark with 1 000 iterations over 8 MiB memory: ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}
}

#ifndef _DEBUG
DISABLE_OPTIMIZATION_BEGIN("") {
#endif

TEST_SUITE("Detours::RTTI") {

	TEST_CASE("DumpRTTI") {
		auto TDs = Detours::RTTI::DumpRTTI(GetModuleHandle(nullptr));
		for (auto& pTD : TDs) {
			printf("Name: `%s`\n", pTD->GetTypeDescriptor()->m_szName);
		}
	}

	TEST_CASE("FindRTTI") {
		// Construct a small hierarchy and verify we can locate RTTI for a derived type
		// and extract a working vtable to call through.
		g_pBaseTestingRTTI = new BaseTestingRTTI();
		CHECK(g_pBaseTestingRTTI != nullptr);

		g_pTestingRTTI = new TestingRTTI();
		CHECK(g_pTestingRTTI != nullptr);

		// Find TestingRTTI while asserting it has BaseTestingRTTI as a parent.
		const auto& pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@", ".?AVBaseTestingRTTI@@");
		CHECK(pObject != nullptr);

		// Pull vtable for direct call tests.
		const auto& pVTable = pObject->GetVTable();
		CHECK(pVTable != nullptr);

		// The test interface: two virtuals with boolean returns.
		using fnFoo = bool(__fastcall*)(void* pThis, void*);
		using fnBoo = bool(__fastcall*)(void* pThis, void*);

		// Validate the vtable entries invoke expected implementations.
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);

		delete g_pTestingRTTI;
		delete g_pBaseTestingRTTI;
	}

	TEST_CASE("DynamicCastingRTTI") {
		// Cross-check base->derived selection using our dynamic cast engine.
		const auto& pMsg1 = new MessageOne();
		CHECK(pMsg1 != nullptr);

		const auto& pMsg2 = new MessageTwo();
		CHECK(pMsg2 != nullptr);

		// Query RTTI nodes for BaseMessage and the two derived message types.
		const auto& pBaseMessageObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVBaseMessage@@", nullptr, false);
		CHECK(pBaseMessageObject != nullptr);

		const auto& pMessageOneObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVMessageOne@@", ".?AVBaseMessage@@");
		CHECK(pMessageOneObject != nullptr);

		const auto& pMessageTwoObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVMessageTwo@@");
		CHECK(pMessageTwoObject != nullptr);

		// base -> MessageOne should succeed for Msg1; fail for Msg2 (and vice versa).
		CHECK(pBaseMessageObject->DynamicCast(pMsg1, pMessageOneObject.get()) != nullptr);
		CHECK(pBaseMessageObject->DynamicCast(pMsg1, pMessageTwoObject.get()) == nullptr);
		CHECK(pBaseMessageObject->DynamicCast(pMsg2, pMessageOneObject.get()) == nullptr);
		CHECK(pBaseMessageObject->DynamicCast(pMsg2, pMessageTwoObject.get()) != nullptr);

		delete pMsg1;
		delete pMsg2;
	}

	TEST_CASE("FindRTTI_SI_by_typeid") {
		// Validate simple single-inheritance upcast and downcast using RTTI graph.
		auto* d = new SI_Derived();
		REQUIRE(d != nullptr);

		// Fetch RTTI nodes by typeid-mangled name: SI_Base and SI_Derived.
		auto baseObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Base>(), nullptr, /*bCompleteObject*/false);
		auto derivedObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>());

		CHECK(baseObj != nullptr);
		CHECK(derivedObj != nullptr);

		// Upcast: Derived* -> Base* must succeed.
		CHECK(derivedObj->DynamicCast(d, baseObj.get()) != nullptr);

		// Downcast: Base* -> Derived* must succeed too (same most-derived).
		SI_Base* b = d;
		CHECK(baseObj->DynamicCast(b, derivedObj.get()) != nullptr);

		delete d;
	}

	TEST_CASE("FindRTTI_ParentFilter_Positive_and_Negative") {
		// Verify the optional "parent" filter in FindObject acts as expected.
		auto* d = new MI_D();
		REQUIRE(d != nullptr);

		// Positive: MI_D has MI_A somewhere in its ancestry.
		auto d_has_A = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), nameof<MI_A>());
		CHECK(d_has_A != nullptr);

		// Negative: MI_D is not derived from SI_Derived.
		auto d_has_fake = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), nameof<SI_Derived>());
		CHECK(d_has_fake == nullptr);

		delete d;
	}

	TEST_CASE("FindRTTI_MI_CompleteObject_Offsets") {
		// When searching for a complete object, the offset must match the
		// subobject layout of the most-derived (MI) object.
		auto* d = new MI_D();
		REQUIRE(d != nullptr);

		// Take subobject pointers and compute their offsets within D.
		auto* asA = static_cast<MI_A*>(d);
		auto* asB = static_cast<MI_B*>(d);
		auto* asD = static_cast<void*>(d);

		ptrdiff_t offA = reinterpret_cast<const char*>(static_cast<void*>(asA)) - reinterpret_cast<const char*>(asD);
		ptrdiff_t offB = reinterpret_cast<const char*>(static_cast<void*>(asB)) - reinterpret_cast<const char*>(asD);

		// Correct offset for A must yield a valid object with vtable.
		auto d_offA = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/nullptr, /*bCompleteObject*/true, static_cast<unsigned>(offA));
		CHECK(d_offA != nullptr);
		CHECK(d_offA->GetVTable() != nullptr);

		// Wrong offset should not match.
		auto d_wrong = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/nullptr, /*bCompleteObject*/true, static_cast<unsigned>(offB + 4));
		CHECK(d_wrong == nullptr);

		// Correct offset for B must also match.
		auto d_offB = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/nullptr, /*bCompleteObject*/true, static_cast<unsigned>(offB));
		CHECK(d_offB != nullptr);
		CHECK(d_offB->GetVTable() != nullptr);

		delete d;
	}

	TEST_CASE("DynamicCast_CrossCast_MI") {
		// Cross-cast across branches in an MI diamond:
		//   D : A, B - casting A* -> B* and B* -> A* should succeed via D.
		auto* d = new MI_D();
		REQUIRE(d != nullptr);

		auto aObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_A>(), nullptr, false);
		auto bObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_B>(), nullptr, false);
		CHECK(aObj != nullptr);
		CHECK(bObj != nullptr);

		MI_A* pa = d;
		CHECK(aObj->DynamicCast(pa, bObj.get()) != nullptr);

		MI_B* pb = d;
		CHECK(bObj->DynamicCast(pb, aObj.get()) != nullptr);

		delete d;
	}

	TEST_CASE("DynamicCast_CrossCast_VI") {
		// Cross-cast through a virtual base path:
		//   D : VI_A, VI_B; both are virtually derived from VI_V.
		auto* d = new VI_D();
		REQUIRE(d != nullptr);

		auto aObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<VI_A>(), nullptr, false);
		auto bObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<VI_B>(), nullptr, false);
		CHECK(aObj != nullptr);
		CHECK(bObj != nullptr);

		VI_A* pa = d;
		CHECK(aObj->DynamicCast(pa, bObj.get()) != nullptr);

		VI_B* pb = d;
		CHECK(bObj->DynamicCast(pb, aObj.get()) != nullptr);

		delete d;
	}

	TEST_CASE("DynamicCast_PrivateBase_is_blocked") {
		// Access control must be enforced: private base prevents a legal up/down cast.
		auto* d = new PrivDerived();
		REQUIRE(d != nullptr);

		auto baseObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<PrivBase>(), nullptr, false);
		auto drvObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<PrivDerived>(), nameof<PrivBase>());
		CHECK(baseObj != nullptr);
		CHECK(drvObj != nullptr);

		PrivBase* pb = d->AsBase(); // returns pointer to private base subobject
		CHECK(baseObj->DynamicCast(pb, drvObj.get()) == nullptr); // cast must be blocked

		delete d;
	}

	TEST_CASE("FindObject_Wide_and_Ansi_ModuleName") {
		// The ANSI and WIDE variants must both locate the same type in the same module.
		wchar_t wpath[MAX_PATH] = {};
		DWORD wn = GetModuleFileNameW(nullptr, wpath, MAX_PATH);
		REQUIRE(wn > 0);

		char apath[MAX_PATH] = {};
		DWORD an = GetModuleFileNameA(nullptr, apath, MAX_PATH);
		REQUIRE(an > 0);

		auto fromW = Detours::RTTI::FindObjectW(wpath, nameof<SI_Derived>(), nameof<SI_Base>());
		auto fromA = Detours::RTTI::FindObjectA(apath, nameof<SI_Derived>(), nameof<SI_Base>());
		CHECK(fromW != nullptr);
		CHECK(fromA != nullptr);
	}

	TEST_CASE("FindRTTI_NotFound_WrongName") {
		// Gracefully returns nullptr for non-existent type names.
		auto o = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AV__Definitely_No_Such_Type__@@", nullptr, false);
		CHECK(o == nullptr);
	}

	TEST_CASE("FindRTTI_Complete_vs_Partial_paths") {
		// Compare the partial (no strict COL) and complete (strict COL + offset) paths.
		auto* d = new SI_Derived();
		REQUIRE(d != nullptr);

		auto partial = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/false);
		CHECK(partial != nullptr);

		auto complete = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/true, /*unOffset*/0);
		CHECK(complete != nullptr);

		auto wrong = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/true, /*unOffset*/4);
		CHECK(wrong == nullptr);

		delete d;
	}

	TEST_CASE("RTCastToVoid_returns_complete_object_SI_MI_VI") {
		// RTCastToVoid should return the most-derived (complete object) pointer.

		// --- SI case ---
		{
			auto* d = new SI_Derived();
			REQUIRE(d != nullptr);

			SI_Base* b = d;
			void* complete = static_cast<void*>(d);
			CHECK(Detours::RTTI::RTCastToVoid(b) == complete);

			delete d;
		}

		// --- MI case ---
		{
			auto* d = new MI_D();
			REQUIRE(d != nullptr);

			MI_A* pa = d;
			MI_B* pb = d;
			void* complete = static_cast<void*>(d);

			CHECK(Detours::RTTI::RTCastToVoid(pa) == complete);
			CHECK(Detours::RTTI::RTCastToVoid(pb) == complete);

			delete d;
		}

		// --- VI case ---
		{
			auto* d = new VI_D();
			REQUIRE(d != nullptr);

			VI_A* pa = d;
			VI_B* pb = d;
			void* complete = static_cast<void*>(d);

			CHECK(Detours::RTTI::RTCastToVoid(pa) == complete);
			CHECK(Detours::RTTI::RTCastToVoid(pb) == complete);

			delete d;
		}
	}

	TEST_CASE("RTtypeid_dynamic_type_matches") {
		// RTtypeid should reflect the dynamic type of the most-derived object
		// no matter which base-subobject pointer is used.

		// --- SI: Base* -> Derived dynamic type ---
		{
			auto* d = new SI_Derived();
			REQUIRE(d != nullptr);

			SI_Base* b = d;
#ifdef _M_X64
			auto td = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(b));
#else
			auto td = Detours::RTTI::RTtypeid(static_cast<void*>(b));
#endif
			REQUIRE(td != nullptr);
			CHECK(strncmp(td->m_szName, nameof<SI_Derived>(), 0x1000) == 0);

			delete d;
		}

		// --- MI: Any base subobject must yield MI_D as dynamic type ---
		{
			auto* d = new MI_D();
			REQUIRE(d != nullptr);

			MI_A* asA = d;
#ifdef _M_X64
			auto tdA = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(asA));
#else
			auto tdA = Detours::RTTI::RTtypeid(static_cast<void*>(asA));
#endif
			REQUIRE(tdA != nullptr);
			CHECK(strncmp(tdA->m_szName, nameof<MI_D>(), 0x1000) == 0);

			MI_B* asB = d;
#ifdef _M_X64
			auto tdB = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(asB));
#else
			auto tdB = Detours::RTTI::RTtypeid(static_cast<void*>(asB));
#endif
			REQUIRE(tdB != nullptr);
			CHECK(strncmp(tdB->m_szName, nameof<MI_D>(), 0x1000) == 0);

			delete d;
		}

		// --- VI: Through virtually inherited subobject, dynamic must be VI_D ---
		{
			auto* d = new VI_D();
			REQUIRE(d != nullptr);

			VI_A* asA = d;
#ifdef _M_X64
			auto td = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(asA));
#else
			auto td = Detours::RTTI::RTtypeid(static_cast<void*>(asA));
#endif
			REQUIRE(td != nullptr);
			CHECK(strncmp(td->m_szName, nameof<VI_D>(), 0x1000) == 0);

			delete d;
		}
	}

	TEST_CASE("RTtypeid_nullptr_throws_bad_typeid") {
		// Standard compliance: typeid(*p) with p == nullptr should throw std::bad_typeid.
#ifdef _M_X64
		CHECK_THROWS_AS(Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), (void*)nullptr), std::bad_typeid);
#else
		CHECK_THROWS_AS(Detours::RTTI::RTtypeid((void*)nullptr), std::bad_typeid);
#endif
	}
}

#ifndef _DEBUG
DISABLE_OPTIMIZATION_END("");
}
#endif

TEST_SUITE("Detours::Sync") {

	typedef struct _EVENT_DATA {
		Detours::Sync::Event* m_pEvent;
		unsigned int m_unData;
	} EVENT_DATA, *PEVENT_DATA;

	typedef struct _EVENTCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szEventName[64];
	} EVENTCLIENT_DATA, *PEVENTCLIENT_DATA;

	typedef struct _MUTEX_DATA {
		Detours::Sync::Event* m_pEvent;
		Detours::Sync::Mutex* m_pMutex;
	} MUTEX_DATA, *PMUTEX_DATA;

	typedef struct _MUTEXCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szMutexName[64];
	} MUTEXCLIENT_DATA, *PMUTEXCLIENT_DATA;

	typedef struct _SEMAPHORE_DATA {
		Detours::Sync::Event* m_pEvent;
		Detours::Sync::Semaphore* m_pSemaphore;
	} SEMAPHORE_DATA, *PSEMAPHORE_DATA;

	typedef struct _SEMAPHORECLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szSemaphoreName[64];
	} SEMAPHORECLIENT_DATA, *PSEMAPHORECLIENT_DATA;

	void OnEventThread(void* pData) {
		PEVENT_DATA pED = reinterpret_cast<PEVENT_DATA>(pData);
		if (pED) {
			auto pEvent = pED->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			pED->m_unData = 0xBEEFDEED;
		}
	}

	void OnEventClientThread(void* pData) {
		PEVENTCLIENT_DATA pECD = reinterpret_cast<PEVENTCLIENT_DATA>(pData);
		if (pECD) {
			auto pEvent = pECD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			Detours::Sync::EventClient EventClient(pECD->m_szEventName);
			EventClient.Signal();
		}
	}

	void OnMutexThread(void* pData) {
		PMUTEX_DATA pMD = reinterpret_cast<PMUTEX_DATA>(pData);
		if (pMD) {
			auto pEvent = pMD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			auto pMutex = pMD->m_pMutex;
			if (pMutex) {
				pMutex->UnLock();
			}
		}
	}

	void OnMutexClientThread(void* pData) {
		PMUTEXCLIENT_DATA pMCD = reinterpret_cast<PMUTEXCLIENT_DATA>(pData);
		if (pMCD) {
			auto pEvent = pMCD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			Detours::Sync::MutexClient MutexClient(pMCD->m_szMutexName);
			MutexClient.UnLock();
		}
	}

	void OnSemaphoreThread(void* pData) {
		PSEMAPHORE_DATA pSD = reinterpret_cast<PSEMAPHORE_DATA>(pData);
		if (pSD) {
			auto pEvent = pSD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			auto pSemaphore = pSD->m_pSemaphore;
			if (pSemaphore) {
				pSemaphore->Leave();
			}
		}
	}

	void OnSemaphoreClientThread(void* pData) {
		PSEMAPHORECLIENT_DATA pSCD = reinterpret_cast<PSEMAPHORECLIENT_DATA>(pData);
		if (pSCD) {
			auto pEvent = pSCD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			Detours::Sync::SemaphoreClient SemaphoreClient(pSCD->m_szSemaphoreName);
			SemaphoreClient.Leave();
		}
	}

	TEST_CASE("Event" * doctest::timeout(10)) {
		Detours::Sync::Event Event;

		EVENT_DATA ed;
		ed.m_pEvent = &Event;
		ed.m_unData = 0xDEEDBEEF;

		Detours::Parallel::Thread Thread(OnEventThread, &ed);
		CHECK(Thread.Start() == true);

		CHECK(ed.m_unData == 0xDEEDBEEF);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(ed.m_unData == 0xBEEFDEED);
	}

	TEST_CASE("EventServer and EventClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::EventServer EventServer;

		EVENTCLIENT_DATA ecd;
		ecd.m_pEvent = &Event;

		CHECK(EventServer.GetEventName(ecd.m_szEventName) == true);

		Detours::Parallel::Thread Thread(OnEventClientThread, &ecd);
		CHECK(Thread.Start() == true);

		CHECK(EventServer.Wait(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(EventServer.Wait() == true);
	}

	TEST_CASE("Mutex" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::Mutex Mutex;

		MUTEX_DATA md;
		md.m_pEvent = &Event;
		md.m_pMutex = &Mutex;

		Detours::Parallel::Thread Thread(OnMutexThread, &md);
		CHECK(Thread.Start() == true);

		CHECK(Mutex.Lock() == true);
		CHECK(Mutex.Lock(1000) == true);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(Mutex.Lock() == true);
		CHECK(Mutex.UnLock() == true);
	}

	TEST_CASE("MutexServer and MutexClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::MutexServer MutexServer;

		MUTEXCLIENT_DATA mcd;
		mcd.m_pEvent = &Event;

		CHECK(MutexServer.GetMutexName(mcd.m_szMutexName) == true);

		Detours::Parallel::Thread Thread(OnMutexClientThread, &mcd);
		CHECK(Thread.Start() == true);

		CHECK(MutexServer.Lock() == true);
		CHECK(MutexServer.Lock(1000) == true);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(MutexServer.Lock() == true);
		CHECK(MutexServer.UnLock() == true);
	}

	TEST_CASE("Semaphore" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::Semaphore Semaphore;

		SEMAPHORE_DATA md;
		md.m_pEvent = &Event;
		md.m_pSemaphore = &Semaphore;

		Detours::Parallel::Thread Thread(OnSemaphoreThread, &md);
		CHECK(Thread.Start() == true);

		CHECK(Semaphore.Enter() == true);
		CHECK(Semaphore.Enter(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(Semaphore.Enter() == true);
		CHECK(Semaphore.Leave() == true);
	}

	TEST_CASE("SemaphoreServer and SemaphoreClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::SemaphoreServer SemaphoreServer;

		SEMAPHORECLIENT_DATA mcd;
		mcd.m_pEvent = &Event;

		CHECK(SemaphoreServer.GetSemaphoreName(mcd.m_szSemaphoreName) == true);

		Detours::Parallel::Thread Thread(OnSemaphoreClientThread, &mcd);
		CHECK(Thread.Start() == true);

		CHECK(SemaphoreServer.Enter() == true);
		CHECK(SemaphoreServer.Enter(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(SemaphoreServer.Enter() == true);
		CHECK(SemaphoreServer.Leave() == true);
	}

	TEST_CASE("Suspender") {
		CHECK(Detours::Sync::g_Suspender.Suspend() == true);
		Detours::Sync::g_Suspender.Resume();
	}
}

TEST_SUITE("Detours::Pipe") {

	typedef struct _PIPECLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szPipeName[64];
	} PIPECLIENT_DATA, *PPIPECLIENT_DATA;

	void OnPipeClientThread(void* pData) {
		PPIPECLIENT_DATA pPCD = reinterpret_cast<PPIPECLIENT_DATA>(pData);
		if (pPCD) {
			Detours::Pipe::PipeClient PipeClient(4);
			while (true) {
				if (!PipeClient.Open(pPCD->m_szPipeName)) {
					Sleep(50);
					continue;
				}

				break;
			}

			auto pEvent = pPCD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			DWORD unData = 0xBEEFDEED;
			PipeClient.Send(reinterpret_cast<unsigned char*>(&unData));
			PipeClient.Close();
		}
	}

	TEST_CASE("PipeServer") {
		Detours::Sync::Event Event;
		Detours::Pipe::PipeServer PipeServer(4);

		PIPECLIENT_DATA pcd;
		pcd.m_pEvent = &Event;

		CHECK(PipeServer.GetPipeName(pcd.m_szPipeName) == true);

		Detours::Parallel::Thread Thread(OnPipeClientThread, &pcd);
		CHECK(Thread.Start() == true);

		CHECK(PipeServer.Open() == true);
		CHECK(Event.Signal() == true);
		DWORD unData = 0;
		CHECK(PipeServer.Receive(reinterpret_cast<unsigned char*>(&unData)) == true);
		CHECK(Thread.Join() == true);
		CHECK(unData == 0xBEEFDEED);
	}
}

TEST_SUITE("Detours::Parallel") {

	void OnThread(void* pData) {
		if (pData) {
			*reinterpret_cast<unsigned int*>(pData) = 0xBEEFDEED;
		}
	}

	void OnFiber(void* pData) {
		if (pData) {
			*reinterpret_cast<unsigned int*>(pData) = 0xBEEFDEED;
		}
	}

	TEST_CASE("Thread") {
		unsigned int unData = 0xDEEDBEEF;
		Detours::Parallel::Thread Thread(OnThread, &unData);
		CHECK(Thread.Start() == true);
		CHECK(Thread.Join() == true);
		CHECK(unData == 0xBEEFDEED);
	}

	TEST_CASE("Fiber") {
		unsigned int unData = 0xDEEDBEEF;
		Detours::Parallel::Fiber Fiber(OnFiber, &unData);
		CHECK(Fiber.Switch() == true);
		CHECK(unData == 0xBEEFDEED);
	}
}

TEST_SUITE("Detours::Memory") {

	typedef struct _SHAREDCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szSharedName[64];
	} SHAREDCLIENT_DATA, *PSHAREDCLIENT_DATA;

	void OnSharedClientThread(void* pData) {
		PSHAREDCLIENT_DATA pSCD = reinterpret_cast<PSHAREDCLIENT_DATA>(pData);
		if (pSCD) {
			auto pEvent = pSCD->m_pEvent;
			if (pEvent) {
				if (!pEvent->Wait()) {
					return;
				}
			}

			Detours::Memory::SharedClient SharedClient(pSCD->m_szSharedName);
			auto pAddress = SharedClient.GetAddress();
			if (pAddress) {
				*reinterpret_cast<unsigned int*>(pAddress) = 0xBEEFDEED;
			}
		}
	}

	TEST_CASE("Shared") {
		Detours::Memory::Shared Shared(4);
		CHECK(Shared.GetAddress() != nullptr);
	}

	TEST_CASE("SharedServer") {
		Detours::Sync::Event Event;
		Detours::Memory::SharedServer SharedServer(4);

		SHAREDCLIENT_DATA scd;
		scd.m_pEvent = &Event;

		CHECK(SharedServer.GetAddress() != nullptr);
		CHECK(SharedServer.GetSharedName(scd.m_szSharedName) == true);

		Detours::Parallel::Thread Thread(OnSharedClientThread, &scd);
		CHECK(Thread.Start() == true);

		unsigned int* pData = reinterpret_cast<unsigned int*>(SharedServer.GetAddress());
		*pData = 0;
		CHECK(*pData == 0);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(*pData == 0xBEEFDEED);
	}

	TEST_CASE("Page") {
		Detours::Memory::Page Page;
		CHECK(Page.Alloc(Page.GetPageCapacity()) != nullptr);
		CHECK(Page.Alloc(1) == nullptr);
		CHECK(Page.Alloc(1, 2) == nullptr);
		CHECK(Page.Alloc(1, 4) == nullptr);
		CHECK(Page.Alloc(1, 8) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity(), 8) != nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity(), Page.GetPageCapacity() * 2) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity() - 1) != nullptr);
		CHECK(Page.Alloc(1, 0, 0) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity() - 1) != nullptr);
		CHECK(Page.Alloc(1, 2) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity() - 2) != nullptr);
		CHECK(Page.Alloc(1, 2, 2) != nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity() - 2) != nullptr);
		CHECK(Page.Alloc(1, 4) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity() - 2) != nullptr);
		CHECK(Page.Alloc(2, 8) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(Page.GetPageCapacity(), 1, 1) != nullptr);
		CHECK(Page.Alloc(Page.GetPageCapacity() + 1, 1, 1) == nullptr);
		Page.DeAllocAll();
		Page.DeAllocAll();
		CHECK(Page.Alloc(0) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(1, 4, 8) != nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(1, 8, 4) != nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(0, 4, 4) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(1, 4, 0) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(1, 0, 4) == nullptr);
		Page.DeAllocAll();
		CHECK(Page.Alloc(1, 0, 0) == nullptr);
	}

	TEST_CASE("Region") {
		Detours::Memory::Region Region;
		CHECK(Region.Alloc(Region.GetRegionCapacity()) != nullptr);
		CHECK(Region.Alloc(1) == nullptr);
		CHECK(Region.Alloc(1, 2) == nullptr);
		CHECK(Region.Alloc(1, 4) == nullptr);
		CHECK(Region.Alloc(1, 8) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity(), 8) != nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity(), Region.GetRegionCapacity() * 2) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity() - 1) != nullptr);
		CHECK(Region.Alloc(1, 0, 0) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity() - 1) != nullptr);
		CHECK(Region.Alloc(1, 2) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity() - 2) != nullptr);
		CHECK(Region.Alloc(1, 2, 2) != nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity() - 2) != nullptr);
		CHECK(Region.Alloc(1, 4) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity() - 2) != nullptr);
		CHECK(Region.Alloc(2, 8) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(Region.GetRegionCapacity(), 1, 1) != nullptr);
		CHECK(Region.Alloc(Region.GetRegionCapacity() + 1, 1, 1) == nullptr);
		Region.DeAllocAll();
		Region.DeAllocAll();
		CHECK(Region.Alloc(0) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(1, 4, 8) != nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(1, 8, 4) != nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(0, 4, 4) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(1, 4, 0) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(1, 0, 4) == nullptr);
		Region.DeAllocAll();
		CHECK(Region.Alloc(1, 0, 0) == nullptr);
	}

	TEST_CASE("Storage") {
		Detours::Memory::Storage Storage;
		unsigned char* pCodeMemory = reinterpret_cast<unsigned char*>(Storage.Alloc(3));
		CHECK(pCodeMemory != nullptr);
		Detours::Memory::Protection CodeMemoryProtection(pCodeMemory, 3, false);
		CHECK(CodeMemoryProtection.Change(PAGE_READWRITE) == true);
		pCodeMemory[0] = 0xB0;
		pCodeMemory[1] = 0x01;
		pCodeMemory[2] = 0xC3;
		CHECK(CodeMemoryProtection.Change(PAGE_EXECUTE_READ) == true);
		using fnType = bool(__cdecl*)();
		CHECK(reinterpret_cast<fnType>(pCodeMemory)() == true);
		CHECK(Storage.DeAlloc(pCodeMemory) == true);
	}
}

TEST_SUITE("Detours::Exception") {

	bool OnException(const EXCEPTION_RECORD & Exception, const PCONTEXT pCTX) {
		if (Exception.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
			return false;
		}

		const ULONG_PTR unAccessType = Exception.ExceptionInformation[0];
		if (unAccessType != 0) {
			return false;
		}

		const void* pAccessAddress = reinterpret_cast<void*>(Exception.ExceptionInformation[1]);
		if (pAccessAddress != reinterpret_cast<void*>(-1)) {
			return false;
		}

		unsigned char* pCode = reinterpret_cast<unsigned char*>(Exception.ExceptionAddress);
		if (pCode[0] != 0xCD) {
			return false;
		}

		const unsigned char unInterrupt = pCode[1];

		_tprintf_s(_T("[OnException] Called `int 0x%02X`\n"), unInterrupt);
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
		pCTX->Rax = 0xDEEDBEEF;
#elif _M_IX86
		pCTX->Eip += 2;
		pCTX->Eax = 0xDEEDBEEF;
#endif

		return true;
	}

	TEST_CASE("g_ExceptionListener") { // TODO: Incorrect return from CallInterrupt on 64 bit.
		CHECK(Detours::Exception::g_ExceptionListener.AddCallBack(OnException) == true);
#ifdef _M_X64
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 0xDEEDBEEF);
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 0xDEEDBEEF);
#elif _M_IX86
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7) == 0xDEEDBEEF);
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7) == 0xDEEDBEEF);
#endif
		CHECK(Detours::Exception::g_ExceptionListener.RemoveCallBack(OnException) == true);

	}
}

TEST_SUITE("Detours::rddisasm") {
	TEST_CASE("RdDecode") {
		Detours::rddisasm::INSTRUCTION ins;
		unsigned char pCode[3] = { 0xB0, 0x01 }; // mov al, 1
#ifdef _M_X64
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pCode), RD_DATA_64, RD_DATA_64)) == true);
#elif _M_IX86
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pCode), RD_DATA_32, RD_DATA_32)) == true);
#endif

		CHECK(ins.Length == 2);
		CHECK(ins.Instruction == Detours::rddisasm::RD_INS_CLASS::RD_INS_MOV);
	}
}

TEST_SUITE("Detours::Hook") {

	typedef bool(__fastcall* fnFooOriginal)(void* pThis, void* /* unused */);
	typedef bool(__fastcall* fnBooOriginal)(void* pThis, void* /* unused */);

	void HardwareHook(const PCONTEXT pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		_tprintf_s(_T("[HardwareHook] Mem access! TID=%lu\n"), GetCurrentThreadId());
	}

	void HardwareSelfUnHook(const PCONTEXT pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		_tprintf_s(_T("[HardwareSelfUnHook] Mem access! TID=%lu\n"), GetCurrentThreadId());

		Detours::Hook::UnHookHardware(GetCurrentThreadId(), Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
	}

	DWORD WINAPI ThreadAccesser(LPVOID lpParameter) {
		reinterpret_cast<unsigned int*>(lpParameter)[0] = 4;
		return 0;
	}

	DWORD WINAPI ThreadAccesserLoop(LPVOID lpParameter) {
		while ((rand() % 100) != 99) {
			for (unsigned int i = 0; i < 1'000'000; ++i) {
				_mm_pause();
			}

			reinterpret_cast<unsigned int*>(lpParameter)[0] = 4;
		}

		return 0;
	}

	DWORD WINAPI ThreadAccesser2(LPVOID lpParameter) {
		reinterpret_cast<unsigned int*>(lpParameter)[0] = 0xDEEDBEEF;
		reinterpret_cast<unsigned int*>(lpParameter)[1] = 0xDEEDFACE;
		reinterpret_cast<unsigned int*>(lpParameter)[2] = 0xFACE;
		return 0;
	}

	DWORD WINAPI ThreadAccesser2Loop(LPVOID lpParameter) {
		while ((rand() % 100) != 99) {
			for (unsigned int i = 0; i < 1'000'000; ++i) {
				_mm_pause();
			}

			reinterpret_cast<unsigned int*>(lpParameter)[0] = 0xDEEDBEEF;
			reinterpret_cast<unsigned int*>(lpParameter)[1] = 0xDEEDFACE;
			reinterpret_cast<unsigned int*>(lpParameter)[2] = 0xFACE;
		}

		return 0;
	}

	void MemoryHook(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[MemoryHook] Mem access! TID=%lu Addr=%p\n"), GetCurrentThreadId(), pAccessAddress);
	}

	void PostMemoryHook(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[PostMemoryHook] Mem access! TID=%lu Addr=%p\n"), GetCurrentThreadId(), pAccessAddress);
	}

	void MemoryHookSelfUnHook(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[MemoryHookSelfUnHook] Mem access! TID=%lu\n"), GetCurrentThreadId());

		Detours::Hook::UnHookMemory(MemoryHookSelfUnHook, const_cast<void*>(pHookAddress));
	}

	void MemoryHookSelfUnHook2(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[MemoryHookSelfUnHook2] Mem access! TID=%lu\n"), GetCurrentThreadId());

		Detours::Hook::UnHookMemory(MemoryHookSelfUnHook2, const_cast<void*>(pHookAddress));
	}

	void MemoryHookModify(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[MemoryHookModify] Mem access! TID=%lu\n"), GetCurrentThreadId());

		static int unDummy = 0;

#ifdef _M_X64
		pCTX->Rax = reinterpret_cast<DWORD64>(&unDummy);
#elif _M_IX86
		pCTX->Eax = reinterpret_cast<DWORD>(&unDummy);
#endif

		Detours::Hook::UnHookMemory(MemoryHookModify, const_cast<void*>(pHookAddress));
	}

	void MemoryHookModify2(const PCONTEXT pCTX, const void* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, const void* pHookAddress, const void* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);
		UNREFERENCED_PARAMETER(pAccessAddress);

		_tprintf_s(_T("[MemoryHookModify2] Mem access! TID=%lu\n"), GetCurrentThreadId());

		static int unDummy = 0;

#ifdef _M_X64
		pCTX->Rax = reinterpret_cast<DWORD64>(&unDummy);
#elif _M_IX86
		pCTX->Eax = reinterpret_cast<DWORD>(&unDummy);
#endif
	}

	bool InterruptHook(const PCONTEXT pCTX, const unsigned char unInterrupt) {
		_tprintf_s(_T("[InterruptHook] Called `int 0x%02X`\n"), unInterrupt);
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
		pCTX->Rax = 0xDEEDBEEF;
#elif _M_IX86
		pCTX->Eax = 0xDEEDBEEF;
#endif

		return true;
	}

	Detours::Hook::VTableFunctionHook fooHook;
	bool __fastcall foo_Hook(void* pThis, void* /* unused */) {
		using fnType = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnType>(fooHook.GetOriginal())(pThis, nullptr);
	}

	Detours::Hook::VTableFunctionHook booHook;
	bool __fastcall boo_Hook(void* pThis, void* /* unused */) {
		using fnType = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnType>(booHook.GetOriginal())(pThis, nullptr);
	}

	Detours::Hook::VTableHook NewTestingRTTIVTable;
	bool __fastcall boo_Hook2(void* pThis, void* /* unused */) {
		using fnType = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnType>(NewTestingRTTIVTable.GetHookingFunctions()[1]->GetOriginal())(pThis, nullptr);
	}

	bool g_bInlineSleepHookCalled = false;
	Detours::Hook::InlineWrapperHook InlineSleepHook;
	void WINAPI Sleep_Hook(DWORD dwMilliseconds) {
		g_bInlineSleepHookCalled = true;
		using fnType = void(WINAPI*)(DWORD);
		return reinterpret_cast<fnType>(InlineSleepHook.GetTrampoline())(dwMilliseconds);
	}

	bool g_bRawSleepHookCalled = false;
	Detours::Hook::RawHook RawSleepHook;
#ifdef _M_X64
	bool __fastcall Sleep_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
	bool __cdecl Sleep_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_bRawSleepHookCalled = true;

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
		g_bRawSleepHookCalled = true;

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
		pCTX->Stack.push(new_foo);
#elif _M_IX86
		void* pReturnAddress = pCTX->Stack.pop();
		pCTX->Stack.push(pCTX->m_unECX);
		pCTX->Stack.push(pReturnAddress);
		pCTX->Stack.push(new_foo);
#endif

		return true;
	}

	Detours::Hook::RawHook RawCPUIDHook;
#ifdef _M_X64
	bool __fastcall CPUID_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
	bool __cdecl CPUID_RawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif

		pCTX->m_unEAX = 0x00000001;
		pCTX->m_unEBX = 0x11223344;
		pCTX->m_unECX = 0x00000003;
		pCTX->m_unEDX = 0x00000004;
		pCTX->Stack.push(reinterpret_cast<char*>(RawCPUIDHook.GetTrampoline()) + RawCPUIDHook.GetFirstInstructionSize());

		return true;
	}

	TEST_CASE("HardwareHook 1") {
		static int pArray[] = {
			1, 2, 3, 4, 5
		};

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		DWORD unCurrentTID = GetCurrentThreadId();
		CHECK(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);

		DWORD unTID = 0;
		HANDLE hThread = CreateThread(nullptr, NULL, ThreadAccesser, &reinterpret_cast<unsigned int*>(pArray)[3], CREATE_SUSPENDED, &unTID);
		CHECK(hThread != nullptr);
		CHECK(hThread != INVALID_HANDLE_VALUE);
		CHECK(Detours::Hook::HookHardware(unTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		ResumeThread(hThread);

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);

		CHECK(Detours::Hook::UnHookHardware(unTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);
		CHECK(Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);
	}

	TEST_CASE("HardwareHook 2") {
		static int pArray[] = {
			1, 2, 3, 4, 5
		};

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		DWORD unCurrentTID = GetCurrentThreadId();
		CHECK(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);

		DWORD unTID1 = 0;
		HANDLE hThread1 = CreateThread(nullptr, NULL, ThreadAccesserLoop, &reinterpret_cast<unsigned int*>(pArray)[3], CREATE_SUSPENDED, &unTID1);
		DWORD unTID2 = 0;
		HANDLE hThread2 = CreateThread(nullptr, NULL, ThreadAccesserLoop, &reinterpret_cast<unsigned int*>(pArray)[3], CREATE_SUSPENDED, &unTID2);
		CHECK(hThread1 != nullptr);
		CHECK(hThread1 != INVALID_HANDLE_VALUE);
		CHECK(hThread2 != nullptr);
		CHECK(hThread2 != INVALID_HANDLE_VALUE);
		CHECK(Detours::Hook::HookHardware(unTID1, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);
		CHECK(Detours::Hook::HookHardware(unTID2, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		ResumeThread(hThread1);
		ResumeThread(hThread2);

		WaitForSingleObject(hThread1, INFINITE);
		WaitForSingleObject(hThread2, INFINITE);

		CloseHandle(hThread1);
		CloseHandle(hThread2);

		CHECK(Detours::Hook::UnHookHardware(unTID2, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);
		CHECK(Detours::Hook::UnHookHardware(unTID1, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);
		CHECK(Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);
	}

	TEST_CASE("HardwareHook 3") {
		static int pArray[] = {
			1, 2, 3, 4, 5
		};

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		DWORD unCurrentTID = GetCurrentThreadId();
		CHECK(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareSelfUnHook, &reinterpret_cast<unsigned int*>(pArray)[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, 4) == true);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);
	}

	TEST_CASE("MemoryHook 1") {
		Detours::Memory::Page Page(nullptr);
		CHECK(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 3);

		int* pArray = reinterpret_cast<int*>(pAddress);

		HANDLE hThread = CreateThread(nullptr, NULL, ThreadAccesser2, pArray, CREATE_SUSPENDED, nullptr);
		CHECK(hThread != nullptr);
		CHECK(hThread != INVALID_HANDLE_VALUE);

		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(int) * 3, PostMemoryHook) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(int) * 3) == false);

		pArray[0] = 0xDEEDBEEF;
		pArray[1] = 0xDEEDFACE;
		pArray[2] = 0xFACE;

		ResumeThread(hThread);

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);

		CHECK(pArray[0] == 0xDEEDBEEF);
		CHECK(pArray[1] == 0xDEEDFACE);
		CHECK(pArray[2] == 0xFACE);

		CHECK(Detours::Hook::UnHookMemory(MemoryHook, pArray) == true);
	}

	TEST_CASE("MemoryHook 2") {
		Detours::Memory::Page Page(nullptr);
		CHECK(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 3);

		int* pArray = reinterpret_cast<int*>(pAddress);

		HANDLE hThread1 = CreateThread(nullptr, NULL, ThreadAccesser2Loop, pArray, CREATE_SUSPENDED, nullptr);
		HANDLE hThread2 = CreateThread(nullptr, NULL, ThreadAccesser2Loop, pArray, CREATE_SUSPENDED, nullptr);
		CHECK(hThread1 != nullptr);
		CHECK(hThread1 != INVALID_HANDLE_VALUE);
		CHECK(hThread2 != nullptr);
		CHECK(hThread2 != INVALID_HANDLE_VALUE);

		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(int) * 3, PostMemoryHook) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(int) * 3) == false);

		pArray[0] = 0xDEEDBEEF;
		pArray[1] = 0xDEEDFACE;
		pArray[2] = 0xFACE;

		ResumeThread(hThread1);
		ResumeThread(hThread2);

		WaitForSingleObject(hThread1, INFINITE);
		WaitForSingleObject(hThread2, INFINITE);

		CloseHandle(hThread1);
		CloseHandle(hThread2);

		CHECK(pArray[0] == 0xDEEDBEEF);
		CHECK(pArray[1] == 0xDEEDFACE);
		CHECK(pArray[2] == 0xFACE);

		CHECK(Detours::Hook::UnHookMemory(MemoryHook, pArray) == true);
	}

	TEST_CASE("MemoryHook 3") {
		Detours::Memory::Page Page(nullptr);
		CHECK(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 5);

		int* pArray = reinterpret_cast<int*>(pAddress);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == false);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);
	}

	TEST_CASE("MemoryHook [benchmark]" * doctest::skip(true)) {
		Detours::Memory::Region Region(nullptr, static_cast<size_t>(0x800000));
		CHECK(Region.GetRegionAddress() != nullptr);
		void* pAddress = Region.Alloc(1);
		CHECK(pAddress != nullptr);
		srand(time(nullptr) & 0xffffffff);
		ULONG unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (size_t i = 0; i < 1'000'000; ++i) {
			reinterpret_cast<unsigned char*>(pAddress)[0] = 1;
		}
		MESSAGE("Benckmark with 1 000 000 iterations (without hook): ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		CHECK(Detours::Hook::HookMemory(MemoryHook, Region.GetRegionAddress(), Region.GetRegionCapacity(), PostMemoryHook) == true);
		unBegin = Detours::KUserSharedData.SystemTime.LowPart;
		for (size_t i = 0; i < 1'000'000; ++i) {
			reinterpret_cast<unsigned char*>(pAddress)[0] = 2;
		}
		MESSAGE("Benckmark with 1 000 000 iterations (with hook): ", (Detours::KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		CHECK(Detours::Hook::UnHookMemory(MemoryHook, Region.GetRegionAddress()) == true);
	}

	TEST_CASE("MemoryHook 4") {
		Detours::Memory::Page Page(nullptr);
		CHECK(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 6);

		int* pArray = reinterpret_cast<int*>(pAddress);

		TryRead(&pArray[0]);
		TryRead(&pArray[3]);

		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook2, pArray + 3, sizeof(int) * 3) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray + 3, sizeof(int) * 3) == false);

		TryRead(&pArray[0]);
		TryRead(&pArray[3]);

		TryRead(&pArray[0]);
		TryRead(&pArray[3]);
	}

	TEST_CASE("MemoryHook 5") {
		CHECK(Detours::Hook::HookMemory(MemoryHookModify, reinterpret_cast<void*>(0x4), sizeof(int), nullptr, true) == true);

		TryRead(reinterpret_cast<void*>(0x4));
	}

	TEST_CASE("MemoryHook 6") {
		SYSTEM_INFO si = {};
		GetSystemInfo(&si);
		const size_t kPageSize = si.dwPageSize;

		Detours::Memory::Page page(nullptr);
		REQUIRE(page.GetPageAddress() != nullptr);

		int* pArray = reinterpret_cast<int*>(page.GetPageAddress());

		MEMORY_BASIC_INFORMATION mbiHere{}, mbiPrev{};
		REQUIRE(VirtualQuery(pArray, &mbiHere, sizeof(mbiHere)) == sizeof(mbiHere));
		REQUIRE(mbiHere.State == MEM_COMMIT);

		void* prevByte = reinterpret_cast<BYTE*>(pArray) - 1;
		REQUIRE(VirtualQuery(prevByte, &mbiPrev, sizeof(mbiPrev)) == sizeof(mbiPrev));

		bool usedFallback = false;
		void* region = nullptr;

		if (mbiPrev.State == MEM_COMMIT) {
			region = VirtualAlloc(nullptr, 2 * kPageSize, MEM_RESERVE, PAGE_READWRITE);
			REQUIRE(region != nullptr);

			void* commit = VirtualAlloc(static_cast<BYTE*>(region) + kPageSize,
				kPageSize, MEM_COMMIT, PAGE_READWRITE);
			REQUIRE(commit != nullptr);

			pArray = static_cast<int*>(commit);

			REQUIRE(VirtualQuery(pArray, &mbiHere, sizeof(mbiHere)) == sizeof(mbiHere));
			REQUIRE(mbiHere.State == MEM_COMMIT);

			prevByte = static_cast<BYTE*>(commit) - 1;
			REQUIRE(VirtualQuery(prevByte, &mbiPrev, sizeof(mbiPrev)) == sizeof(mbiPrev));
			REQUIRE(mbiPrev.State != MEM_COMMIT);
			usedFallback = true;
		} else {
			REQUIRE(mbiPrev.State != MEM_COMMIT);
		}

		CHECK(Detours::Hook::HookMemory(
			MemoryHookModify2,
			reinterpret_cast<BYTE*>(pArray) - sizeof(int),
			sizeof(int),
			nullptr,
			true) == true);

		CHECK(Detours::Hook::HookMemory(
			MemoryHookModify2,
			pArray,
			sizeof(int),
			nullptr,
			false) == true);

		TryRead(reinterpret_cast<BYTE*>(pArray) - sizeof(int));
		TryRead(pArray);

		CHECK(Detours::Hook::UnHookMemory(MemoryHookModify2, pArray) == true);
		CHECK(Detours::Hook::UnHookMemory(MemoryHookModify2, reinterpret_cast<BYTE*>(pArray) - sizeof(int)) == true);

		if (usedFallback) {
			VirtualFree(region, 0, MEM_RELEASE);
		}
	}

	TEST_CASE("InterruptHook") {
		CHECK(Detours::Hook::HookInterrupt(InterruptHook, 0x7E) == true);
#ifdef _M_X64
		unsigned long long unRAX = CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		CallInterrupt(unRAX, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#elif _M_IX86
		unsigned int unEAX = CallInterrupt(1, 2, 3, 4, 5, 6, 7);
		CallInterrupt(unEAX, 2, 3, 4, 5, 6, 7);
#endif
		CHECK(Detours::Hook::UnHookInterrupt(InterruptHook) == true);
	}

#pragma optimize("", off)

	TEST_CASE("VTableFunctionHook") {
		g_pBaseTestingRTTI = new BaseTestingRTTI();
		CHECK(g_pBaseTestingRTTI != nullptr);

		g_pTestingRTTI = new TestingRTTI();
		CHECK(g_pTestingRTTI != nullptr);

		const auto& pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		CHECK(pObject != nullptr);
		auto pVTable = pObject->GetVTable();
		CHECK(pVTable != nullptr);
		using fnFoo = bool(__fastcall*)(void* pThis, void*);
		using fnBoo = bool(__fastcall*)(void* pThis, void*);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);

		CHECK(fooHook.Set(pVTable, 0) == true);
		CHECK(fooHook.Hook(foo_Hook) == true);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == false);
		CHECK(fooHook.UnHook() == true);
		CHECK(fooHook.Release() == true);

		CHECK(booHook.Set(pVTable, 1) == true);
		CHECK(booHook.Hook(boo_Hook) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == true);
		CHECK(booHook.UnHook() == true);
		CHECK(booHook.Release() == true);

		delete g_pTestingRTTI;
		delete g_pBaseTestingRTTI;
	}

	TEST_CASE("VTableHook") {
		g_pBaseTestingRTTI = new BaseTestingRTTI();
		CHECK(g_pBaseTestingRTTI != nullptr);

		g_pTestingRTTI = new TestingRTTI();
		CHECK(g_pTestingRTTI != nullptr);

		const auto& pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		CHECK(pObject != nullptr);
		auto pVTable = pObject->GetVTable();
		CHECK(pVTable != nullptr);
		using fnFoo = bool(__fastcall*)(void* pThis, void*);
		using fnBoo = bool(__fastcall*)(void* pThis, void*);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);

		void* pNewVTable[2] = {
			nullptr, // Will be skipped
			reinterpret_cast<void*>(boo_Hook2)
		};

		CHECK(NewTestingRTTIVTable.Set(pVTable, 2) == true);
		CHECK(NewTestingRTTIVTable.Hook(pNewVTable) == true);

		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == true);

		CHECK(NewTestingRTTIVTable.UnHook() == true);
		CHECK(NewTestingRTTIVTable.Release() == true);

		delete g_pTestingRTTI;
		delete g_pBaseTestingRTTI;
	}

#pragma optimize("", on)

	TEST_CASE("InlineWrapperHook") {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		CHECK(hKernel32 != nullptr);
		CHECK(hKernel32 != INVALID_HANDLE_VALUE);
		CHECK(InlineSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))) == true);
		CHECK(InlineSleepHook.Hook(reinterpret_cast<void*>(Sleep_Hook), true) == true);
		CHECK(g_bInlineSleepHookCalled == false);
		Sleep(1000);
		CHECK(g_bInlineSleepHookCalled == true);
		CHECK(InlineSleepHook.UnHook() == true);
		CHECK(InlineSleepHook.Release() == true);
	}

	TEST_CASE("RawHook") {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		CHECK(hKernel32 != nullptr);
		CHECK(hKernel32 != INVALID_HANDLE_VALUE);
		CHECK(RawSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))) == true);
		CHECK(RawSleepHook.Hook(Sleep_RawHook, false, 0x16, true) == true);
		CHECK(g_bRawSleepHookCalled == false);
		Sleep(1000);
		CHECK(g_bRawSleepHookCalled == true);
		CHECK(RawSleepHook.UnHook() == true);
		CHECK(RawSleepHook.Release() == true);
	}

	TEST_CASE("RawHook 2") {
		g_bRawSleepHookCalled = false;

		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		CHECK(hKernel32 != nullptr);
		CHECK(hKernel32 != INVALID_HANDLE_VALUE);
		CHECK(RawSleepHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))) == true);
		CHECK(RawSleepHook.Hook(Sleep_RawHookMod, false, 0x16, true) == true);
		CHECK(g_bRawSleepHookCalled == false);
		CHECK(g_LastXMM7.m_un64[0] == 0);
		CHECK(g_LastXMM7.m_un64[1] == 0);
		Sleep(1000); // Will record last XMM7 value and change it
		Sleep(1000); // Will record last XMM7 value and change it
		CHECK(g_LastXMM7.m_un64[0] == 0x1122334455667788);
		CHECK(g_LastXMM7.m_un64[1] == 0x1122334455667788);
		CHECK(g_bRawSleepHookCalled == true);
		CHECK(RawSleepHook.UnHook() == true);
		CHECK(RawSleepHook.Release() == true);
	}

#pragma optimize("", off)

	TEST_CASE("RawHook 3") {
		g_pBaseTestingRTTI = new BaseTestingRTTI();
		CHECK(g_pBaseTestingRTTI != nullptr);

		g_pTestingRTTI = new TestingRTTI();
		CHECK(g_pTestingRTTI != nullptr);

		const auto& pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		CHECK(pObject != nullptr);

		auto pVTable = pObject->GetVTable();
		CHECK(pVTable != nullptr);

		CHECK(RawHook_CallConv_Convert.Set(pVTable[0]) == true);
		CHECK(RawHook_CallConv_Convert.Hook(CallConv_Convert_RawHook, true, 0x10, true) == true);
		CHECK(g_pTestingRTTI->foo() == false);
		CHECK(RawHook_CallConv_Convert.UnHook() == true);
		CHECK(RawHook_CallConv_Convert.Release() == true);

		delete g_pBaseTestingRTTI;
		delete g_pTestingRTTI;
	}

#pragma optimize("", on)

	unsigned int DemoFunction() { SELF_EXPORT("DemoFunction");
		int cpuinfo[4];
		__cpuidex(cpuinfo, 7, 0);
		_tprintf_s(_T("cpuinfo[0] = 0x%08X\n"), cpuinfo[0]);
		_tprintf_s(_T("cpuinfo[1] = 0x%08X\n"), cpuinfo[1]);
		_tprintf_s(_T("cpuinfo[2] = 0x%08X\n"), cpuinfo[2]);
		_tprintf_s(_T("cpuinfo[3] = 0x%08X\n"), cpuinfo[3]);
		return cpuinfo[1];
	}

	TEST_CASE("RawHook 4") {
		Detours::rddisasm::INSTRUCTION ins;
		size_t unOffset = 0;
		void* pFoundCPUID = nullptr;
#ifdef _DEBUG
		void* pStartAddress = Detours::rddisasm::RdGetAddressFromRelOrDisp(DemoFunction);
		if (!pStartAddress) {
			FAIL("Can't resolve JMP address from JMP table.");
		}
#else
		void* pStartAddress = DemoFunction;
#endif
		while (unOffset < 0xFF) {
#ifdef _M_X64
			if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pStartAddress) + unOffset, RD_DATA_64, RD_DATA_64))) {
#elif _M_IX86
			if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pStartAddress) + unOffset, RD_DATA_32, RD_DATA_32))) {
#endif
				return;
			}

			if (ins.Instruction == Detours::rddisasm::RD_INS_CLASS::RD_INS_CPUID) {
				_tprintf_s(_T("Found `cpuid` instruction!\n"));
				pFoundCPUID = reinterpret_cast<void*>(reinterpret_cast<char*>(pStartAddress) + unOffset);
				break;
			}

			unOffset += ins.Length;
		}

		if (!pFoundCPUID) {
			FAIL("Failed to find `cpuid` in DemoFunction.");
		}

		CHECK(RawCPUIDHook.Set(pFoundCPUID) == true);
		CHECK(DemoFunction() != 0x11223344);
		CHECK(RawCPUIDHook.Hook(CPUID_RawHook, true, 0x8, true) == true);
		CHECK(DemoFunction() == 0x11223344);
		CHECK(RawCPUIDHook.UnHook() == true);
		CHECK(RawCPUIDHook.Release() == true);
	}
}

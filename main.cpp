
// Platform
#if defined(_WIN32)
#include <Windows.h>
#include <tchar.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#endif

// Advanced
#if defined(_WIN32)
#include <intrin.h>
#endif

// C++
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <typeinfo>
#include <unordered_map>
#include <vector>

// Detours
#include "Detours.h"

// doctest
#undef min
#undef max
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#if defined(__linux__)
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#endif
#include "doctest.h"

#if defined(_WIN32)

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
	virtual bool foo() {
		return false;
	}

	virtual bool boo() {
		return true;
	}
};

class TestingRTTI : public BaseTestingRTTI {
public:
	TestingRTTI() {
		m_bFoo = true;
		m_bBoo = false;
	}

	bool foo() override {
		return m_bFoo;
	}

	bool boo() override {
		return m_bBoo;
	}

private:
	bool m_bFoo;
	bool m_bBoo;
};

struct SI_Base {
	virtual ~SI_Base() {}

	virtual int id() {
		return 1;
	}

	virtual bool base_only() {
		return true;
	}
};

struct SI_Derived : SI_Base {
	~SI_Derived() override {}

	int id() override {
		return 2;
	}

	bool base_only() override {
		return false;
	}
};

struct MI_A {
	virtual ~MI_A() {}

	virtual int a() {
		return 10;
	}
};

struct MI_B {
	virtual ~MI_B() {}

	virtual int b() {
		return 20;
	}
};

struct MI_D : MI_A, MI_B {
	~MI_D() override {}

	int a() override {
		return 11;
	}

	int b() override {
		return 21;
	}
};

struct VI_V {
	virtual ~VI_V() {}

	virtual const char* v() {
		return "V";
	}
};

struct VI_A : virtual VI_V {
	~VI_A() override {}

	const char* v() override {
		return "A";
	}
};

struct VI_B : virtual VI_V {
	~VI_B() override {}

	const char* v() override {
		return "B";
	}
};

struct VI_D : VI_A, VI_B {
	~VI_D() override {}

	const char* v() override {
		return "D";
	}
};

struct PrivBase {
	virtual ~PrivBase() {}

	virtual int tag() {
		return 777;
	}
};

struct PrivDerived : private PrivBase {
public:
	~PrivDerived() override {}

	PrivBase* AsBase() {
		return static_cast<PrivBase*>(this);
	}

	int tag() override {
		return 888;
	}
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
#pragma warning(disable : 6001)

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

	TEST_CASE("Decode validates input and preserves ignored bytes") {
		char szData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::Decode(_T("412A42"), reinterpret_cast<void*>(szData), 0x2A) == true);
		CHECK(memcmp(szData, "AyB", sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::Decode(_T("A"), reinterpret_cast<void*>(szData), 0x2A) == false);
		CHECK(Detours::Hexadecimal::Decode(_T("GG"), reinterpret_cast<void*>(szData), 0x2A) == false);
	}
}

TEST_SUITE("Detours::Scan") {
	TEST_CASE("FindSection") {
		void* pSection = nullptr;
		size_t unSectionSize = 0;
		CHECK(Detours::Scan::FindSection(GetModuleHandle(nullptr), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize) == true);
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

		unsigned char pLeakTestEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

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

	TEST_CASE("FindSignatureNative [benckmark]" * doctest::timeout(30)) {
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

	TEST_CASE("FindSignatureSSE2 [benckmark]" * doctest::timeout(15)) {
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

		unsigned char pLeakTestEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(pLeakTestEmptyArray, sizeof(pLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

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

	TEST_CASE("FindDataNative [benckmark]" * doctest::timeout(30)) {
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

	TEST_CASE("FindDataSSE2 [benckmark]" * doctest::timeout(15)) {
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
			auto baseObj = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Base>(), nullptr, /*bCompleteObject*/ false);
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
			auto d_offA = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(offA));
			CHECK(d_offA != nullptr);
			CHECK(d_offA->GetVTable() != nullptr);

			// Wrong offset should not match.
			auto d_wrong = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(offB + 4));
			CHECK(d_wrong == nullptr);

			// Correct offset for B must also match.
			auto d_offB = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(offB));
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

			PrivBase* pb = d->AsBase();                               // returns pointer to private base subobject
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

			auto partial = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/ false);
			CHECK(partial != nullptr);

			auto complete = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/ true, /*unOffset*/ 0);
			CHECK(complete != nullptr);

			auto wrong = Detours::RTTI::FindObject(GetModuleHandle(nullptr), nameof<SI_Derived>(), nameof<SI_Base>(), /*bCompleteObject*/ true, /*unOffset*/ 4);
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
		Detours::Sync::SuspendTransaction Transaction(Detours::Sync::g_Suspender);
		CHECK(static_cast<bool>(Transaction) == true);
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
	constexpr size_t kProcessScannerChunkSize = 1024 * 1024;

	typedef struct _TEST_PROCESS_SCAN_RESULT {
		_TEST_PROCESS_SCAN_RESULT() {
			m_bCompleted = false;
			m_unBytesScanned = 0;
			m_unReadFailures = 0;
		}

		bool m_bCompleted;
		size_t m_unBytesScanned;
		size_t m_unReadFailures;
		std::vector<void*> m_vecMatches;
	} TEST_PROCESS_SCAN_RESULT, *PTEST_PROCESS_SCAN_RESULT;

	typedef struct _SHAREDCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szSharedName[64];
	} SHAREDCLIENT_DATA, *PSHAREDCLIENT_DATA;

	class TestProcessScanner {
	public:
		explicit TestProcessScanner(HANDLE hProcess = GetCurrentProcess()) {
			m_hProcess = hProcess;
		}

	public:
		bool Find(const void* pData, size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, const void* pBeginAddress = nullptr, size_t unRangeSize = 0) const;

	private:
		HANDLE m_hProcess;
	};

	void CollectProcessScannerMatches(
	    const unsigned char* pBuffer,
	    size_t unBufferSize,
	    const unsigned char* pData,
	    size_t unDataSize,
	    size_t unBaseAddress,
	    size_t unCandidateCount,
	    std::vector<void*>& vecMatches) {
		if (!pBuffer || !pData || !unDataSize || (unBufferSize < unDataSize)) {
			return;
		}

		const size_t unAvailableCandidates = unBufferSize - unDataSize + 1;
		const size_t unCandidates = std::min(unCandidateCount, unAvailableCandidates);
		for (size_t unIndex = 0; unIndex < unCandidates; ++unIndex) {
			if (std::memcmp(pBuffer + unIndex, pData, unDataSize) == 0) {
				vecMatches.push_back(reinterpret_cast<void*>(unBaseAddress + unIndex));
			}
		}
	}

	size_t CollectProcessScannerChunk(
	    std::vector<unsigned char> & vecBuffer,
	    size_t unCarrySize,
	    size_t unBytesRead,
	    const unsigned char* pData,
	    size_t unDataSize,
	    size_t unReadAddress,
	    std::vector<void*>& vecMatches) {
		if (!unBytesRead) {
			return unCarrySize;
		}

		const size_t unBufferSize = unCarrySize + unBytesRead;
		CollectProcessScannerMatches(vecBuffer.data(), unBufferSize, pData, unDataSize, unReadAddress - unCarrySize, unBytesRead, vecMatches);

		const size_t unNewCarrySize = std::min(unDataSize - 1, unBufferSize);
		if (unNewCarrySize) {
			std::memmove(vecBuffer.data(), vecBuffer.data() + unBufferSize - unNewCarrySize, unNewCarrySize);
		}

		return unNewCarrySize;
	}

	bool IsProcessScannerProtectionReadable(DWORD unProtection) {
		if ((unProtection & PAGE_GUARD) || (unProtection & PAGE_NOACCESS)) {
			return false;
		}

		switch (unProtection & 0xFF) {
			case PAGE_READONLY:
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				return true;
		}

		return false;
	}

	bool TestProcessScanner::Find(const void* pData, size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, const void* pBeginAddress, size_t unRangeSize) const {
		if (!pResult) {
			return false;
		}

		*pResult = {};
		auto& vecMatches = pResult->m_vecMatches;
		if (!pData || !unDataSize || (unDataSize > (SIZE_MAX - kProcessScannerChunkSize + 1)) || !m_hProcess) {
			return false;
		}

		std::vector<unsigned char> vecData(unDataSize);
		std::memcpy(vecData.data(), pData, unDataSize);
		std::vector<unsigned char> vecBuffer(kProcessScannerChunkSize + unDataSize - 1);

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unMinimumAddress = reinterpret_cast<size_t>(SystemInfo.lpMinimumApplicationAddress);
		const size_t unMaximumAddress = reinterpret_cast<size_t>(SystemInfo.lpMaximumApplicationAddress);
		const size_t unSystemEnd = (unMaximumAddress == SIZE_MAX) ? SIZE_MAX : unMaximumAddress + 1;
		const size_t unBeginAddress = pBeginAddress ? reinterpret_cast<size_t>(pBeginAddress) : unMinimumAddress;
		size_t unEndAddress = unSystemEnd;
		if (unRangeSize) {
			unEndAddress = (unRangeSize > (SIZE_MAX - unBeginAddress)) ? SIZE_MAX : unBeginAddress + unRangeSize;
		}

		if ((unBeginAddress >= unEndAddress) || (unEndAddress <= unMinimumAddress)) {
			return false;
		}

		size_t unCarrySize = 0;
		size_t unNextAddress = std::max(unBeginAddress, unMinimumAddress);
		size_t unCursor = std::max(unBeginAddress, unMinimumAddress);
		unEndAddress = std::min(unEndAddress, unSystemEnd);
		if (unCursor >= unEndAddress) {
			return false;
		}

		while (unCursor < unEndAddress) {
			MEMORY_BASIC_INFORMATION MemoryInfo {};
			if (VirtualQueryEx(m_hProcess, reinterpret_cast<void*>(unCursor), &MemoryInfo, sizeof(MemoryInfo)) != sizeof(MemoryInfo)) {
				++pResult->m_unReadFailures;
				return false;
			}

			const size_t unRegionBase = reinterpret_cast<size_t>(MemoryInfo.BaseAddress);
			const size_t unRegionEnd = (MemoryInfo.RegionSize > (SIZE_MAX - unRegionBase)) ? SIZE_MAX : unRegionBase + MemoryInfo.RegionSize;
			const size_t unScanBegin = std::max(unCursor, unRegionBase);
			const size_t unScanEnd = std::min(unEndAddress, unRegionEnd);
			if ((MemoryInfo.State == MEM_COMMIT) && IsProcessScannerProtectionReadable(MemoryInfo.Protect) && (unScanBegin < unScanEnd)) {
				if (unScanBegin != unNextAddress) {
					unCarrySize = 0;
				}

				size_t unChunkAddress = unScanBegin;
				while (unChunkAddress < unScanEnd) {
					const size_t unReadSize = std::min(kProcessScannerChunkSize, unScanEnd - unChunkAddress);
					SIZE_T unBytesRead = 0;
					const bool bRead = ReadProcessMemory(m_hProcess, reinterpret_cast<void*>(unChunkAddress), vecBuffer.data() + unCarrySize, unReadSize, &unBytesRead) != FALSE;
					pResult->m_unBytesScanned += static_cast<size_t>(unBytesRead);
					if (unBytesRead) {
						unCarrySize = CollectProcessScannerChunk(vecBuffer, unCarrySize, static_cast<size_t>(unBytesRead), vecData.data(), unDataSize, unChunkAddress, vecMatches);
					}

					if (!bRead || (unBytesRead != unReadSize)) {
						++pResult->m_unReadFailures;
						unCarrySize = 0;
					}

					unChunkAddress += unReadSize;
					unNextAddress = unChunkAddress;
				}
			} else {
				unCarrySize = 0;
				unNextAddress = unScanEnd;
			}

			if (unRegionEnd <= unCursor) {
				++pResult->m_unReadFailures;
				return false;
			}

			unCursor = unRegionEnd;
		}

		pResult->m_bCompleted = true;
		return true;
	}

	bool FreeScannerTestMemory(void* pAddress) {
		return pAddress && (VirtualFree(pAddress, 0, MEM_RELEASE) != FALSE);
	}

	bool CopyProtectedTestMemory(void* pAddress, size_t unSize, std::vector<unsigned char>* pData) {
		if (!pAddress || !unSize || !pData) {
			return false;
		}

		DWORD unOldProtection = 0;
		if (!VirtualProtect(pAddress, unSize, PAGE_READONLY, &unOldProtection)) {
			return false;
		}

		pData->resize(unSize);
		std::memcpy(pData->data(), pAddress, unSize);
		DWORD unTemporaryProtection = 0;
		return VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection) != FALSE;
	}

	bool TamperProtectedTestMemory(void* pAddress, size_t unSize) {
		if (!pAddress || !unSize) {
			return false;
		}

		DWORD unOldProtection = 0;
		if (!VirtualProtect(pAddress, unSize, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
			return false;
		}

		unsigned char* const pData = static_cast<unsigned char*>(pAddress);
		pData[0] = static_cast<unsigned char>(pData[0] ^ 1);
		DWORD unTemporaryProtection = 0;
		return VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection) != FALSE;
	}

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
		CHECK(Page.Alloc(SIZE_MAX, 2) == nullptr);
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

	TEST_CASE("Page and Region near address") {
		constexpr size_t kMaximumRelativeJumpDistance = 0x7FFFFFFB;

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		REQUIRE(hKernel32 != INVALID_HANDLE_VALUE);
		if (!hKernel32 || (hKernel32 == INVALID_HANDLE_VALUE)) {
			return;
		}

		void* const pDesiredAddress = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pDesiredAddress != nullptr);

		auto const IsWithinRelativeDistance = [](void const* const pFirstAddress, void const* const pSecondAddress) -> bool {
			const size_t unFirstAddress = reinterpret_cast<size_t>(pFirstAddress);
			const size_t unSecondAddress = reinterpret_cast<size_t>(pSecondAddress);
			const size_t unDistance = (unFirstAddress > unSecondAddress) ? (unFirstAddress - unSecondAddress) : (unSecondAddress - unFirstAddress);
			return unDistance <= kMaximumRelativeJumpDistance;
		};

		{
			Detours::Memory::Page NearPage(pDesiredAddress);
			void* const pPageAddress = NearPage.GetPageAddress();
			REQUIRE(pPageAddress != nullptr);
			CHECK((reinterpret_cast<size_t>(pPageAddress) % SystemInfo.dwAllocationGranularity) == 0);
			CHECK(IsWithinRelativeDistance(pDesiredAddress, pPageAddress));
		}

		{
			const size_t unRegionCapacity = static_cast<size_t>(SystemInfo.dwPageSize) * 2;
			Detours::Memory::Region NearRegion(pDesiredAddress, unRegionCapacity);
			void* const pRegionAddress = NearRegion.GetRegionAddress();
			REQUIRE(pRegionAddress != nullptr);
			CHECK(NearRegion.GetRegionCapacity() == unRegionCapacity);
			CHECK((reinterpret_cast<size_t>(pRegionAddress) % SystemInfo.dwAllocationGranularity) == 0);
			CHECK(IsWithinRelativeDistance(pDesiredAddress, pRegionAddress));
		}
	}

	TEST_CASE("Region") {
		Detours::Memory::Region Region;
		CHECK(Region.Alloc(SIZE_MAX, 2) == nullptr);
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

	TEST_CASE("ProcessScanner chunk boundary") {
		constexpr size_t kScannerChunkSize = 1024 * 1024;
		constexpr size_t kNeedleSize = sizeof(unsigned long long);
		constexpr size_t kNeedleSplit = kNeedleSize / 2;
		const size_t unAllocationSize = kScannerChunkSize + kNeedleSize;
		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		const unsigned long long unNeedle = __rdtsc() ^ reinterpret_cast<size_t>(pMemory);
		unsigned char* const pNeedleAddress = pMemory + kScannerChunkSize - kNeedleSplit;
		const unsigned char* const pNeedleData = reinterpret_cast<const unsigned char*>(&unNeedle);
		for (size_t i = 0; i < sizeof(unNeedle); ++i) {
			pNeedleAddress[i] = pNeedleData[i];
		}

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ScanResult, pMemory, unAllocationSize) == true);
		CHECK(ScanResult.m_bCompleted == true);
		CHECK(ScanResult.m_unBytesScanned == unAllocationSize);
		CHECK(ScanResult.m_unReadFailures == 0);
		CHECK(std::find(ScanResult.m_vecMatches.begin(), ScanResult.m_vecMatches.end(), pNeedleAddress) != ScanResult.m_vecMatches.end());

		CHECK(FreeScannerTestMemory(pMemory) == true);
	}

	TEST_CASE("ProcessScanner readable region boundary") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unPageSize = static_cast<size_t>(SystemInfo.dwPageSize);
		const size_t unAllocationSize = unPageSize * 2;
		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		const unsigned long long unNeedle = __rdtsc() ^ reinterpret_cast<size_t>(pMemory);
		unsigned char* const pNeedleAddress = pMemory + unPageSize - (sizeof(unNeedle) / 2);
		const unsigned char* const pNeedleData = reinterpret_cast<const unsigned char*>(&unNeedle);
		for (size_t i = 0; i < sizeof(unNeedle); ++i) {
			pNeedleAddress[i] = pNeedleData[i];
		}

		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pMemory + unPageSize, unPageSize, PAGE_READONLY, &unOldProtection) != FALSE);

		MEMORY_BASIC_INFORMATION FirstMemoryInfo {};
		MEMORY_BASIC_INFORMATION SecondMemoryInfo {};
		REQUIRE(VirtualQuery(pMemory, &FirstMemoryInfo, sizeof(FirstMemoryInfo)) == sizeof(FirstMemoryInfo));
		REQUIRE(VirtualQuery(pMemory + unPageSize, &SecondMemoryInfo, sizeof(SecondMemoryInfo)) == sizeof(SecondMemoryInfo));
		REQUIRE(FirstMemoryInfo.BaseAddress == pMemory);
		REQUIRE(FirstMemoryInfo.RegionSize == unPageSize);
		REQUIRE(SecondMemoryInfo.BaseAddress == (pMemory + unPageSize));
		REQUIRE(SecondMemoryInfo.RegionSize == unPageSize);

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ScanResult, pMemory, unAllocationSize) == true);
		CHECK(ScanResult.m_bCompleted == true);
		CHECK(ScanResult.m_unBytesScanned == unAllocationSize);
		CHECK(ScanResult.m_unReadFailures == 0);
		CHECK(std::find(ScanResult.m_vecMatches.begin(), ScanResult.m_vecMatches.end(), pNeedleAddress) != ScanResult.m_vecMatches.end());

		CHECK(FreeScannerTestMemory(pMemory) == true);
	}

	TEST_CASE("ProtectedPage") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		CHECK(ProtectedPage.GetPageCapacity() != 0);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);
		CHECK(ProtectedPage.IsPageEmpty() == true);

		volatile unsigned long long* const pData = static_cast<volatile unsigned long long*>(ProtectedPage.Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		const unsigned long long unValue = __rdtsc() ^ reinterpret_cast<size_t>(pPageAddress);
		*pData = unValue;
		CHECK(*pData == unValue);
		CHECK(ProtectedPage.GetDataSize() == sizeof(unValue));
		CHECK(ProtectedPage.IsPageEmpty() == false);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unValue, sizeof(unValue), &ScanResult, pPageAddress, ProtectedPage.GetPageCapacity()) == true);
		CHECK(ScanResult.m_vecMatches.empty());

		CHECK(ProtectedPage.DeAlloc(const_cast<unsigned long long*>(pData)) == true);
		CHECK(ProtectedPage.IsPageEmpty() == true);
		CHECK(ProtectedPage.Release() == true);
		CHECK(ProtectedPage.Release() == false);
	}

	TEST_CASE("Protected and Secure pages use exactly one system page") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unPageSize = static_cast<size_t>(SystemInfo.dwPageSize);

		Detours::Memory::ProtectedPage ProtectedPage;
		REQUIRE(ProtectedPage.GetPageAddress() != nullptr);
		CHECK(ProtectedPage.GetPageCapacity() == unPageSize);
		void* const pProtectedData = ProtectedPage.Alloc(unPageSize);
		REQUIRE(pProtectedData != nullptr);
		CHECK(ProtectedPage.Alloc(1) == nullptr);

		Detours::Memory::SecurePage SecurePage;
		REQUIRE(SecurePage.GetPageAddress() != nullptr);
		CHECK(SecurePage.GetPageCapacity() == unPageSize);
		void* const pSecureData = SecurePage.Alloc(unPageSize);
		REQUIRE(pSecureData != nullptr);
		CHECK(SecurePage.Alloc(1) == nullptr);

		void* const pMultiPageAddress = VirtualAlloc(nullptr, unPageSize * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		REQUIRE(pMultiPageAddress != nullptr);
		if (pMultiPageAddress) {
			Detours::Memory::ProtectedPage InvalidProtectedPage(pMultiPageAddress, unPageSize * 2);
			Detours::Memory::SecurePage InvalidSecurePage(pMultiPageAddress, unPageSize * 2);
			CHECK(InvalidProtectedPage.GetPageAddress() == nullptr);
			CHECK(InvalidSecurePage.GetPageAddress() == nullptr);
			const BOOL bMultiPageFreed = VirtualFree(pMultiPageAddress, 0, MEM_RELEASE);
			CHECK(bMultiPageFreed != FALSE);
		}
	}

	TEST_CASE("ProtectedRange and ProtectedStorage") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unRangeSize = static_cast<size_t>(SystemInfo.dwPageSize) + 64;
		Detours::Memory::ProtectedRange ProtectedRange(unRangeSize);
		void* const pRangeAddress = ProtectedRange.GetRangeAddress();
		REQUIRE(pRangeAddress != nullptr);
		CHECK(ProtectedRange.GetRangeSize() == unRangeSize);
		CHECK(ProtectedRange.IsProtected() == true);
		volatile unsigned long long* const pLastValue = reinterpret_cast<volatile unsigned long long*>(static_cast<unsigned char*>(pRangeAddress) + unRangeSize - sizeof(unsigned long long));
		const unsigned long long unValue = __rdtsc() ^ reinterpret_cast<size_t>(pRangeAddress);
		*pLastValue = unValue;
		CHECK(*pLastValue == unValue);
		CHECK(ProtectedRange.IsCompromised() == false);

		Detours::Memory::ProtectedStorage ProtectedStorage(128);
		void* const pFirst = ProtectedStorage.Alloc(64);
		void* const pSecond = ProtectedStorage.ZeroAlloc(64);
		REQUIRE(pFirst != nullptr);
		REQUIRE(pSecond != nullptr);
		CHECK(ProtectedStorage.GetDataSize() == 128);
		CHECK(ProtectedStorage.IsStorageEmpty() == false);
		CHECK(ProtectedStorage.IsProtected() == true);
		CHECK(ProtectedStorage.IsCompromised() == false);
		*static_cast<volatile unsigned long long*>(pFirst) = unValue;
		CHECK(*static_cast<volatile unsigned long long*>(pFirst) == unValue);
		CHECK(*static_cast<volatile unsigned long long*>(pSecond) == 0);
		CHECK(ProtectedStorage.DeAllocAll() == true);
		CHECK(ProtectedStorage.IsStorageEmpty() == true);
	}

	TEST_CASE("External ProtectedRange and SecureRange reject partial pages") {
		constexpr unsigned char kFirstValue = 0x5A;
		constexpr unsigned char kNeighborValue = 0xA5;

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unPageSize = static_cast<size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize > 1);

		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		pMemory[0] = kFirstValue;
		pMemory[unPageSize - 1] = kNeighborValue;
		{
			Detours::Memory::ProtectedRange InvalidProtectedRange(pMemory, unPageSize - 1);
			CHECK(InvalidProtectedRange.GetRangeAddress() == nullptr);
			CHECK(InvalidProtectedRange.GetRangeSize() == 0);
			CHECK(InvalidProtectedRange.IsProtected() == false);
			CHECK(InvalidProtectedRange.Release() == false);
		}

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pMemory, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READWRITE);
		CHECK(pMemory[0] == kFirstValue);
		CHECK(pMemory[unPageSize - 1] == kNeighborValue);

		{
			Detours::Memory::SecureRange InvalidSecureRange(pMemory, unPageSize - 1);
			CHECK(InvalidSecureRange.GetRangeAddress() == nullptr);
			CHECK(InvalidSecureRange.GetRangeSize() == 0);
			CHECK(InvalidSecureRange.IsSecured() == false);
			CHECK(InvalidSecureRange.Release() == false);
		}

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pMemory, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READWRITE);
		CHECK(pMemory[0] == kFirstValue);
		CHECK(pMemory[unPageSize - 1] == kNeighborValue);
		CHECK(FreeScannerTestMemory(pMemory) == true);
	}

	TEST_CASE("ProtectedPage detects bypass tampering") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);

		Detours::Memory::ProtectedPage ProtectedPage(pPageAddress, Page.GetPageCapacity());
		volatile unsigned long long* const pData = static_cast<volatile unsigned long long*>(ProtectedPage.Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		*pData = __rdtsc() ^ reinterpret_cast<size_t>(pData);
		CHECK(ProtectedPage.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(const_cast<unsigned long long*>(pData), sizeof(*pData)) == true);
		CHECK(ProtectedPage.IsCompromised() == true);
		CHECK(ProtectedPage.Release() == true);
	}

	TEST_CASE("Secure and Protected exact-range composition") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		const size_t unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);

		void* pValueAddress = nullptr;
		const unsigned long long unValue = __rdtsc() ^ reinterpret_cast<size_t>(pPageAddress);
		{
			Detours::Memory::SecurePage SecurePage(Page.GetPageAddress(), Page.GetPageCapacity());
			REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
			REQUIRE(SecurePage.IsSecured() == true);

			Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
			REQUIRE(ProtectedPage.GetPageAddress() == SecurePage.GetPageAddress());
			CHECK(ProtectedPage.IsProtected() == true);
			pValueAddress = ProtectedPage.Alloc(sizeof(unValue));
			REQUIRE(pValueAddress != nullptr);
			*static_cast<volatile unsigned long long*>(pValueAddress) = unValue;
			CHECK(*static_cast<volatile unsigned long long*>(pValueAddress) == unValue);
			CHECK(ProtectedPage.GetDataSize() == sizeof(unValue));
			CHECK(SecurePage.GetDataSize() == sizeof(unValue));

			std::vector<unsigned char> vecCiphertext;
			REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecCiphertext) == true);
			const unsigned char* const pValueBytes = reinterpret_cast<const unsigned char*>(&unValue);
			CHECK(std::search(vecCiphertext.begin(), vecCiphertext.end(), pValueBytes, pValueBytes + sizeof(unValue)) == vecCiphertext.end());
			CHECK(SecurePage.IsCompromised() == false);
			CHECK(ProtectedPage.IsCompromised() == false);

			TestProcessScanner Scanner;
			TEST_PROCESS_SCAN_RESULT ScanResult {};
			REQUIRE(Scanner.Find(&unValue, sizeof(unValue), &ScanResult, pPageAddress, unPageCapacity) == true);
			CHECK(ScanResult.m_vecMatches.empty());
		}

		REQUIRE(pValueAddress != nullptr);
		CHECK(*static_cast<unsigned long long*>(pValueAddress) == unValue);
	}

	TEST_CASE("SecureRange and ProtectedRange exact-range composition") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unRangeSize = static_cast<size_t>(SystemInfo.dwPageSize) + 64;

		Detours::Memory::SecureRange SecureRange(unRangeSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		REQUIRE(SecureRange.IsSecured() == true);

		Detours::Memory::ProtectedRange ProtectedRange(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize());
		REQUIRE(ProtectedRange.GetRangeAddress() == SecureRange.GetRangeAddress());
		REQUIRE(ProtectedRange.IsProtected() == true);

		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(ProtectedRange.Alloc(unRangeSize));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		pData[unRangeSize - 1] = 0xA5;
		CHECK(pData[unRangeSize - 1] == 0xA5);
		CHECK(ProtectedRange.GetDataSize() == unRangeSize);
		CHECK(SecureRange.GetDataSize() == unRangeSize);
		CHECK(ProtectedRange.IsCompromised() == false);
		CHECK(SecureRange.IsCompromised() == false);
	}

	TEST_CASE("SecurePage uses independent encryption metadata") {
		Detours::Memory::SecurePage FirstSecurePage;
		Detours::Memory::SecurePage SecondSecurePage;
		void* const pFirstAddress = FirstSecurePage.GetPageAddress();
		void* const pSecondAddress = SecondSecurePage.GetPageAddress();
		REQUIRE(pFirstAddress != nullptr);
		REQUIRE(pSecondAddress != nullptr);
		REQUIRE(pFirstAddress != pSecondAddress);
		REQUIRE(FirstSecurePage.GetPageCapacity() == SecondSecurePage.GetPageCapacity());

		volatile unsigned long long* const pFirstValue = static_cast<volatile unsigned long long*>(FirstSecurePage.Alloc(sizeof(unsigned long long)));
		volatile unsigned long long* const pSecondValue = static_cast<volatile unsigned long long*>(SecondSecurePage.Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pFirstValue) != 0);
		REQUIRE(reinterpret_cast<size_t>(pSecondValue) != 0);
		const unsigned long long unValue = __rdtsc() ^ reinterpret_cast<size_t>(pFirstAddress);
		*pFirstValue = unValue;
		*pSecondValue = unValue;

		std::vector<unsigned char> vecFirstCiphertext;
		std::vector<unsigned char> vecSecondCiphertext;
		REQUIRE(CopyProtectedTestMemory(pFirstAddress, FirstSecurePage.GetPageCapacity(), &vecFirstCiphertext) == true);
		REQUIRE(CopyProtectedTestMemory(pSecondAddress, SecondSecurePage.GetPageCapacity(), &vecSecondCiphertext) == true);
		CHECK(vecFirstCiphertext != vecSecondCiphertext);
		CHECK(*pFirstValue == unValue);
		std::vector<unsigned char> vecFirstResealedCiphertext;
		REQUIRE(CopyProtectedTestMemory(pFirstAddress, FirstSecurePage.GetPageCapacity(), &vecFirstResealedCiphertext) == true);
		CHECK(vecFirstCiphertext != vecFirstResealedCiphertext);

		for (size_t unIndex = 0; unIndex < 8; ++unIndex) {
			const unsigned long long unCurrentValue = unValue + unIndex;
			*pFirstValue = unCurrentValue;
			CHECK(*pFirstValue == unCurrentValue);
			CHECK(FirstSecurePage.IsCompromised() == false);
		}

		CHECK(SecondSecurePage.IsCompromised() == false);
	}

	TEST_CASE("SecurePage only reports decrypted hash mismatches") {
		Detours::Memory::SecurePage SecurePage;
		void* const pAddress = SecurePage.GetPageAddress();
		const size_t unCapacity = SecurePage.GetPageCapacity();
		REQUIRE(pAddress != nullptr);
		REQUIRE(unCapacity != 0);

		volatile unsigned long long* const pValue = static_cast<volatile unsigned long long*>(SecurePage.Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pValue) != 0);
		*pValue = __rdtsc() ^ reinterpret_cast<size_t>(pValue);
		CHECK(SecurePage.IsCompromised() == false);

		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pAddress, unCapacity, PAGE_READONLY, &unOldProtection) != FALSE);
		CHECK(SecurePage.IsCompromised() == false);
		CHECK(SecurePage.IsSecured() == false);

		DWORD unTemporaryProtection = 0;
		CHECK(VirtualProtect(pAddress, unCapacity, unOldProtection, &unTemporaryProtection) != FALSE);
	}

	TEST_CASE("SecurePage detects encrypted payload tampering") {
		Detours::Memory::Page Page;
		Detours::Memory::SecurePage SecurePage(Page.GetPageAddress(), Page.GetPageCapacity());
		void* const pData = SecurePage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = __rdtsc() ^ reinterpret_cast<size_t>(pData);
		CHECK(SecurePage.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(Page.GetPageAddress(), Page.GetPageCapacity()) == true);
		CHECK(SecurePage.IsCompromised() == true);

		Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
		CHECK(ProtectedPage.IsCompromised() == true);
		CHECK(ProtectedPage.Release() == true);
		CHECK(SecurePage.Release() == true);
		CHECK(*static_cast<unsigned long long*>(pData) == 0);
	}

	TEST_CASE("ProtectedPage preserves SecurePage compromise state") {
		Detours::Memory::Page Page;
		Detours::Memory::SecurePage SecurePage(Page.GetPageAddress(), Page.GetPageCapacity());
		Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
		void* const pData = ProtectedPage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = __rdtsc() ^ reinterpret_cast<size_t>(pData);
		REQUIRE(TamperProtectedTestMemory(Page.GetPageAddress(), Page.GetPageCapacity()) == true);
		CHECK(SecurePage.Release() == true);
		CHECK(ProtectedPage.IsCompromised() == true);
		CHECK(ProtectedPage.Release() == true);
	}

	TEST_CASE("SecurePage") {
		Detours::Memory::SecurePage SecurePage;
		void* const pAddress = SecurePage.GetPageAddress();
		REQUIRE(pAddress != nullptr);
		CHECK(SecurePage.GetPageCapacity() != 0);
		CHECK((reinterpret_cast<size_t>(pAddress) % SecurePage.GetPageCapacity()) == 0);
		CHECK(SecurePage.IsSecured() == true);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK(MemoryInfo.State == MEM_COMMIT);
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		const unsigned long long unNeedle = __rdtsc() ^ reinterpret_cast<size_t>(pAddress);
		unsigned long long unControl = unNeedle;
		volatile unsigned long long* const pData = static_cast<volatile unsigned long long*>(pAddress);
		*pData = unNeedle;

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(*pData == unNeedle);

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ControlResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ControlResult, &unControl, sizeof(unControl)) == true);
		CHECK(ControlResult.m_bCompleted == true);
		CHECK(ControlResult.m_unReadFailures == 0);
		CHECK(std::find(ControlResult.m_vecMatches.begin(), ControlResult.m_vecMatches.end(), &unControl) != ControlResult.m_vecMatches.end());

		TEST_PROCESS_SCAN_RESULT SecureResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &SecureResult, pAddress, SecurePage.GetPageCapacity()) == true);
		CHECK(SecureResult.m_bCompleted == true);
		CHECK(SecureResult.m_unReadFailures == 0);
		CHECK(SecureResult.m_vecMatches.empty());

		TEST_PROCESS_SCAN_RESULT FullResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &FullResult) == true);
		CHECK(FullResult.m_bCompleted == true);
		CHECK(std::find(FullResult.m_vecMatches.begin(), FullResult.m_vecMatches.end(), &unControl) != FullResult.m_vecMatches.end());
		CHECK(std::find(FullResult.m_vecMatches.begin(), FullResult.m_vecMatches.end(), pAddress) == FullResult.m_vecMatches.end());
		MESSAGE("ProcessScanner full scan: matches = " << FullResult.m_vecMatches.size() << ", protected address was not found");

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(SecurePage.Release() == true);
		CHECK(SecurePage.GetPageAddress() == nullptr);
		CHECK(SecurePage.GetPageCapacity() == 0);
		CHECK(SecurePage.IsSecured() == false);
		CHECK(SecurePage.Release() == false);
	}

	TEST_CASE("SecureRange") {
		Detours::Memory::SecureRange EmptyRange(0);
		CHECK(EmptyRange.GetRangeAddress() == nullptr);
		CHECK(EmptyRange.GetRangeSize() == 0);
		CHECK(EmptyRange.IsSecured() == false);
		CHECK(EmptyRange.Release() == false);

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		const size_t unRangeSize = static_cast<size_t>(SystemInfo.dwPageSize) + 64;
		Detours::Memory::SecureRange SecureRange(unRangeSize);
		void* const pAddress = SecureRange.GetRangeAddress();
		REQUIRE(pAddress != nullptr);
		CHECK(SecureRange.GetRangeSize() == unRangeSize);
		CHECK(SecureRange.IsSecured() == true);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		unsigned char* const pCode = static_cast<unsigned char*>(pAddress);
		pCode[0] = 0xB8;
		pCode[1] = 0x2A;
		pCode[2] = 0;
		pCode[3] = 0;
		pCode[4] = 0;
		pCode[5] = 0xC3;
		REQUIRE(FlushInstructionCache(GetCurrentProcess(), pCode, 6) != FALSE);

		using fnSecureRange = int(__cdecl*)();
		CHECK(reinterpret_cast<fnSecureRange>(pCode)() == 42);

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		const unsigned long long unNeedle = __rdtsc() ^ reinterpret_cast<size_t>(pAddress);
		*static_cast<volatile unsigned long long*>(pAddress) = unNeedle;
		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ScanResult, pAddress, SecureRange.GetRangeSize()) == true);
		CHECK(ScanResult.m_bCompleted == true);
		CHECK(ScanResult.m_unReadFailures == 0);
		CHECK(ScanResult.m_vecMatches.empty());

		volatile unsigned long long* const pLastValue = reinterpret_cast<volatile unsigned long long*>(static_cast<unsigned char*>(pAddress) + unRangeSize - sizeof(unsigned long long));
		*pLastValue = unNeedle;
		CHECK(*pLastValue == unNeedle);

		MemoryInfo = {};
		REQUIRE(VirtualQuery(const_cast<const unsigned long long*>(pLastValue), &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(SecureRange.Release() == true);
		CHECK(SecureRange.GetRangeAddress() == nullptr);
		CHECK(SecureRange.GetRangeSize() == 0);
		CHECK(SecureRange.IsSecured() == false);
		CHECK(SecureRange.Release() == false);
	}

	TEST_CASE("SecureRange authenticates partial logical tail") {
		constexpr size_t kRangeSize = 31;
		Detours::Memory::SecureRange SecureRange(kRangeSize);
		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(SecureRange.Alloc(kRangeSize));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		CHECK(SecureRange.GetRangeSize() == kRangeSize);
		CHECK(SecureRange.IsSecured() == true);

		unsigned char pPlaintext[kRangeSize] {};
		for (size_t unIndex = 0; unIndex < kRangeSize; ++unIndex) {
			pPlaintext[unIndex] = static_cast<unsigned char>(unIndex + 1);
			pData[unIndex] = pPlaintext[unIndex];
		}

		volatile unsigned char* const pTail = pData + (kRangeSize - 1);
		CHECK(*pTail == pPlaintext[kRangeSize - 1]);
		std::vector<unsigned char> vecCiphertext;
		REQUIRE(CopyProtectedTestMemory(const_cast<unsigned char*>(pData), kRangeSize, &vecCiphertext) == true);
		CHECK(std::equal(pPlaintext + 16, pPlaintext + kRangeSize, vecCiphertext.begin() + 16) == false);
		CHECK(SecureRange.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(const_cast<unsigned char*>(pTail), 1) == true);
		CHECK(SecureRange.IsCompromised() == true);
		CHECK(SecureRange.Release() == true);
	}

	TEST_CASE("SecureStorage") {
		Detours::Memory::SecureStorage SecureStorage(128);
		CHECK(SecureStorage.GetStorageCapacity() == 128);
		CHECK(SecureStorage.GetDataSize() == 0);
		CHECK(SecureStorage.IsStorageEmpty() == true);
		CHECK(SecureStorage.Alloc(0) == nullptr);
		CHECK(SecureStorage.DeAlloc(nullptr) == false);
		CHECK(SecureStorage.GetDataSize() == 0);

		void* const pFirst = SecureStorage.Alloc(64);
		REQUIRE(pFirst != nullptr);
		CHECK(SecureStorage.GetDataSize() == 64);

		void* const pSecond = SecureStorage.ZeroAlloc(64);
		REQUIRE(pSecond != nullptr);
		CHECK(SecureStorage.GetDataSize() == 128);
		CHECK(SecureStorage.IsStorageEmpty() == false);
		CHECK(*static_cast<volatile unsigned long long*>(pSecond) == 0);

		MEMORY_BASIC_INFORMATION ZeroMemoryInfo {};
		REQUIRE(VirtualQuery(pSecond, &ZeroMemoryInfo, sizeof(ZeroMemoryInfo)) == sizeof(ZeroMemoryInfo));
		CHECK((ZeroMemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(SecureStorage.Alloc(1) == nullptr);
		CHECK(SecureStorage.Alloc(SIZE_MAX) == nullptr);
		CHECK(SecureStorage.GetDataSize() == 128);

		const unsigned long long unNeedle = __rdtsc() ^ reinterpret_cast<size_t>(pFirst);
		*static_cast<volatile unsigned long long*>(pFirst) = unNeedle;

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ScanResult, pFirst, 64) == true);
		CHECK(ScanResult.m_bCompleted == true);
		CHECK(ScanResult.m_unReadFailures == 0);
		CHECK(ScanResult.m_vecMatches.empty());

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pFirst, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(SecureStorage.DeAlloc(pSecond) == true);
		CHECK(SecureStorage.GetDataSize() == 64);
		CHECK(SecureStorage.DeAllocAll() == true);
		CHECK(SecureStorage.GetDataSize() == 0);
		CHECK(SecureStorage.IsStorageEmpty() == true);
		CHECK(SecureStorage.DeAlloc(pFirst) == false);
	}

	TEST_CASE("ProtectedMemoryManager") {
		Detours::Memory::ProtectedMemoryManager Manager;
		CHECK(Manager.DestroyPage(nullptr) == false);
		CHECK(Manager.DestroyStorage(nullptr) == false);

		Detours::Memory::ProtectedPage UnmanagedPage;
		Detours::Memory::ProtectedStorage UnmanagedStorage;
		CHECK(Manager.DestroyPage(&UnmanagedPage) == false);
		CHECK(Manager.DestroyStorage(&UnmanagedStorage) == false);

		Detours::Memory::ProtectedPage* const pPage = Manager.CreatePage();
		REQUIRE(pPage != nullptr);
		CHECK(pPage->IsProtected() == true);
		volatile unsigned long long* const pPageData = static_cast<volatile unsigned long long*>(pPage->Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pPageData) != 0);
		*pPageData = 0x123456789ABCDEF0;
		CHECK(*pPageData == 0x123456789ABCDEF0);

		Detours::Memory::ProtectedStorage* const pStorage = Manager.CreateStorage(64);
		REQUIRE(pStorage != nullptr);
		volatile unsigned long long* const pStorageData = static_cast<volatile unsigned long long*>(pStorage->Alloc(64));
		REQUIRE(reinterpret_cast<size_t>(pStorageData) != 0);
		*pStorageData = 0x0FEDCBA987654321;
		CHECK(*pStorageData == 0x0FEDCBA987654321);
		CHECK(pStorage->IsProtected() == true);

		CHECK(Manager.DestroyStorage(pStorage) == true);
		CHECK(Manager.DestroyPage(pPage) == true);
	}

	TEST_CASE("SecureMemoryManager") {
		Detours::Memory::SecureMemoryManager Manager;
		CHECK(Manager.DestroyPage(nullptr) == false);
		CHECK(Manager.DestroyStorage(nullptr) == false);

		Detours::Memory::SecurePage UnmanagedPage;
		Detours::Memory::SecureStorage UnmanagedStorage;
		CHECK(Manager.DestroyPage(&UnmanagedPage) == false);
		CHECK(Manager.DestroyStorage(&UnmanagedStorage) == false);

		Detours::Memory::SecurePage* const pPage = Manager.CreatePage();
		REQUIRE(pPage != nullptr);
		CHECK(pPage->IsSecured() == true);
		volatile unsigned long long* const pPageData = static_cast<volatile unsigned long long*>(pPage->Alloc(sizeof(unsigned long long)));
		REQUIRE(reinterpret_cast<size_t>(pPageData) != 0);
		*pPageData = 0x123456789ABCDEF0;
		CHECK(*pPageData == 0x123456789ABCDEF0);

		Detours::Memory::SecureStorage* const pStorage = Manager.CreateStorage(64);
		REQUIRE(pStorage != nullptr);
		volatile unsigned long long* const pStorageData = static_cast<volatile unsigned long long*>(pStorage->Alloc(64));
		REQUIRE(reinterpret_cast<size_t>(pStorageData) != 0);
		*pStorageData = 0x0FEDCBA987654321;
		CHECK(*pStorageData == 0x0FEDCBA987654321);
		CHECK(pStorage->IsSecured() == true);

		CHECK(Manager.DestroyStorage(pStorage) == true);
		CHECK(Manager.DestroyPage(pPage) == true);
	}
}

TEST_SUITE("Detours::Exception") {

	bool OnException(const EXCEPTION_RECORD& Exception, const PCONTEXT pCTX) {
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

	typedef bool(__fastcall * fnFooOriginal)(void* pThis, void* /* unused */);
	typedef bool(__fastcall * fnBooOriginal)(void* pThis, void* /* unused */);

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
		RawSleepHook.CallTrampoline(pCTX);
		return true;
	}

	std::atomic<unsigned int> g_unRawSleepConcurrentCalls = 0;
	Detours::Hook::RawHook RawSleepConcurrentHook;
#ifdef _M_X64
	bool __fastcall Sleep_RawHookConcurrent(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
	bool __cdecl Sleep_RawHookConcurrent(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_unRawSleepConcurrentCalls.fetch_add(1, std::memory_order_relaxed);
		RawSleepConcurrentHook.CallTrampoline(pCTX);
		return true;
	}

	Detours::Hook::RAW_CONTEXT_M128 g_LastXMM7;

#ifdef _M_X64
	__declspec(noinline) unsigned long long __fastcall CallAddressStandaloneTarget(unsigned long long unValue) {
		// Exercise the complete Windows x64 home area. A context captured by
		// GetCurrentContext must describe the caller's ABI entry stack, not the
		// already-returned internal capture-code frame.
		volatile unsigned long long* pShadowSpace = reinterpret_cast<volatile unsigned long long*>(_AddressOfReturnAddress()) + 1;
		pShadowSpace[0] = unValue;
		pShadowSpace[1] = unValue + 1;
		pShadowSpace[2] = unValue + 2;
		pShadowSpace[3] = unValue + 3;
		return unValue + 0x1234;
	}
#elif _M_IX86
	__declspec(noinline) unsigned int __fastcall CallAddressStandaloneTarget(unsigned int unValue) {
		return unValue + 0x1234;
	}
#endif

#ifdef _M_X64
	bool __fastcall Sleep_RawHookMod(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif _M_IX86
	bool __cdecl Sleep_RawHookMod(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_bRawSleepHookCalled = true;

		g_LastXMM7 = pCTX->m_XMM7;
		pCTX->m_XMM7.m_un64[0] = 0x1122334455667788;
		pCTX->m_XMM7.m_un64[1] = 0x1122334455667788;

		Detours::Hook::CallAddress(RawSleepHook.GetTrampoline(), pCTX);
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
		pCTX->m_Stack.Push(new_foo);
#elif _M_IX86
		void* pReturnAddress = pCTX->m_Stack.Pop();
		pCTX->m_Stack.Push(pCTX->m_unECX);
		pCTX->m_Stack.Push(pReturnAddress);
		pCTX->m_Stack.Push(new_foo);
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
		pCTX->m_Stack.Push(reinterpret_cast<char*>(RawCPUIDHook.GetTrampoline()) + RawCPUIDHook.GetFirstInstructionSize());

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

		MEMORY_BASIC_INFORMATION mbiHere {}, mbiPrev {};
		REQUIRE(VirtualQuery(pArray, &mbiHere, sizeof(mbiHere)) == sizeof(mbiHere));
		REQUIRE(mbiHere.State == MEM_COMMIT);

		void* prevByte = reinterpret_cast<BYTE*>(pArray) - 1;
		REQUIRE(VirtualQuery(prevByte, &mbiPrev, sizeof(mbiPrev)) == sizeof(mbiPrev));

		bool usedFallback = false;
		void* region = nullptr;

		if (mbiPrev.State == MEM_COMMIT) {
			region = VirtualAlloc(nullptr, 2 * kPageSize, MEM_RESERVE, PAGE_READWRITE);
			REQUIRE(region != nullptr);

			void* commit = VirtualAlloc(static_cast<BYTE*>(region) + kPageSize, kPageSize, MEM_COMMIT, PAGE_READWRITE);
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

		CHECK(Detours::Hook::HookMemory(MemoryHookModify2, reinterpret_cast<BYTE*>(pArray) - sizeof(int), sizeof(int), nullptr, true) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHookModify2, pArray, sizeof(int), nullptr, false) == true);

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

	TEST_CASE("GetCurrentContext and CallAddress") {
		Detours::Hook::RAW_CONTEXT Context{};
		Detours::Hook::GetCurrentContext(&Context);
#ifdef _M_IX86
		unsigned int unCurrentStackAddress = 0;
		__asm mov unCurrentStackAddress, esp
#endif
		CHECK(Context.m_Stack.GetAddress() != nullptr);
#ifdef _M_X64
		CHECK(Context.m_unRFLAGS != 0);
		CHECK((reinterpret_cast<size_t>(Context.m_Stack.GetAddress()) & 0xF) == 0x8);
		Context.m_unRCX = 0x300;
#elif _M_IX86
		CHECK(Context.m_unEFLAGS != 0);
		// MSVC may retain the cdecl outgoing argument slot or reclaim it
		// immediately after GetCurrentContext returns.
		const bool bOutgoingStackSlotRetained = Context.m_unESP == unCurrentStackAddress;
		const bool bOutgoingStackSlotReleased = (Context.m_unESP + sizeof(void*)) == unCurrentStackAddress;
		CHECK((bOutgoingStackSlotRetained || bOutgoingStackSlotReleased));
		Context.m_unECX = 0x300;
#endif

		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#ifdef _M_X64
		CHECK(Context.m_unRAX == 0x1534);
#elif _M_IX86
		CHECK(Context.m_unEAX == 0x1534);
#endif
	}

	TEST_CASE("CallAddress standalone RAW_CONTEXT") {
		Detours::Hook::RAW_CONTEXT Context{};
		Context.m_unEFLAGS = 0x202;
		Context.m_unMXCSR = 0x1F80;
		Context.m_FPU.m_unControlWord = 0x037F;
		Context.m_FPU.m_unTagWord = 0xFFFF;
#ifdef _M_X64
		Context.m_unRCX = 0x100;
#elif _M_IX86
		Context.m_unECX = 0x100;
#endif

		CHECK(Context.m_Stack.GetAddress() == nullptr);
		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
		CHECK(Context.m_Stack.GetAddress() == nullptr);
#ifdef _M_X64
		CHECK(Context.m_unRAX == 0x1334);
#elif _M_IX86
		CHECK(Context.m_unEAX == 0x1334);
#endif
	}

	TEST_CASE("CallAddress standalone custom stack") {
		constexpr size_t kStackSize = 0x10000;
		void* pStack = VirtualAlloc(nullptr, kStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		REQUIRE(pStack != nullptr);
		if (!pStack) {
			return;
		}

		Detours::Hook::RAW_CONTEXT Context{};
		Context.m_unEFLAGS = 0x202;
		Context.m_unMXCSR = 0x1F80;
		Context.m_FPU.m_unControlWord = 0x037F;
		Context.m_FPU.m_unTagWord = 0xFFFF;
#ifdef _M_X64
		Context.m_unRCX = 0x200;
		size_t unStackAddress = (reinterpret_cast<size_t>(pStack) + kStackSize - 0x100) & ~static_cast<size_t>(0xF);
		unStackAddress -= 8;
#elif _M_IX86
		Context.m_unECX = 0x200;
		size_t unStackAddress = (reinterpret_cast<size_t>(pStack) + kStackSize - 0x100) & ~static_cast<size_t>(0xF);
		unStackAddress -= 4;
#endif
		Context.m_Stack.SetAddress(reinterpret_cast<void*>(unStackAddress));
		*reinterpret_cast<size_t*>(Context.m_Stack.GetAddress()) = 0;

		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#ifdef _M_X64
		CHECK(Context.m_unRAX == 0x1434);
#elif _M_IX86
		CHECK(Context.m_unEAX == 0x1434);
#endif
		CHECK(reinterpret_cast<size_t>(Context.m_Stack.GetAddress()) >= reinterpret_cast<size_t>(pStack));
		CHECK(reinterpret_cast<size_t>(Context.m_Stack.GetAddress()) < (reinterpret_cast<size_t>(pStack) + kStackSize));
#pragma warning(suppress : 6001) // Custom stack transfer obscures pStack lifetime from code analysis.
		CHECK(VirtualFree(pStack, 0, MEM_RELEASE) != FALSE);
	}

	TEST_CASE("CallAddress concurrent contexts") {
		constexpr unsigned int unThreadCount = 8;
		constexpr unsigned int unIterations = 128;
		std::atomic<unsigned int> unFailures = 0;
		std::vector<std::thread> Threads;
		Threads.reserve(unThreadCount);

		for (unsigned int unThread = 0; unThread < unThreadCount; ++unThread) {
			Threads.emplace_back([unThread, &unFailures]() {
				for (unsigned int unIteration = 0; unIteration < unIterations; ++unIteration) {
#ifdef _M_X64
					const unsigned long long unInput = (static_cast<unsigned long long>(unThread) << 32) | unIteration;
#elif _M_IX86
					const unsigned int unInput = (unThread << 16) | unIteration;
#endif
					Detours::Hook::RAW_CONTEXT Context{};
#ifdef _M_X64
					Context.m_unRFLAGS = 0x202;
#elif _M_IX86
					Context.m_unEFLAGS = 0x202;
#endif
					Context.m_unMXCSR = 0x1F80;
					Context.m_FPU.m_unControlWord = 0x037F;
					Context.m_FPU.m_unTagWord = 0xFFFF;
#ifdef _M_X64
					Context.m_unRCX = unInput;
#elif _M_IX86
					Context.m_unECX = unInput;
#endif

					Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#ifdef _M_X64
					if (Context.m_Stack.GetAddress() || (Context.m_unRAX != (unInput + 0x1234))) {
#elif _M_IX86
					if (Context.m_Stack.GetAddress() || (Context.m_unEAX != (unInput + 0x1234))) {
#endif
						unFailures.fetch_add(1, std::memory_order_relaxed);
					}
				}
			});
		}

		for (std::thread& Thread : Threads) {
			Thread.join();
		}

		CHECK(unFailures.load(std::memory_order_relaxed) == 0);
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

	TEST_CASE("RawHook rejects oversized reserved stack") {
		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		REQUIRE(hKernel32 != INVALID_HANDLE_VALUE);

		void* pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		Detours::Hook::RawHook OversizedRawHook;
		REQUIRE(OversizedRawHook.Set(pSleep) == true);
		CHECK(OversizedRawHook.Hook(Sleep_RawHook, true, std::numeric_limits<unsigned int>::max(), true) == false);
		CHECK(OversizedRawHook.Release() == true);
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


	TEST_CASE("RawHook CallTrampoline concurrent") {
		g_unRawSleepConcurrentCalls.store(0, std::memory_order_relaxed);

		HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		REQUIRE(hKernel32 != INVALID_HANDLE_VALUE);
		REQUIRE(RawSleepConcurrentHook.Set(reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"))) == true);
		REQUIRE(RawSleepConcurrentHook.Hook(Sleep_RawHookConcurrent, false, 0x16, true) == true);

		constexpr unsigned int unThreadCount = 8;
		constexpr unsigned int unIterations = 64;
		std::vector<std::thread> Threads;
		Threads.reserve(unThreadCount);
		for (unsigned int unThread = 0; unThread < unThreadCount; ++unThread) {
			Threads.emplace_back([]() {
				for (unsigned int unIteration = 0; unIteration < unIterations; ++unIteration) {
					Sleep(0);
				}
			});
		}

		for (std::thread& Thread : Threads) {
			Thread.join();
		}

		CHECK(g_unRawSleepConcurrentCalls.load(std::memory_order_relaxed) == (unThreadCount * unIterations));
		CHECK(RawSleepConcurrentHook.UnHook() == true);
		CHECK(RawSleepConcurrentHook.Release() == true);
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

	unsigned int DemoFunction() {
		SELF_EXPORT("DemoFunction");

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

#elif defined(__linux__)

TEST_SUITE("Detours::Hexadecimal") {
	TEST_CASE("Decode validates input and preserves ignored bytes") {
		char szData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::DecodeA("412A42", szData, 0x2A) == true);
		CHECK(std::memcmp(szData, "AyB", sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeA("A", szData, 0x2A) == false);
		CHECK(Detours::Hexadecimal::DecodeA("GG", szData, 0x2A) == false);

		szData[0] = 'x';
		szData[1] = 'y';
		szData[2] = 'z';
		CHECK(Detours::Hexadecimal::DecodeW(L"412A42", szData, 0x2A) == true);
		CHECK(std::memcmp(szData, "AyB", sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeW(L"A", szData, 0x2A) == false);
		CHECK(Detours::Hexadecimal::DecodeW(L"GG", szData, 0x2A) == false);
	}
}

TEST_SUITE("Detours::Sync") {
	TEST_CASE("Named infinite waits ignore stale errno") {
		Detours::Sync::EventServer EventServer(false, true, true);
		errno = EINVAL;
		CHECK(EventServer.Wait() == true);

		Detours::Sync::MutexServer MutexServer;
		errno = EINVAL;
		CHECK(MutexServer.Lock() == true);
		CHECK(MutexServer.UnLock() == true);

		Detours::Sync::SemaphoreServer SemaphoreServer;
		errno = EINVAL;
		CHECK(SemaphoreServer.Enter(0xFFFFFFFF) == true);
		CHECK(SemaphoreServer.Leave() == true);
	}
}

constexpr size_t kProcessScannerChunkSize = 1024 * 1024;

typedef struct _TEST_PROCESS_SCAN_RESULT {
	_TEST_PROCESS_SCAN_RESULT() {
		m_bCompleted = false;
		m_unBytesScanned = 0;
		m_unReadFailures = 0;
	}

	bool m_bCompleted;
	size_t m_unBytesScanned;
	size_t m_unReadFailures;
	std::vector<void*> m_vecMatches;
} TEST_PROCESS_SCAN_RESULT, *PTEST_PROCESS_SCAN_RESULT;

typedef struct _TEST_PROCESS_MEMORY_REGION {
	size_t m_unBeginAddress;
	size_t m_unEndAddress;
	bool m_bReadable;
} TEST_PROCESS_MEMORY_REGION, *PTEST_PROCESS_MEMORY_REGION;

static size_t GetTestPageSize() {
	const long nPageSize = ::sysconf(_SC_PAGESIZE);
	return (nPageSize > 0) ? static_cast<size_t>(nPageSize) : 0;
}

static void CollectProcessScannerMatches(
	const unsigned char* pBuffer,
	size_t unBufferSize,
	const unsigned char* pData,
	size_t unDataSize,
	size_t unBaseAddress,
	size_t unCandidateCount,
	std::vector<void*>& vecMatches) {
	if (!pBuffer || !pData || !unDataSize || (unBufferSize < unDataSize)) {
		return;
	}

	const size_t unAvailableCandidates = unBufferSize - unDataSize + 1;
	const size_t unCandidates = std::min(unCandidateCount, unAvailableCandidates);
	for (size_t unIndex = 0; unIndex < unCandidates; ++unIndex) {
		if (std::memcmp(pBuffer + unIndex, pData, unDataSize) == 0) {
			vecMatches.push_back(reinterpret_cast<void*>(unBaseAddress + unIndex));
		}
	}
}

static size_t CollectProcessScannerChunk(
	std::vector<unsigned char>& vecBuffer,
	size_t unCarrySize,
	size_t unBytesRead,
	const unsigned char* pData,
	size_t unDataSize,
	size_t unReadAddress,
	std::vector<void*>& vecMatches) {
	if (!unBytesRead) {
		return unCarrySize;
	}

	const size_t unBufferSize = unCarrySize + unBytesRead;
	CollectProcessScannerMatches(vecBuffer.data(), unBufferSize, pData, unDataSize, unReadAddress - unCarrySize, unBytesRead, vecMatches);

	const size_t unNewCarrySize = std::min(unDataSize - 1, unBufferSize);
	if (unNewCarrySize) {
		std::memmove(vecBuffer.data(), vecBuffer.data() + unBufferSize - unNewCarrySize, unNewCarrySize);
	}

	return unNewCarrySize;
}

static bool CollectProcessScannerRegions(std::vector<TEST_PROCESS_MEMORY_REGION>* pRegions) {
	if (!pRegions) {
		return false;
	}

	pRegions->clear();
	std::ifstream Maps("/proc/self/maps");
	if (!Maps.is_open()) {
		return false;
	}

	std::string sLine;
	while (std::getline(Maps, sLine)) {
		unsigned long long unBeginAddress = 0;
		unsigned long long unEndAddress = 0;
		char szProtection[5] {};
		if (std::sscanf(sLine.c_str(), "%llx-%llx %4s", &unBeginAddress, &unEndAddress, szProtection) != 3) {
			continue;
		}

		if ((unBeginAddress >= unEndAddress) || (unBeginAddress > static_cast<unsigned long long>(SIZE_MAX)) || (unEndAddress > static_cast<unsigned long long>(SIZE_MAX))) {
			continue;
		}

		TEST_PROCESS_MEMORY_REGION Region {};
		Region.m_unBeginAddress = static_cast<size_t>(unBeginAddress);
		Region.m_unEndAddress = static_cast<size_t>(unEndAddress);
		Region.m_bReadable = szProtection[0] == 'r';
		pRegions->emplace_back(Region);
	}

	return !pRegions->empty();
}

class TestProcessScanner {
public:
	bool Find(const void* pData, size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, const void* pBeginAddress = nullptr, size_t unRangeSize = 0) const {
		if (!pResult) {
			return false;
		}

		*pResult = {};
		if (!pData || !unDataSize || (unDataSize > (SIZE_MAX - kProcessScannerChunkSize + 1))) {
			return false;
		}

		std::vector<TEST_PROCESS_MEMORY_REGION> vecRegions;
		if (!CollectProcessScannerRegions(&vecRegions)) {
			return false;
		}

		std::vector<unsigned char> vecData(unDataSize);
		std::memcpy(vecData.data(), pData, unDataSize);
		std::vector<unsigned char> vecBuffer(kProcessScannerChunkSize + unDataSize - 1);

		const size_t unBeginAddress = pBeginAddress ? reinterpret_cast<size_t>(pBeginAddress) : 0;
		size_t unEndAddress = SIZE_MAX;
		if (unRangeSize) {
			unEndAddress = (unRangeSize > (SIZE_MAX - unBeginAddress)) ? SIZE_MAX : unBeginAddress + unRangeSize;
		}

		if (unBeginAddress >= unEndAddress) {
			return false;
		}

		const int nMemoryFile = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
		if (nMemoryFile < 0) {
			return false;
		}

		size_t unCarrySize = 0;
		size_t unNextAddress = unBeginAddress;
		for (const TEST_PROCESS_MEMORY_REGION& Region : vecRegions) {
			if (Region.m_unEndAddress <= unBeginAddress) {
				continue;
			}

			if (Region.m_unBeginAddress >= unEndAddress) {
				break;
			}

			const size_t unScanBegin = std::max(unBeginAddress, Region.m_unBeginAddress);
			const size_t unScanEnd = std::min(unEndAddress, Region.m_unEndAddress);
			if (!Region.m_bReadable || (unScanBegin >= unScanEnd)) {
				unCarrySize = 0;
				unNextAddress = unScanEnd;
				continue;
			}

			if (unScanBegin != unNextAddress) {
				unCarrySize = 0;
			}

			size_t unChunkAddress = unScanBegin;
			while (unChunkAddress < unScanEnd) {
				const size_t unReadSize = std::min(kProcessScannerChunkSize, unScanEnd - unChunkAddress);
				if (unChunkAddress > static_cast<size_t>(std::numeric_limits<off_t>::max())) {
					++pResult->m_unReadFailures;
					unCarrySize = 0;
					break;
				}

				const ssize_t nBytesRead = ::pread(nMemoryFile, vecBuffer.data() + unCarrySize, unReadSize, static_cast<off_t>(unChunkAddress));
				const size_t unBytesRead = (nBytesRead > 0) ? static_cast<size_t>(nBytesRead) : 0;
				pResult->m_unBytesScanned += unBytesRead;
				if (unBytesRead) {
					unCarrySize = CollectProcessScannerChunk(vecBuffer, unCarrySize, unBytesRead, vecData.data(), unDataSize, unChunkAddress, pResult->m_vecMatches);
				}

				if (unBytesRead != unReadSize) {
					++pResult->m_unReadFailures;
					unCarrySize = 0;
				}

				unChunkAddress += unReadSize;
				unNextAddress = unChunkAddress;
			}
		}

		::close(nMemoryFile);
		pResult->m_bCompleted = true;
		return true;
	}
};

static bool ChangeProtectedTestMemoryProtection(void* pAddress, size_t unSize, int nProtection) {
	const size_t unPageSize = GetTestPageSize();
	const size_t unAddress = reinterpret_cast<size_t>(pAddress);
	if (!pAddress || !unSize || !unPageSize || (unSize > (SIZE_MAX - unAddress))) {
		return false;
	}

	const size_t unAlignedAddress = unAddress - (unAddress % unPageSize);
	size_t unAlignedEnd = unAddress + unSize;
	const size_t unEndRemainder = unAlignedEnd % unPageSize;
	if (unEndRemainder) {
		const size_t unEndPadding = unPageSize - unEndRemainder;
		if (unEndPadding > (SIZE_MAX - unAlignedEnd)) {
			return false;
		}

		unAlignedEnd += unEndPadding;
	}

	return ::mprotect(reinterpret_cast<void*>(unAlignedAddress), unAlignedEnd - unAlignedAddress, nProtection) == 0;
}

static bool CopyProtectedTestMemory(void* pAddress, size_t unSize, std::vector<unsigned char>* pData) {
	if (!pAddress || !unSize || !pData || !ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_READ)) {
		return false;
	}

	pData->resize(unSize);
	std::memcpy(pData->data(), pAddress, unSize);
	return ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
}

static bool TamperProtectedTestMemory(void* pAddress, size_t unSize) {
	if (!pAddress || !unSize || !ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_READ | PROT_WRITE)) {
		return false;
	}

	unsigned char* const pData = static_cast<unsigned char*>(pAddress);
	pData[unSize - 1] = static_cast<unsigned char>(pData[unSize - 1] ^ 1);
	return ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
}

TEST_SUITE("Detours::Memory") {
	TEST_CASE("Page, Region and Storage") {
		const size_t unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Page Page;
		REQUIRE(Page.GetPageAddress() != nullptr);
		CHECK(Page.GetPageCapacity() == unPageSize);
		CHECK(Page.Alloc(SIZE_MAX, 2) == nullptr);
		CHECK(Page.Alloc(1, 0, 1) == nullptr);
		volatile std::uint64_t* const pPageValue = static_cast<volatile std::uint64_t*>(Page.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pPageValue) != 0);
		CHECK(*pPageValue == 0);
		*pPageValue = 11;
		CHECK(*pPageValue == 11);
		CHECK(Page.DeAlloc(const_cast<std::uint64_t*>(pPageValue)) == true);
		CHECK(Page.IsPageEmpty() == true);

		Detours::Memory::Region Region(nullptr, unPageSize * 2);
		CHECK(Region.Alloc(SIZE_MAX, 2) == nullptr);
		CHECK(Region.Alloc(1, 0, 1) == nullptr);
		volatile std::uint64_t* const pRegionValue = static_cast<volatile std::uint64_t*>(Region.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pRegionValue) != 0);
		CHECK(*pRegionValue == 0);
		*pRegionValue = 13;
		CHECK(*pRegionValue == 13);
		CHECK(Region.GetDataSize() == sizeof(std::uint64_t));
		CHECK(Region.DeAlloc(const_cast<std::uint64_t*>(pRegionValue)) == true);

		Detours::Memory::Storage Storage(128, unPageSize);
		volatile std::uint64_t* const pStorageValue = static_cast<volatile std::uint64_t*>(Storage.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pStorageValue) != 0);
		CHECK(*pStorageValue == 0);
		*pStorageValue = 17;
		CHECK(*pStorageValue == 17);
		CHECK(Storage.DeAlloc(const_cast<std::uint64_t*>(pStorageValue)) == true);
		CHECK(Storage.IsStorageEmpty() == true);
	}

	TEST_CASE("Storage enforces and reuses total capacity") {
		const size_t unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage LimitedStorage(16, unPageSize);
		void* const pLimitedAllocation = LimitedStorage.Alloc(16);
		REQUIRE(pLimitedAllocation != nullptr);
		CHECK(LimitedStorage.Alloc(1) == nullptr);
		CHECK(LimitedStorage.DeAlloc(pLimitedAllocation) == true);

		Detours::Memory::Storage ReusedStorage(unPageSize * 2, unPageSize);
		void* const pFirstAllocation = ReusedStorage.Alloc(unPageSize);
		REQUIRE(pFirstAllocation != nullptr);
		CHECK(ReusedStorage.DeAlloc(pFirstAllocation) == true);

		void* const pReusedAllocation = ReusedStorage.Alloc(unPageSize);
		void* const pSecondAllocation = ReusedStorage.Alloc(unPageSize);
		REQUIRE(pReusedAllocation != nullptr);
		REQUIRE(pSecondAllocation != nullptr);
		CHECK(ReusedStorage.DeAlloc(pReusedAllocation) == true);
		CHECK(ReusedStorage.DeAlloc(pSecondAllocation) == true);
	}

	TEST_CASE("External ProtectedRange and SecureRange reject partial pages") {
		constexpr unsigned char kFirstValue = 0x5A;
		constexpr unsigned char kNeighborValue = 0xA5;

		const size_t unPageSize = GetTestPageSize();
		REQUIRE(unPageSize > 1);

		void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		if (pMapping == MAP_FAILED) {
			return;
		}

		unsigned char* const pMemory = static_cast<unsigned char*>(pMapping);
		pMemory[0] = kFirstValue;
		pMemory[unPageSize - 1] = kNeighborValue;
		{
			Detours::Memory::ProtectedRange InvalidProtectedRange(pMemory, unPageSize - 1);
			CHECK(InvalidProtectedRange.GetRangeAddress() == nullptr);
			CHECK(InvalidProtectedRange.GetRangeSize() == 0);
			CHECK(InvalidProtectedRange.IsProtected() == false);
			CHECK(InvalidProtectedRange.Release() == false);
		}

		CHECK(pMemory[0] == kFirstValue);
		CHECK(pMemory[unPageSize - 1] == kNeighborValue);

		{
			Detours::Memory::SecureRange InvalidSecureRange(pMemory, unPageSize - 1);
			CHECK(InvalidSecureRange.GetRangeAddress() == nullptr);
			CHECK(InvalidSecureRange.GetRangeSize() == 0);
			CHECK(InvalidSecureRange.IsSecured() == false);
			CHECK(InvalidSecureRange.Release() == false);
		}

		CHECK(pMemory[0] == kFirstValue);
		CHECK(pMemory[unPageSize - 1] == kNeighborValue);
		CHECK(::munmap(pMemory, unPageSize) == 0);
	}

	TEST_CASE("ProtectedPage and process scanner") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		CHECK(ProtectedPage.GetPageCapacity() == GetTestPageSize());
		CHECK(ProtectedPage.IsProtected() == true);

		const std::uint64_t unValue = 0x123456789ABCDEF0;
		std::uint64_t unControl = unValue;
		volatile std::uint64_t* const pData = static_cast<volatile std::uint64_t*>(ProtectedPage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		*pData = unValue;
		CHECK(*pData == unValue);
		CHECK(ProtectedPage.IsProtected() == true);

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ControlResult {};
		REQUIRE(Scanner.Find(&unValue, sizeof(unValue), &ControlResult, &unControl, sizeof(unControl)) == true);
		CHECK(ControlResult.m_bCompleted == true);
		CHECK(ControlResult.m_unReadFailures == 0);
		CHECK(std::find(ControlResult.m_vecMatches.begin(), ControlResult.m_vecMatches.end(), &unControl) != ControlResult.m_vecMatches.end());

		TEST_PROCESS_SCAN_RESULT ProtectedResult {};
		REQUIRE(Scanner.Find(&unValue, sizeof(unValue), &ProtectedResult, pPageAddress, ProtectedPage.GetPageCapacity()) == true);
		CHECK(ProtectedResult.m_bCompleted == true);
		CHECK(ProtectedResult.m_unReadFailures == 0);
		CHECK(ProtectedResult.m_vecMatches.empty());
		CHECK(ProtectedPage.IsCompromised() == false);

		REQUIRE(TamperProtectedTestMemory(pPageAddress, ProtectedPage.GetPageCapacity()) == true);
		CHECK(ProtectedPage.IsCompromised() == true);
	}

	TEST_CASE("SecurePage and ProtectedPage composition") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		const size_t unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);

		void* pValueAddress = nullptr;
		const std::uint64_t unValue = 0x0FEDCBA987654321;
		{
			Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
			Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
			REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
			REQUIRE(ProtectedPage.GetPageAddress() == pPageAddress);
			CHECK(SecurePage.IsSecured() == true);
			CHECK(ProtectedPage.IsProtected() == true);

			pValueAddress = ProtectedPage.Alloc(sizeof(unValue));
			REQUIRE(pValueAddress != nullptr);
			*static_cast<volatile std::uint64_t*>(pValueAddress) = unValue;
			CHECK(*static_cast<volatile std::uint64_t*>(pValueAddress) == unValue);
			CHECK(ProtectedPage.GetDataSize() == sizeof(unValue));
			CHECK(SecurePage.GetDataSize() == sizeof(unValue));

			std::vector<unsigned char> vecCiphertext;
			REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecCiphertext) == true);
			const unsigned char* const pValueBytes = reinterpret_cast<const unsigned char*>(&unValue);
			CHECK(std::search(vecCiphertext.begin(), vecCiphertext.end(), pValueBytes, pValueBytes + sizeof(unValue)) == vecCiphertext.end());

			TestProcessScanner Scanner;
			TEST_PROCESS_SCAN_RESULT ScanResult {};
			REQUIRE(Scanner.Find(&unValue, sizeof(unValue), &ScanResult, pPageAddress, unPageCapacity) == true);
			CHECK(ScanResult.m_bCompleted == true);
			CHECK(ScanResult.m_unReadFailures == 0);
			CHECK(ScanResult.m_vecMatches.empty());
			CHECK(SecurePage.IsCompromised() == false);
			CHECK(ProtectedPage.IsCompromised() == false);
		}

		REQUIRE(pValueAddress != nullptr);
		CHECK(*static_cast<std::uint64_t*>(pValueAddress) == unValue);
	}

	TEST_CASE("SecureRange and ProtectedRange composition") {
		const size_t unRangeSize = GetTestPageSize() + 37;
		REQUIRE(unRangeSize > 37);

		Detours::Memory::SecureRange SecureRange(unRangeSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		Detours::Memory::ProtectedRange ProtectedRange(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize());
		REQUIRE(ProtectedRange.GetRangeAddress() == SecureRange.GetRangeAddress());
		CHECK(SecureRange.IsSecured() == true);
		CHECK(ProtectedRange.IsProtected() == true);

		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(ProtectedRange.Alloc(unRangeSize));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);
		pData[0] = 0x5A;
		pData[unRangeSize - 1] = 0xA5;
		CHECK(pData[0] == 0x5A);
		CHECK(pData[unRangeSize - 1] == 0xA5);
		CHECK(ProtectedRange.GetDataSize() == unRangeSize);
		CHECK(SecureRange.GetDataSize() == unRangeSize);
		CHECK(ProtectedRange.IsCompromised() == false);
		CHECK(SecureRange.IsCompromised() == false);
	}

	TEST_CASE("SecurePage executes protected code") {
		Detours::Memory::SecurePage SecurePage;
		volatile unsigned char* const pCode = static_cast<volatile unsigned char*>(SecurePage.Alloc(6));
		REQUIRE(reinterpret_cast<size_t>(pCode) != 0);

		pCode[0] = 0xB8;
		pCode[1] = 0x2A;
		pCode[2] = 0;
		pCode[3] = 0;
		pCode[4] = 0;
		pCode[5] = 0xC3;
		unsigned char* const pExecutableCode = const_cast<unsigned char*>(pCode);
		__builtin___clear_cache(reinterpret_cast<char*>(pExecutableCode), reinterpret_cast<char*>(pExecutableCode + 6));

		using fnSecurePage = int (*)();
		CHECK(reinterpret_cast<fnSecurePage>(pExecutableCode)() == 42);
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);
	}

	TEST_CASE("ProtectedMemoryManager and SecureMemoryManager") {
		Detours::Memory::ProtectedMemoryManager ProtectedManager;
		CHECK(ProtectedManager.DestroyPage(nullptr) == false);
		CHECK(ProtectedManager.DestroyStorage(nullptr) == false);

		Detours::Memory::ProtectedPage* const pProtectedPage = ProtectedManager.CreatePage();
		Detours::Memory::ProtectedStorage* const pProtectedStorage = ProtectedManager.CreateStorage(64);
		REQUIRE(pProtectedPage != nullptr);
		REQUIRE(pProtectedStorage != nullptr);
		volatile std::uint64_t* const pProtectedValue = static_cast<volatile std::uint64_t*>(pProtectedStorage->Alloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pProtectedValue) != 0);
		*pProtectedValue = 19;
		CHECK(*pProtectedValue == 19);
		CHECK(pProtectedStorage->IsProtected() == true);
		CHECK(ProtectedManager.DestroyStorage(pProtectedStorage) == true);
		CHECK(ProtectedManager.DestroyPage(pProtectedPage) == true);

		Detours::Memory::SecureMemoryManager SecureManager;
		CHECK(SecureManager.DestroyPage(nullptr) == false);
		CHECK(SecureManager.DestroyStorage(nullptr) == false);

		Detours::Memory::SecurePage* const pSecurePage = SecureManager.CreatePage();
		Detours::Memory::SecureStorage* const pSecureStorage = SecureManager.CreateStorage(64);
		REQUIRE(pSecurePage != nullptr);
		REQUIRE(pSecureStorage != nullptr);
		volatile std::uint64_t* const pSecureValue = static_cast<volatile std::uint64_t*>(pSecureStorage->Alloc(sizeof(std::uint64_t)));
		REQUIRE(reinterpret_cast<size_t>(pSecureValue) != 0);
		*pSecureValue = 23;
		CHECK(*pSecureValue == 23);
		CHECK(pSecureStorage->IsSecured() == true);
		CHECK(pSecureStorage->IsCompromised() == false);
		CHECK(SecureManager.DestroyStorage(pSecureStorage) == true);
		CHECK(SecureManager.DestroyPage(pSecurePage) == true);
	}

	TEST_CASE("SecureRange detects encrypted tail tampering") {
		constexpr size_t kRangeSize = 37;
		Detours::Memory::SecureRange SecureRange(kRangeSize);
		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(SecureRange.Alloc(kRangeSize));
		REQUIRE(reinterpret_cast<size_t>(pData) != 0);

		for (size_t unIndex = 0; unIndex < kRangeSize; ++unIndex) {
			pData[unIndex] = static_cast<unsigned char>(unIndex + 1);
		}

		CHECK(SecureRange.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize()) == true);
		CHECK(SecureRange.IsCompromised() == true);
	}
}

#endif

#include "Detours.h"

// General
#if defined(_WIN32)
#include <Windows.h>
#include <tchar.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#if defined(_WIN32)
#include <intrin.h>
#endif

// C
#if defined(__linux__)
#include <fcntl.h>
#include <setjmp.h>
#include <spawn.h>
#include <unistd.h>
#endif

// C++
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <typeinfo>

// STL
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

// Third-party
#undef min
#undef max
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#if defined(__linux__)
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#endif
#include "doctest.h"
#undef DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#undef DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#if defined(__linux__)
#undef DOCTEST_CONFIG_NO_POSIX_SIGNALS
#endif

#if defined(_WIN32)
using TestMemoryProtection = DWORD;
constexpr TestMemoryProtection kProtectedMemoryDefaultTestProtection = PAGE_EXECUTE_READWRITE;
constexpr TestMemoryProtection kProtectedMemoryReadOnlyTestProtection = PAGE_READONLY;
constexpr TestMemoryProtection kProtectedMemoryReadWriteTestProtection = PAGE_READWRITE;
constexpr TestMemoryProtection kProtectedMemoryReadExecuteTestProtection = PAGE_EXECUTE_READ;
constexpr TestMemoryProtection kProtectedMemoryInvalidTestProtection = PAGE_NOACCESS;
constexpr unsigned int kMemoryHookTestRegistryInsert = 0;
constexpr unsigned int kMemoryHookTestRegisterPage = 1;
constexpr unsigned int kMemoryHookTestUnregisterPage = 2;
constexpr unsigned int kMemoryHookTestOpenPage = 3;
constexpr unsigned int kMemoryHookTestClosePage = 4;
constexpr unsigned int kWindowsModuleReferenceWaitMilliseconds = 5000;
constexpr unsigned int kWindowsTemporaryModuleCreateAttemptCount = 16;
constexpr wchar_t kWindowsTemporaryModulePrefix[] = L"DTR";
constexpr wchar_t kWindowsTemporaryModuleSourceName[] = L"version.dll";
#elif defined(__linux__)
using TestMemoryProtection = int;
constexpr TestMemoryProtection kProtectedMemoryDefaultTestProtection = PROT_READ | PROT_WRITE | PROT_EXEC;
constexpr TestMemoryProtection kProtectedMemoryReadOnlyTestProtection = PROT_READ;
constexpr TestMemoryProtection kProtectedMemoryReadWriteTestProtection = PROT_READ | PROT_WRITE;
constexpr TestMemoryProtection kProtectedMemoryReadExecuteTestProtection = PROT_READ | PROT_EXEC;
constexpr TestMemoryProtection kProtectedMemoryInvalidTestProtection = PROT_NONE;
#endif

constexpr unsigned int kProtectedStressThreadCount = 4;
constexpr unsigned int kProtectedStressIterations = 256;
constexpr unsigned int kMutexStressThreadCount = 8;
constexpr unsigned int kMutexStressIterations = 2000;
constexpr unsigned int kParallelThreadWaitMilliseconds = 2000;
constexpr unsigned int kTestCleanupAttemptCount = 64;
constexpr std::size_t kInlineUnHookRedirectOffset = 64;
constexpr std::size_t kInlineHookTargetSnapshotSize = HOOK_INLINE_TRAMPOLINE_SIZE;
constexpr std::size_t kInlineHookInstallLauncherOffset = 128;
constexpr std::size_t kInlineHookInstallBlockerOffset = 192;
constexpr std::size_t kHookTargetInsideCallCandidateOffset = 2;
constexpr std::size_t kHookTargetInsideMoveCandidateOffset = 5;
constexpr int kInlineUnHookOriginalValue = 17;

using LegacySectionName = std::array<unsigned char const, Detours::Scan::kSectionNameSize>;
#if defined(_WIN32)
using LegacyFindSection = bool (*)(HMODULE, LegacySectionName const&, void**, std::size_t*) noexcept;
using TestNamedObjectCharacter = TCHAR;
using EventNameGetter = bool (Detours::Sync::EventServer::*)(TCHAR*, std::size_t);
using MutexNameGetter = bool (Detours::Sync::MutexServer::*)(TCHAR*, std::size_t);
using SemaphoreNameGetter = bool (Detours::Sync::SemaphoreServer::*)(TCHAR*, std::size_t);
using PipeNameGetter = bool (Detours::Pipe::PipeServer::*)(TCHAR*, std::size_t);
using SharedNameGetter = bool (Detours::Memory::SharedServer::*)(TCHAR*, std::size_t);
using LDRTryReLinkModule = bool (*)(Detours::LDR::LINK_DATA);
using LDRReLinkModule = void (*)(Detours::LDR::LINK_DATA);
#elif defined(__linux__)
using LegacyFindSection = bool (*)(void*, LegacySectionName const&, void**, std::size_t*) noexcept;
using TestNamedObjectCharacter = char;
using EventNameGetter = bool (Detours::Sync::EventServer::*)(char*, std::size_t);
using MutexNameGetter = bool (Detours::Sync::MutexServer::*)(char*, std::size_t);
using SemaphoreNameGetter = bool (Detours::Sync::SemaphoreServer::*)(char*, std::size_t);
using PipeNameGetter = bool (Detours::Pipe::PipeServer::*)(char*, std::size_t);
using SharedNameGetter = bool (Detours::Memory::SharedServer::*)(char*, std::size_t);
#endif
using NamedPipeClientOpen = bool (Detours::Pipe::PipeClient::*)(TestNamedObjectCharacter const*, std::size_t);
using TestNamedObjectName = TestNamedObjectCharacter[Detours::kNamedObjectNameCapacity];
using CodecEncode = int (*)(unsigned short, char const*, std::size_t, wchar_t*, int);
using CodecDecode = int (*)(unsigned short, wchar_t const*, std::size_t, char*, int);
using HexadecimalEncodeA = bool (*)(void const*, std::size_t, char*, std::size_t, unsigned char);
using HexadecimalEncodeW = bool (*)(void const*, std::size_t, wchar_t*, std::size_t, unsigned char);
using HexadecimalEncode = bool (*)(void const*, std::size_t, TestNamedObjectCharacter*, std::size_t, unsigned char);
using HexadecimalDecodeA = bool (*)(char const*, std::size_t, void*, std::size_t, unsigned char);
using HexadecimalDecodeW = bool (*)(wchar_t const*, std::size_t, void*, std::size_t, unsigned char);
using HexadecimalDecode = bool (*)(TestNamedObjectCharacter const*, std::size_t, void*, std::size_t, unsigned char);
using PipeServerSend = bool (Detours::Pipe::PipeServer::*)(unsigned char const*, std::size_t);
using PipeServerReceive = bool (Detours::Pipe::PipeServer::*)(unsigned char*, std::size_t);
using PipeClientSend = bool (Detours::Pipe::PipeClient::*)(unsigned char const*, std::size_t);
using PipeClientReceive = bool (Detours::Pipe::PipeClient::*)(unsigned char*, std::size_t);
using RawHookCallAddress = void (Detours::Hook::RawHook::*)(void*, Detours::Hook::PRAW_CONTEXT) const;

static_assert(
	std::is_same<
		decltype(std::declval<Detours::Exception::ExceptionListener&>().GetCallBacks()),
		std::deque<Detours::Exception::fnExceptionCallBack>&>::value,
	"ExceptionListener::GetCallBacks must preserve its mutable-reference ABI");
static_assert(Detours::Scan::kSectionNameSize == 8, "Legacy section names must contain eight bytes");
static_assert(std::is_const<typename LegacySectionName::value_type>::value, "Legacy section-name elements must remain const");
static_assert(std::is_same<decltype(static_cast<LegacyFindSection>(&Detours::Scan::FindSection)), LegacyFindSection>::value, "Legacy FindSection signature changed");
static_assert(std::is_same<decltype(static_cast<EventNameGetter>(&Detours::Sync::EventServer::GetEventName)), EventNameGetter>::value, "EventServer name getter signature changed");
static_assert(std::is_same<decltype(static_cast<MutexNameGetter>(&Detours::Sync::MutexServer::GetMutexName)), MutexNameGetter>::value, "MutexServer name getter signature changed");
static_assert(std::is_same<decltype(static_cast<SemaphoreNameGetter>(&Detours::Sync::SemaphoreServer::GetSemaphoreName)), SemaphoreNameGetter>::value, "SemaphoreServer name getter signature changed");
static_assert(std::is_same<decltype(static_cast<PipeNameGetter>(&Detours::Pipe::PipeServer::GetPipeName)), PipeNameGetter>::value, "PipeServer name getter signature changed");
static_assert(std::is_same<decltype(static_cast<SharedNameGetter>(&Detours::Memory::SharedServer::GetSharedName)), SharedNameGetter>::value, "SharedServer name getter signature changed");
static_assert(std::is_same<decltype(static_cast<NamedPipeClientOpen>(&Detours::Pipe::PipeClient::Open)), NamedPipeClientOpen>::value, "PipeClient bounded name signature changed");
static_assert(std::is_same<decltype(static_cast<CodecEncode>(&Detours::Codec::Encode)), CodecEncode>::value, "Codec::Encode bounded signature changed");
static_assert(std::is_same<decltype(static_cast<CodecDecode>(&Detours::Codec::Decode)), CodecDecode>::value, "Codec::Decode bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalEncodeA>(&Detours::Hexadecimal::EncodeA)), HexadecimalEncodeA>::value, "Hexadecimal::EncodeA bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalEncodeW>(&Detours::Hexadecimal::EncodeW)), HexadecimalEncodeW>::value, "Hexadecimal::EncodeW bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalEncode>(&Detours::Hexadecimal::Encode)), HexadecimalEncode>::value, "Hexadecimal::Encode bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalDecodeA>(&Detours::Hexadecimal::DecodeA)), HexadecimalDecodeA>::value, "Hexadecimal::DecodeA bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalDecodeW>(&Detours::Hexadecimal::DecodeW)), HexadecimalDecodeW>::value, "Hexadecimal::DecodeW bounded signature changed");
static_assert(std::is_same<decltype(static_cast<HexadecimalDecode>(&Detours::Hexadecimal::Decode)), HexadecimalDecode>::value, "Hexadecimal::Decode bounded signature changed");
static_assert(std::is_same<decltype(static_cast<PipeServerSend>(&Detours::Pipe::PipeServer::Send)), PipeServerSend>::value, "PipeServer bounded send signature changed");
static_assert(std::is_same<decltype(static_cast<PipeServerReceive>(&Detours::Pipe::PipeServer::Receive)), PipeServerReceive>::value, "PipeServer bounded receive signature changed");
static_assert(std::is_same<decltype(static_cast<PipeClientSend>(&Detours::Pipe::PipeClient::Send)), PipeClientSend>::value, "PipeClient bounded send signature changed");
static_assert(std::is_same<decltype(static_cast<PipeClientReceive>(&Detours::Pipe::PipeClient::Receive)), PipeClientReceive>::value, "PipeClient bounded receive signature changed");
static_assert(std::is_same<decltype(static_cast<RawHookCallAddress>(&Detours::Hook::RawHook::CallAddress)), RawHookCallAddress>::value, "RawHook authenticated CallAddress signature changed");
static_assert(std::is_constructible<Detours::Sync::EventClient, TestNamedObjectCharacter const*, std::size_t, bool>::value, "EventClient bounded name constructor changed");
static_assert(std::is_constructible<Detours::Sync::MutexClient, TestNamedObjectCharacter const*, std::size_t, bool>::value, "MutexClient bounded name constructor changed");
static_assert(std::is_constructible<Detours::Sync::SemaphoreClient, TestNamedObjectCharacter const*, std::size_t, bool>::value, "SemaphoreClient bounded name constructor changed");
static_assert(std::is_constructible<Detours::Memory::SharedClient, TestNamedObjectCharacter const*, std::size_t, bool>::value, "SharedClient bounded name constructor changed");
static_assert(std::is_constructible<Detours::Sync::EventClient, TestNamedObjectName&>::value, "EventClient array name constructor changed");
static_assert(std::is_constructible<Detours::Sync::MutexClient, TestNamedObjectName&>::value, "MutexClient array name constructor changed");
static_assert(std::is_constructible<Detours::Sync::SemaphoreClient, TestNamedObjectName&>::value, "SemaphoreClient array name constructor changed");
static_assert(std::is_constructible<Detours::Memory::SharedClient, TestNamedObjectName&>::value, "SharedClient array name constructor changed");
static_assert(!std::is_constructible<Detours::Sync::EventClient, TestNamedObjectCharacter const*>::value, "EventClient must require a bounded pointer or an array");
static_assert(!std::is_constructible<Detours::Sync::MutexClient, TestNamedObjectCharacter const*>::value, "MutexClient must require a bounded pointer or an array");
static_assert(!std::is_constructible<Detours::Sync::SemaphoreClient, TestNamedObjectCharacter const*>::value, "SemaphoreClient must require a bounded pointer or an array");
static_assert(!std::is_constructible<Detours::Memory::SharedClient, TestNamedObjectCharacter const*>::value, "SharedClient must require a bounded pointer or an array");
#if defined(_WIN32)
static_assert(std::is_same<decltype(Detours::KUserSharedData), Detours::KUSER_SHARED_DATA const volatile&>::value, "Legacy KUserSharedData type changed");
static_assert(std::is_standard_layout<Detours::LDR::LINK_DATA>::value, "LINK_DATA must remain standard-layout");
static_assert(std::is_trivially_copyable<Detours::LDR::LINK_DATA>::value, "LINK_DATA must remain trivially copyable");
static_assert(sizeof(Detours::LDR::LINK_DATA) == (6 * sizeof(void*)), "LINK_DATA must remain six pointers wide");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pDTE) == (0 * sizeof(void*)), "LINK_DATA DTE offset changed");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pSavedInLoadOrderLinks) == (1 * sizeof(void*)), "LINK_DATA load-order offset changed");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pSavedInMemoryOrderLinks) == (2 * sizeof(void*)), "LINK_DATA memory-order offset changed");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pSavedInInitializationOrderLinks) == (3 * sizeof(void*)), "LINK_DATA initialization-order offset changed");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pSavedHashLinks) == (4 * sizeof(void*)), "LINK_DATA hash offset changed");
static_assert(offsetof(Detours::LDR::LINK_DATA, m_pSavedNodeModuleLink) == (5 * sizeof(void*)), "LINK_DATA node offset changed");
static_assert(std::is_same<decltype(&Detours::LDR::TryReLinkModule), LDRTryReLinkModule>::value, "TryReLinkModule signature changed");
static_assert(std::is_same<decltype(&Detours::LDR::ReLinkModule), LDRReLinkModule>::value, "ReLinkModule signature changed");
#endif

struct ProtectedStressResult {
	unsigned int m_unValue;
	unsigned int m_unFailures;
};

struct MutexStressResult {
	unsigned int m_unValue;
	unsigned int m_unFailures;
};

struct ThreadSelfActionData {
	ThreadSelfActionData() noexcept;

	Detours::Parallel::Thread* m_pThread;
	std::atomic<bool> m_bProceed;
	std::atomic<bool> m_bActionCompleted;
	std::atomic<bool> m_bRelease;
	std::atomic<bool> m_bCompleted;
	std::atomic<bool> m_bSucceeded;
	bool m_bDestroy;
	bool m_bSuspend;
	bool m_bWaitAfterAction;
};

struct TestMemoryRange {
	std::uintptr_t m_unBeginAddress;
	std::uintptr_t m_unEndAddress;
};

struct InlineUnHookCodeFixture {
	InlineUnHookCodeFixture() noexcept;

	void* m_pMapping;
	std::size_t m_unMappingSize;
	void* m_pTarget;
	void* m_pRedirect;
	void* m_pLauncher;
	void* m_pBlocker;
};

struct InlineWrapperLoopState {
	InlineWrapperLoopState() noexcept;

	std::atomic<unsigned int> m_unEntered;
	std::atomic<unsigned int> m_unRelease;
};

#if defined(_WIN32)
class WindowsTemporaryModule {
public:
	WindowsTemporaryModule() noexcept;
	~WindowsTemporaryModule() noexcept;

	WindowsTemporaryModule(WindowsTemporaryModule const&) = delete;
	WindowsTemporaryModule& operator=(WindowsTemporaryModule const&) = delete;

public:
	bool Create();
	bool ReleaseCallerReference() noexcept;

public:
	HMODULE GetModule() const noexcept;
	wchar_t const* GetPath() const noexcept;
	char const* GetAnsiBaseName() const noexcept;

private:
	void Clear() noexcept;

private:
	HMODULE m_hModule;
	std::wstring m_strPath;
	std::string m_strAnsiBaseName;
};
#endif

static_assert(std::atomic<unsigned int>::is_always_lock_free, "Inline hook execution tests require lock-free unsigned atomics");
static_assert(std::is_standard_layout<InlineWrapperLoopState>::value, "Inline wrapper loop state must have a fixed memory layout");
static_assert(sizeof(std::atomic<unsigned int>) == sizeof(unsigned int), "Inline wrapper loop atomics must use one native unsigned word");
static_assert(offsetof(InlineWrapperLoopState, m_unRelease) == sizeof(unsigned int), "Inline wrapper loop fields must be adjacent");

ThreadSelfActionData::ThreadSelfActionData() noexcept :
	m_pThread(nullptr),
	m_bProceed(false),
	m_bActionCompleted(false),
	m_bRelease(false),
	m_bCompleted(false),
	m_bSucceeded(false),
	m_bDestroy(false),
	m_bSuspend(false),
	m_bWaitAfterAction(false)
{
}

InlineUnHookCodeFixture::InlineUnHookCodeFixture() noexcept :
	m_pMapping(nullptr),
	m_unMappingSize(0),
	m_pTarget(nullptr),
	m_pRedirect(nullptr),
	m_pLauncher(nullptr),
	m_pBlocker(nullptr)
{
}

InlineWrapperLoopState::InlineWrapperLoopState() noexcept :
	m_unEntered(0),
	m_unRelease(0)
{
}

#if defined(_WIN32)
WindowsTemporaryModule::WindowsTemporaryModule() noexcept :
	m_hModule(nullptr),
	m_strPath(),
	m_strAnsiBaseName()
{
}
#endif

template <typename Function>
class ScopeExit {
public:
	explicit ScopeExit(Function FunctionObject) :
		m_Function(std::move(FunctionObject)),
		m_bActive(true)
	{
	}

	ScopeExit(ScopeExit&& Other) noexcept(std::is_nothrow_move_constructible<Function>::value) :
		m_Function(std::move(Other.m_Function)),
		m_bActive(Other.m_bActive)
	{
		Other.m_bActive = false;
	}

	~ScopeExit() noexcept(false) {
		if (m_bActive) {
			try {
				m_Function();
			} catch (std::exception const&) {
			}
		}
	}

	ScopeExit(ScopeExit const&) = delete;
	ScopeExit& operator=(ScopeExit const&) = delete;
	ScopeExit& operator=(ScopeExit&&) = delete;

	void Release() noexcept {
		m_bActive = false;
	}

private:
	Function m_Function;
	bool m_bActive;
};

static std::atomic<bool> g_bInlineUnHookBlockerEntered { false };
static std::atomic<bool> g_bInlineUnHookBlockerRelease { false };
static Detours::Hook::InlineHook* g_pInlineUnHook = nullptr;
static std::atomic<bool> g_bInlineWrapperCallbackEntered { false };
static std::atomic<bool> g_bInlineWrapperCallbackRelease { false };
static Detours::Hook::InlineWrapperHook* g_pInlineWrapperCallbackHook = nullptr;

namespace {
	class GlobalExceptionListenerFixture {
	public:
		GlobalExceptionListenerFixture() {
			m_bEnabled = m_Listener.EnableHandler();
			m_bDisabled = m_bEnabled && m_Listener.DisableHandler();
		}

		bool WasEnabled() const noexcept {
			return m_bEnabled;
		}

		bool WasDisabled() const noexcept {
			return m_bDisabled;
		}

	private:
		Detours::Exception::ExceptionListener m_Listener;
		bool m_bEnabled;
		bool m_bDisabled;
	};

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4073)
#pragma init_seg(lib)
	GlobalExceptionListenerFixture g_GlobalExceptionListenerFixture;
#pragma warning(pop)
#elif defined(__GNUC__)
	GlobalExceptionListenerFixture g_GlobalExceptionListenerFixture __attribute__((init_priority(200)));
#else
	GlobalExceptionListenerFixture g_GlobalExceptionListenerFixture;
#endif

#if defined(_MSC_VER)
#define DETOURS_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DETOURS_TEST_NOINLINE __attribute__((noinline))
#else
#define DETOURS_TEST_NOINLINE
#endif

	DETOURS_TEST_NOINLINE int GlobalInlineHookTarget(int const nValue) {
		volatile int nResult = nValue + 17;
		nResult ^= 0x1357;
		nResult ^= 0x1357;
		return nResult;
	}

	DETOURS_TEST_NOINLINE int GlobalInlineHookCallBack(int const nValue) {
		return nValue - 29;
	}

	class GlobalInlineHookFixture {
	public:
		GlobalInlineHookFixture() :
			m_Hook(reinterpret_cast<void*>(GlobalInlineHookTarget))
		{
			m_bInstalled = m_Hook.Hook(reinterpret_cast<void*>(GlobalInlineHookCallBack), false, true);
			m_bRedirectObserved = m_bInstalled && (GlobalInlineHookTarget(41) == 12);
		}

		~GlobalInlineHookFixture() noexcept {
			if (m_bInstalled) {
				m_Hook.UnHook(true);
			}
		}

		bool WasInstalled() const noexcept {
			return m_bInstalled;
		}

		bool WasRedirectObserved() const noexcept {
			return m_bRedirectObserved;
		}

		bool IsRedirectActive() const noexcept {
			return m_bInstalled && (GlobalInlineHookTarget(53) == 24);
		}

	private:
		Detours::Hook::InlineHook m_Hook;
		bool m_bInstalled;
		bool m_bRedirectObserved;
	};

#if defined(_MSC_VER)
	GlobalInlineHookFixture g_GlobalInlineHookFixture;
#elif defined(__GNUC__)
	GlobalInlineHookFixture g_GlobalInlineHookFixture __attribute__((init_priority(201)));
#else
	GlobalInlineHookFixture g_GlobalInlineHookFixture;
#endif
} // namespace

#undef DETOURS_TEST_NOINLINE

#if defined(_WIN32)
WindowsTemporaryModule::~WindowsTemporaryModule() noexcept {
	Clear();
}

bool WindowsTemporaryModule::Create() {
	Clear();

	wchar_t szSystemDirectory[MAX_PATH] {};
	UINT const unSystemDirectoryLength = GetSystemDirectoryW(szSystemDirectory, static_cast<UINT>(std::size(szSystemDirectory)));
	if (!unSystemDirectoryLength ||
		(unSystemDirectoryLength >= std::size(szSystemDirectory))) {
		return false;
	}

	wchar_t szTemporaryDirectory[MAX_PATH] {};
	DWORD const unTemporaryDirectoryLength = GetTempPathW(static_cast<DWORD>(std::size(szTemporaryDirectory)), szTemporaryDirectory);
	if (!unTemporaryDirectoryLength ||
		(unTemporaryDirectoryLength >= std::size(szTemporaryDirectory))) {
		return false;
	}

	std::wstring strSourcePath(szSystemDirectory, unSystemDirectoryLength);
	if (!strSourcePath.empty() && (strSourcePath.back() != L'\\')) {
		strSourcePath.push_back(L'\\');
	}

	strSourcePath += kWindowsTemporaryModuleSourceName;

	for (std::size_t unAttempt = 0;
		 unAttempt < kWindowsTemporaryModuleCreateAttemptCount;
		 ++unAttempt) {
		wchar_t szTemporaryFile[MAX_PATH] {};
		if (!GetTempFileNameW(szTemporaryDirectory, kWindowsTemporaryModulePrefix, 0, szTemporaryFile)) {
			return false;
		}

		std::wstring strCandidatePath(szTemporaryFile);
		if (!DeleteFileW(szTemporaryFile)) {
			return false;
		}

		std::size_t const unExtensionOffset = strCandidatePath.find_last_of(L'.');
		if (unExtensionOffset == std::wstring::npos) {
			return false;
		}

		strCandidatePath.replace(unExtensionOffset, std::wstring::npos, L".dll");

		if (CopyFileW(strSourcePath.c_str(), strCandidatePath.c_str(), TRUE)) {
			m_strPath = std::move(strCandidatePath);
			break;
		}

		if (GetLastError() != ERROR_FILE_EXISTS) {
			return false;
		}
	}

	if (m_strPath.empty()) {
		return false;
	}

	m_hModule = LoadLibraryW(m_strPath.c_str());
	if (!m_hModule) {
		Clear();
		return false;
	}

	std::size_t const unBaseNameOffset = m_strPath.find_last_of(L"\\/");
	wchar_t const* const szBaseName = m_strPath.c_str() +
		((unBaseNameOffset == std::wstring::npos) ? 0 : (unBaseNameOffset + 1));
	for (wchar_t const* szCurrent = szBaseName; *szCurrent; ++szCurrent) {
		if (*szCurrent > 0x7F) {
			Clear();
			return false;
		}

		m_strAnsiBaseName.push_back(static_cast<char>(*szCurrent));
	}

	return !m_strAnsiBaseName.empty();
}

bool WindowsTemporaryModule::ReleaseCallerReference() noexcept {
	if (!m_hModule || !FreeLibrary(m_hModule)) {
		return false;
	}

	m_hModule = nullptr;
	return true;
}

HMODULE WindowsTemporaryModule::GetModule() const noexcept {
	return m_hModule;
}

wchar_t const* WindowsTemporaryModule::GetPath() const noexcept {
	return m_strPath.c_str();
}

char const* WindowsTemporaryModule::GetAnsiBaseName() const noexcept {
	return m_strAnsiBaseName.c_str();
}

void WindowsTemporaryModule::Clear() noexcept {
	if (m_hModule) {
		FreeLibrary(m_hModule);
		m_hModule = nullptr;
	}

	if (!m_strPath.empty()) {
		DeleteFileW(m_strPath.c_str());
		m_strPath.clear();
	}

	m_strAnsiBaseName.clear();
}
#endif

template <typename Function>
static ScopeExit<Function> MakeScopeExit(Function FunctionObject) {
	return ScopeExit<Function>(std::move(FunctionObject));
}

static bool CollectNewNoAccessTestPages(std::vector<TestMemoryRange> const& vecBefore, std::vector<TestMemoryRange> const& vecAfter, void* pExcludedAddress, std::size_t unExcludedSize, std::size_t unPageSize, std::vector<void*>* pPages) {
	if (!unPageSize || !pPages || (!pExcludedAddress && unExcludedSize)) {
		return false;
	}

	static_assert(sizeof(std::uintptr_t) == sizeof(std::size_t), "address and size widths must match");
	const std::uintptr_t unPageExtent = static_cast<std::uintptr_t>(unPageSize);
	const std::uintptr_t unExcludedAddress = reinterpret_cast<std::uintptr_t>(pExcludedAddress);
	const std::uintptr_t unExcludedSizeValue = static_cast<std::uintptr_t>(unExcludedSize);
	if (unExcludedSizeValue > (std::numeric_limits<std::uintptr_t>::max() - unExcludedAddress)) {
		return false;
	}

	const std::uintptr_t unExcludedEnd = unExcludedAddress + unExcludedSizeValue;

	pPages->clear();
	std::size_t unBeforeIndex = 0;
	try {
		for (auto const& AfterRange : vecAfter) {
			if ((AfterRange.m_unBeginAddress >= AfterRange.m_unEndAddress) ||
				(AfterRange.m_unBeginAddress % unPageExtent) ||
				(AfterRange.m_unEndAddress % unPageExtent)) {
				pPages->clear();
				return false;
			}

			std::uintptr_t unCurrentAddress = AfterRange.m_unBeginAddress;
			while (unCurrentAddress < AfterRange.m_unEndAddress) {
				while ((unBeforeIndex < vecBefore.size()) &&
					   (vecBefore[unBeforeIndex].m_unEndAddress <= unCurrentAddress)) {
					++unBeforeIndex;
				}

				if ((unBeforeIndex < vecBefore.size()) &&
					(vecBefore[unBeforeIndex].m_unBeginAddress <= unCurrentAddress)) {
					if (vecBefore[unBeforeIndex].m_unEndAddress <= unCurrentAddress) {
						pPages->clear();
						return false;
					}

					unCurrentAddress = std::min(AfterRange.m_unEndAddress, vecBefore[unBeforeIndex].m_unEndAddress);
					continue;
				}

				std::uintptr_t unNewRangeEnd = AfterRange.m_unEndAddress;
				if (unBeforeIndex < vecBefore.size()) {
					unNewRangeEnd = std::min(unNewRangeEnd, vecBefore[unBeforeIndex].m_unBeginAddress);
				}

				if ((unNewRangeEnd <= unCurrentAddress) || (unNewRangeEnd % unPageExtent)) {
					pPages->clear();
					return false;
				}

				while (unCurrentAddress < unNewRangeEnd) {
					if (unPageExtent > (std::numeric_limits<std::uintptr_t>::max() - unCurrentAddress)) {
						pPages->clear();
						return false;
					}

					const std::uintptr_t unPageEnd = unCurrentAddress + unPageExtent;
					if (!unExcludedSizeValue || (unPageEnd <= unExcludedAddress) || (unCurrentAddress >= unExcludedEnd)) {
						pPages->emplace_back(reinterpret_cast<void*>(unCurrentAddress));
					}

					unCurrentAddress = unPageEnd;
				}
			}
		}
	} catch (...) {
		pPages->clear();
		return false;
	}

	return true;
}

static bool IsTestMemoryAddressNoAccess(std::vector<TestMemoryRange> const& vecRanges, void* pAddress) noexcept {
	const std::uintptr_t unAddress = reinterpret_cast<std::uintptr_t>(pAddress);
	for (auto const& Range : vecRanges) {
		if (unAddress < Range.m_unBeginAddress) {
			return false;
		}

		if (unAddress < Range.m_unEndAddress) {
			return true;
		}
	}

	return false;
}

template <typename Predicate>
static bool WaitForTestCondition(Predicate Condition, unsigned int unMilliseconds) {
	auto const EndTime =
		std::chrono::steady_clock::now() + std::chrono::milliseconds(unMilliseconds);
	while (!Condition()) {
		if (std::chrono::steady_clock::now() >= EndTime) {
			return false;
		}

		std::this_thread::yield();
	}

	return true;
}

#if defined(_WIN32)
template <typename Function>
static bool RunWindowsNamedModuleReferenceLifetimeTest(Function FunctionObject) {
	WindowsTemporaryModule Module;
	if (!Module.Create()) {
		return false;
	}

	std::atomic<bool> bCallCompleted { false };
	std::atomic<bool> bCallSucceeded { false };
	std::thread Worker([&]() {
		try {
			bCallSucceeded.store(FunctionObject(Module), std::memory_order_release);
		} catch (...) {
			bCallSucceeded.store(false, std::memory_order_release);
		}

		bCallCompleted.store(true, std::memory_order_release);
	});
	auto WorkerCleanup = MakeScopeExit([&Worker]() {
		if (Worker.joinable()) {
			Worker.join();
		}
	});

	if (!Module.ReleaseCallerReference()) {
		return false;
	}

	if (!WaitForTestCondition([&bCallCompleted]() {
			return bCallCompleted.load(std::memory_order_acquire);
		},
			kWindowsModuleReferenceWaitMilliseconds)) {
		return false;
	}

	Worker.join();
	WorkerCleanup.Release();

	HMODULE hReleasedModule = nullptr;
	bool const bReferenceReleased =
		!GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			Module.GetPath(),
			&hReleasedModule);
	return bReferenceReleased && bCallSucceeded.load(std::memory_order_acquire);
}
#endif

template <typename Function>
static bool RetryTestCleanup(Function CleanupFunction) noexcept {
	for (std::size_t unAttempt = 0; unAttempt < kTestCleanupAttemptCount; ++unAttempt) {
		if (CleanupFunction()) {
			return true;
		}

		std::this_thread::yield();
	}

	return false;
}

static void ParallelSuccessCallBack(void* pData) {
	std::atomic<unsigned int>* const pCalls = static_cast<std::atomic<unsigned int>*>(pData);
	if (pCalls) {
		pCalls->fetch_add(1, std::memory_order_relaxed);
	}
}

static void ParallelThrowingCallBack(void*) {
	throw std::runtime_error("parallel callback failure");
}

static void ThreadSelfActionCallBack(void* pData) {
	ThreadSelfActionData* const pActionData = static_cast<ThreadSelfActionData*>(pData);
	if (!pActionData) {
		return;
	}

	while (!pActionData->m_bProceed.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}

	if (!pActionData->m_pThread) {
		pActionData->m_bCompleted.store(true, std::memory_order_release);
		return;
	}

	if (pActionData->m_bDestroy) {
		delete pActionData->m_pThread;
		pActionData->m_bSucceeded.store(true, std::memory_order_release);
	} else if (pActionData->m_bSuspend) {
		pActionData->m_bSucceeded.store(pActionData->m_pThread->Suspend(), std::memory_order_release);
	} else {
		pActionData->m_bSucceeded.store(pActionData->m_pThread->Join(), std::memory_order_release);
	}

	pActionData->m_bActionCompleted.store(true, std::memory_order_release);
	while (pActionData->m_bWaitAfterAction &&
		!pActionData->m_bRelease.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}

	pActionData->m_bCompleted.store(true, std::memory_order_release);
}

static ProtectedStressResult RunProtectedMemoryStress(volatile unsigned int* pValues) {
	ProtectedStressResult Result {};
	if (!pValues) {
		Result.m_unFailures = 1;
		return Result;
	}

	std::atomic<unsigned int> unFailures = 0;
	std::atomic<unsigned int> unReady = 0;
	std::atomic<bool> bStart = false;
	std::mutex AccessMutex;
	std::vector<std::thread> vecThreads;
	vecThreads.reserve(kProtectedStressThreadCount);
	auto ThreadsCleanup = MakeScopeExit([&vecThreads, &bStart]() {
		bStart.store(true, std::memory_order_release);
		for (auto& Thread : vecThreads) {
			if (Thread.joinable()) {
				Thread.join();
			}
		}
	});

	for (std::size_t unThread = 0; unThread < kProtectedStressThreadCount; ++unThread) {
		vecThreads.emplace_back([pValues, unThread, &unFailures, &unReady, &bStart, &AccessMutex]() {
			unReady.fetch_add(1, std::memory_order_acq_rel);
			while (!bStart.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			volatile unsigned int* const pValue = pValues + unThread;
			for (std::size_t unIteration = 0; unIteration < kProtectedStressIterations; ++unIteration) {
				std::lock_guard<std::mutex> AccessLock(AccessMutex);
				unsigned int const unExpectedValue = static_cast<unsigned int>(unIteration + 1);
				*pValue = unExpectedValue;
				if (*pValue != unExpectedValue) {
					unFailures.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}

	if (!WaitForTestCondition([&unReady]() {
			return unReady.load(std::memory_order_acquire) == kProtectedStressThreadCount;
		},
							  kParallelThreadWaitMilliseconds)) {
		unFailures.fetch_add(1, std::memory_order_relaxed);
	}

	bStart.store(true, std::memory_order_release);

	for (auto& Thread : vecThreads) {
		Thread.join();
	}

	ThreadsCleanup.Release();

	for (std::size_t unThread = 0; unThread < kProtectedStressThreadCount; ++unThread) {
		Result.m_unValue += pValues[unThread];
	}

	Result.m_unFailures = unFailures.load(std::memory_order_relaxed);
	return Result;
}

static MutexStressResult RunMutexStress() {
	MutexStressResult Result {};
	Detours::Sync::Mutex Mutex;
	if (!Mutex.GetMutex()) {
		Result.m_unFailures = 1;
		return Result;
	}

	std::atomic<unsigned int> unFailures = 0;
	std::atomic<unsigned int> unReady = 0;
	std::atomic<bool> bStart = false;
	std::atomic<unsigned int> unCriticalOwners = 0;
	std::atomic<unsigned int> unValue = 0;
	std::vector<std::thread> vecThreads;
	vecThreads.reserve(kMutexStressThreadCount);
	auto ThreadsCleanup = MakeScopeExit([&vecThreads, &bStart]() {
		bStart.store(true, std::memory_order_release);
		for (auto& Thread : vecThreads) {
			if (Thread.joinable()) {
				Thread.join();
			}
		}
	});

	for (std::size_t unThread = 0; unThread < kMutexStressThreadCount; ++unThread) {
		vecThreads.emplace_back([&Mutex, &unFailures, &unReady, &bStart, &unCriticalOwners, &unValue]() {
			unReady.fetch_add(1, std::memory_order_acq_rel);
			while (!bStart.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			for (std::size_t unIteration = 0; unIteration < kMutexStressIterations; ++unIteration) {
				if (!Mutex.Lock()) {
					unFailures.fetch_add(1, std::memory_order_relaxed);
					continue;
				}

				if (unCriticalOwners.fetch_add(1, std::memory_order_acq_rel) != 0) {
					unFailures.fetch_add(1, std::memory_order_relaxed);
				}

				unValue.fetch_add(1, std::memory_order_relaxed);
				if (unCriticalOwners.fetch_sub(1, std::memory_order_acq_rel) != 1) {
					unFailures.fetch_add(1, std::memory_order_relaxed);
				}

				if (!Mutex.UnLock()) {
					std::abort();
				}
			}
		});
	}

	if (!WaitForTestCondition([&unReady]() {
			return unReady.load(std::memory_order_acquire) == kMutexStressThreadCount;
		},
							  kParallelThreadWaitMilliseconds)) {
		unFailures.fetch_add(1, std::memory_order_relaxed);
	}

	bStart.store(true, std::memory_order_release);

	for (auto& Thread : vecThreads) {
		Thread.join();
	}

	ThreadsCleanup.Release();

	Result.m_unValue = unValue.load(std::memory_order_relaxed);
	Result.m_unFailures = unFailures.load(std::memory_order_relaxed);
	return Result;
}

static void ProtectedMemoryRollbackHook(
#if defined(_WIN32)
	CONTEXT* const,
#elif defined(__linux__)
	ucontext_t* const,
#endif
	void const* const,
	Detours::Hook::MEMORY_HOOK_OPERATION,
	void const* const,
	void const* const) {
}

static std::size_t GetInlineUnHookPageSize() noexcept {
#if defined(_WIN32)
	SYSTEM_INFO SystemInformation {};
	GetSystemInfo(&SystemInformation);
	return static_cast<std::size_t>(SystemInformation.dwPageSize);
#elif defined(__linux__)
	long const nPageSize = ::sysconf(_SC_PAGESIZE);
	return nPageSize > 0 ? static_cast<std::size_t>(nPageSize) : 0;
#endif
}

static void DestroyInlineUnHookCodeFixture(InlineUnHookCodeFixture* const pFixture) noexcept {
	if (!pFixture || !pFixture->m_pMapping || !pFixture->m_unMappingSize) {
		return;
	}

#if defined(_WIN32)
	VirtualFree(pFixture->m_pMapping, 0, MEM_RELEASE);
#elif defined(__linux__)
	::munmap(pFixture->m_pMapping, pFixture->m_unMappingSize);
#endif
	pFixture->m_pMapping = nullptr;
	pFixture->m_unMappingSize = 0;
	pFixture->m_pTarget = nullptr;
	pFixture->m_pRedirect = nullptr;
	pFixture->m_pLauncher = nullptr;
	pFixture->m_pBlocker = nullptr;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int InlineWrapperCallbackTarget() noexcept {
	return kInlineUnHookOriginalValue;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int InlineWrapperBlockingCallback() noexcept {
	g_bInlineWrapperCallbackEntered.store(true, std::memory_order_release);
	while (!g_bInlineWrapperCallbackRelease.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}

	using fnInlineWrapperTarget = int (*)();
	void* const pTrampoline = g_pInlineWrapperCallbackHook ?
		g_pInlineWrapperCallbackHook->GetTrampoline() : nullptr;
	volatile int nResult = pTrampoline ?
		reinterpret_cast<fnInlineWrapperTarget>(pTrampoline)() : 0;
	return nResult;
}

static void InlineUnHookBlocker() noexcept {
	g_bInlineUnHookBlockerEntered.store(true, std::memory_order_release);
	while (!g_bInlineUnHookBlockerRelease.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
}

static int InlineUnHookReplacement() {
	using fnInlineUnHookTarget = int (*)();
	InlineUnHookBlocker();
	void* const pTrampoline = g_pInlineUnHook ? g_pInlineUnHook->GetTrampoline() : nullptr;
	volatile int nResult = pTrampoline ?
		reinterpret_cast<fnInlineUnHookTarget>(pTrampoline)() : 0;
	return nResult;
}

static bool CreateInlineUnHookCodeFixture(InlineUnHookCodeFixture* const pFixture) noexcept {
	if (!pFixture || pFixture->m_pMapping) {
		return false;
	}

	std::size_t const unPageSize = GetInlineUnHookPageSize();
	if (unPageSize <= (kInlineUnHookRedirectOffset + 16)) {
		return false;
	}

#if defined(_WIN32)
	void* const pMapping = VirtualAlloc(nullptr, unPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#elif defined(__linux__)
	void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pMapping == MAP_FAILED) {
		return false;
	}
#endif
#if defined(_WIN32)
	if (!pMapping) {
		return false;
	}
#endif

	InlineUnHookCodeFixture Fixture {};
	Fixture.m_pMapping = pMapping;
	Fixture.m_unMappingSize = unPageSize;
	Fixture.m_pTarget = pMapping;
	Fixture.m_pRedirect = static_cast<unsigned char*>(pMapping) + kInlineUnHookRedirectOffset;
	auto MappingCleanup = MakeScopeExit([&Fixture]() {
		DestroyInlineUnHookCodeFixture(&Fixture);
	});

	std::memset(pMapping, 0xCC, unPageSize);
	unsigned char* const pTarget = static_cast<unsigned char*>(Fixture.m_pTarget);
	unsigned char* const pRedirect = static_cast<unsigned char*>(Fixture.m_pRedirect);
#if defined(DETOURS_ARCH_X64)
#if defined(_WIN32)
	constexpr unsigned char kStackAllocation = 0x28;
#elif defined(__linux__)
	constexpr unsigned char kStackAllocation = 0x08;
#endif
	pTarget[0] = 0x48;
	pTarget[1] = 0x83;
	pTarget[2] = 0xEC;
	pTarget[3] = kStackAllocation;
	pTarget[4] = 0xFF;
	pTarget[5] = 0x15;
	std::int32_t const nBlockerDisplacement = 12;
	std::memcpy(pTarget + 6, &nBlockerDisplacement, sizeof(nBlockerDisplacement));
	pTarget[10] = 0x48;
	pTarget[11] = 0x83;
	pTarget[12] = 0xC4;
	pTarget[13] = kStackAllocation;
	pTarget[14] = 0xB8;
	std::memcpy(pTarget + 15, &kInlineUnHookOriginalValue, sizeof(kInlineUnHookOriginalValue));
	pTarget[19] = 0xC3;
	void* const pBlocker = reinterpret_cast<void*>(InlineUnHookBlocker);
	std::memcpy(pTarget + 22, &pBlocker, sizeof(pBlocker));

	pRedirect[0] = 0xFF;
	pRedirect[1] = 0x25;
	std::uint32_t const unRedirectDisplacement = 0;
	std::memcpy(pRedirect + 2, &unRedirectDisplacement, sizeof(unRedirectDisplacement));
	void* const pReplacement = reinterpret_cast<void*>(InlineUnHookReplacement);
	std::memcpy(pRedirect + 6, &pReplacement, sizeof(pReplacement));
#elif defined(DETOURS_ARCH_X86)
	pTarget[0] = 0x83;
	pTarget[1] = 0xEC;
	pTarget[2] = 0x0C;
	pTarget[3] = 0xFF;
	pTarget[4] = 0x15;
	std::uint32_t const unBlockerSlotAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pTarget + 20));
	std::memcpy(pTarget + 5, &unBlockerSlotAddress, sizeof(unBlockerSlotAddress));
	pTarget[9] = 0x83;
	pTarget[10] = 0xC4;
	pTarget[11] = 0x0C;
	pTarget[12] = 0xB8;
	std::memcpy(pTarget + 13, &kInlineUnHookOriginalValue, sizeof(kInlineUnHookOriginalValue));
	pTarget[17] = 0xC3;
	std::uint32_t const unBlockerAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(InlineUnHookBlocker));
	std::memcpy(pTarget + 20, &unBlockerAddress, sizeof(unBlockerAddress));

	pRedirect[0] = 0xB8;
	std::uint32_t const unReplacementAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(InlineUnHookReplacement));
	std::memcpy(pRedirect + 1, &unReplacementAddress, sizeof(unReplacementAddress));
	pRedirect[5] = 0xFF;
	pRedirect[6] = 0xE0;
#endif

#if defined(_WIN32)
	DWORD unOldProtection = 0;
	if (!VirtualProtect(pMapping, unPageSize, PAGE_EXECUTE_READ, &unOldProtection) ||
		!FlushInstructionCache(GetCurrentProcess(), pMapping, unPageSize)) {
		return false;
	}
#elif defined(__linux__)
	if (::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) {
		return false;
	}

	__builtin___clear_cache(static_cast<char*>(pMapping), static_cast<char*>(pMapping) + unPageSize);
#endif

	*pFixture = Fixture;
	MappingCleanup.Release();
	return true;
}

static bool CreateInlineHookInstallCodeFixture(InlineUnHookCodeFixture* const pFixture, InlineWrapperLoopState* const pState) noexcept {
	if (!pFixture || !pState || pFixture->m_pMapping) {
		return false;
	}

	InlineUnHookCodeFixture Fixture {};
	if (!CreateInlineUnHookCodeFixture(&Fixture)) {
		return false;
	}

	auto MappingCleanup = MakeScopeExit([&Fixture]() {
		DestroyInlineUnHookCodeFixture(&Fixture);
	});
	if (Fixture.m_unMappingSize <= (kInlineHookInstallBlockerOffset + 32)) {
		return false;
	}

	Fixture.m_pLauncher = static_cast<unsigned char*>(Fixture.m_pMapping) + kInlineHookInstallLauncherOffset;
	Fixture.m_pBlocker = static_cast<unsigned char*>(Fixture.m_pMapping) + kInlineHookInstallBlockerOffset;
	pState->m_unEntered.store(0, std::memory_order_relaxed);
	pState->m_unRelease.store(0, std::memory_order_relaxed);

#if defined(_WIN32)
	DWORD unOldProtection = 0;
	if (!VirtualProtect(Fixture.m_pMapping, Fixture.m_unMappingSize, PAGE_READWRITE, &unOldProtection)) {
		return false;
	}
#elif defined(__linux__)
	if (::mprotect(Fixture.m_pMapping, Fixture.m_unMappingSize, PROT_READ | PROT_WRITE) != 0) {
		return false;
	}
#endif

	unsigned char* const pTarget = static_cast<unsigned char*>(Fixture.m_pTarget);
	unsigned char* const pRedirect = static_cast<unsigned char*>(Fixture.m_pRedirect);
	unsigned char* const pLauncher = static_cast<unsigned char*>(Fixture.m_pLauncher);
	unsigned char* const pBlocker = static_cast<unsigned char*>(Fixture.m_pBlocker);
	std::memset(pTarget, 0xCC, 32);
	std::memset(pRedirect, 0xCC, 16);
	std::memset(pLauncher, 0xCC, 32);
	std::memset(pBlocker, 0xCC, 32);

	pTarget[0] = 0x53;
	pTarget[1] = 0xFF;
	pTarget[2] = 0xD0;
	pTarget[3] = 0x5B;
	pTarget[4] = 0xB8;
	std::memcpy(pTarget + 5, &kInlineUnHookOriginalValue, sizeof(kInlineUnHookOriginalValue));
	pTarget[9] = 0xC3;

	constexpr int kInlineHookInstallRedirectValue = 29;
	pRedirect[0] = 0xB8;
	std::memcpy(pRedirect + 1, &kInlineHookInstallRedirectValue, sizeof(kInlineHookInstallRedirectValue));
	pRedirect[5] = 0xC3;

#if defined(DETOURS_ARCH_X64)
	pLauncher[0] = 0xF3;
	pLauncher[1] = 0x0F;
	pLauncher[2] = 0x1E;
	pLauncher[3] = 0xFA;
	pLauncher[4] = 0x48;
	pLauncher[5] = 0xB8;
	std::memcpy(pLauncher + 6, &Fixture.m_pBlocker, sizeof(Fixture.m_pBlocker));
	pLauncher[14] = 0xE9;
	std::int32_t const nTargetDisplacement = static_cast<std::int32_t>(
		reinterpret_cast<std::intptr_t>(Fixture.m_pTarget) -
		(reinterpret_cast<std::intptr_t>(pLauncher) + 19));
	std::memcpy(pLauncher + 15, &nTargetDisplacement, sizeof(nTargetDisplacement));

	pBlocker[0] = 0xF3;
	pBlocker[1] = 0x0F;
	pBlocker[2] = 0x1E;
	pBlocker[3] = 0xFA;
	pBlocker[4] = 0x48;
	pBlocker[5] = 0xB8;
	std::memcpy(pBlocker + 6, &pState, sizeof(pState));
	pBlocker[14] = 0xC7;
	pBlocker[15] = 0x00;
	pBlocker[16] = 0x01;
	pBlocker[17] = 0x00;
	pBlocker[18] = 0x00;
	pBlocker[19] = 0x00;
	pBlocker[20] = 0x83;
	pBlocker[21] = 0x78;
	pBlocker[22] = 0x04;
	pBlocker[23] = 0x00;
	pBlocker[24] = 0x74;
	pBlocker[25] = 0xFA;
	pBlocker[26] = 0xC3;
#elif defined(DETOURS_ARCH_X86)
	pLauncher[0] = 0xF3;
	pLauncher[1] = 0x0F;
	pLauncher[2] = 0x1E;
	pLauncher[3] = 0xFB;
	pLauncher[4] = 0xB8;
	std::uint32_t const unBlockerAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(Fixture.m_pBlocker));
	std::memcpy(pLauncher + 5, &unBlockerAddress, sizeof(unBlockerAddress));
	pLauncher[9] = 0xE9;
	std::int32_t const nTargetDisplacement = static_cast<std::int32_t>(
		reinterpret_cast<std::intptr_t>(Fixture.m_pTarget) -
		(reinterpret_cast<std::intptr_t>(pLauncher) + 14));
	std::memcpy(pLauncher + 10, &nTargetDisplacement, sizeof(nTargetDisplacement));

	pBlocker[0] = 0xF3;
	pBlocker[1] = 0x0F;
	pBlocker[2] = 0x1E;
	pBlocker[3] = 0xFB;
	pBlocker[4] = 0xB8;
	std::uint32_t const unStateAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pState));
	std::memcpy(pBlocker + 5, &unStateAddress, sizeof(unStateAddress));
	pBlocker[9] = 0xC7;
	pBlocker[10] = 0x00;
	pBlocker[11] = 0x01;
	pBlocker[12] = 0x00;
	pBlocker[13] = 0x00;
	pBlocker[14] = 0x00;
	pBlocker[15] = 0x83;
	pBlocker[16] = 0x78;
	pBlocker[17] = 0x04;
	pBlocker[18] = 0x00;
	pBlocker[19] = 0x74;
	pBlocker[20] = 0xFA;
	pBlocker[21] = 0xC3;
#endif

#if defined(_WIN32)
	DWORD unUnusedProtection = 0;
	if (!VirtualProtect(Fixture.m_pMapping, Fixture.m_unMappingSize, unOldProtection, &unUnusedProtection) ||
		!FlushInstructionCache(GetCurrentProcess(), Fixture.m_pMapping, Fixture.m_unMappingSize)) {
		return false;
	}
#elif defined(__linux__)
	if (::mprotect(Fixture.m_pMapping, Fixture.m_unMappingSize, PROT_READ | PROT_EXEC) != 0) {
		return false;
	}

	__builtin___clear_cache(
		static_cast<char*>(Fixture.m_pMapping),
		static_cast<char*>(Fixture.m_pMapping) + Fixture.m_unMappingSize);
#endif

	*pFixture = Fixture;
	MappingCleanup.Release();
	return true;
}

#if defined(_WIN32) && defined(DETOURS_ARCH_X64)
static bool __fastcall BlockingCallRawHook(Detours::Hook::PRAW_CONTEXT) {
#elif defined(_WIN32) && defined(DETOURS_ARCH_X86)
static bool __cdecl BlockingCallRawHook(Detours::Hook::PRAW_CONTEXT) {
#elif defined(__linux__)
static bool BlockingCallRawHook(Detours::Hook::PRAW_CONTEXT) {
#endif
	return false;
}

template <typename HookType>
static HookType* CreateBlockingCallHook(InlineUnHookCodeFixture const* const pFixture) {
	return pFixture ? new (std::nothrow) HookType(pFixture->m_pTarget) : nullptr;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void KeepHookTargetStackCandidate(void* volatile* const ppCandidate) noexcept {
	if (!ppCandidate) {
		return;
	}

	std::atomic_signal_fence(std::memory_order_seq_cst);
	*ppCandidate;
	std::atomic_signal_fence(std::memory_order_seq_cst);
}

template <typename HookType, typename InstallFunction>
static void VerifyBlockingCallHookInstallation(InstallFunction Install) {
	std::unique_ptr<InlineUnHookCodeFixture> pFixture(new InlineUnHookCodeFixture());
	std::unique_ptr<InlineWrapperLoopState> pBlockerState(new InlineWrapperLoopState());
	REQUIRE(pFixture != nullptr);
	REQUIRE(pBlockerState != nullptr);
	REQUIRE(CreateInlineHookInstallCodeFixture(pFixture.get(), pBlockerState.get()) == true);
	auto MappingCleanup = MakeScopeExit([&pFixture]() {
		DestroyInlineUnHookCodeFixture(pFixture.get());
	});

	std::unique_ptr<HookType> pHook(CreateBlockingCallHook<HookType>(pFixture.get()));
	REQUIRE(pHook != nullptr);
	auto HookCleanup = MakeScopeExit([&pHook]() {
		pHook->UnHook();
		pHook->Release();
	});
	using fnInlineHookLauncher = int (*)();
	std::atomic<int> nTargetResult = 0;
	std::atomic<bool> bHookCompleted = false;
	bool bHooked = false;
	unsigned char* const pTargetBytes = static_cast<unsigned char*>(pFixture->m_pTarget);
	void* volatile arrFalseStackCandidates[] = {
		pTargetBytes,
		pTargetBytes + kHookTargetInsideCallCandidateOffset,
		pTargetBytes + kHookTargetInsideMoveCandidateOffset
	};
	for (auto& pFalseStackCandidate : arrFalseStackCandidates) {
		KeepHookTargetStackCandidate(&pFalseStackCandidate);
	}

	std::thread TargetThread([&pFixture, &nTargetResult]() {
		nTargetResult.store(reinterpret_cast<fnInlineHookLauncher>(pFixture->m_pLauncher)(), std::memory_order_release);
	});
	std::thread HookThread;
	auto ThreadCleanup = MakeScopeExit([&TargetThread, &HookThread, &pBlockerState]() {
		pBlockerState->m_unRelease.store(1, std::memory_order_release);
		if (TargetThread.joinable()) {
			TargetThread.join();
		}

		if (HookThread.joinable()) {
			HookThread.join();
		}
	});

	REQUIRE(WaitForTestCondition([&pBlockerState]() {
		return pBlockerState->m_unEntered.load(std::memory_order_acquire) != 0;
	},
								 kParallelThreadWaitMilliseconds));
	HookThread = std::thread([&pHook, &Install, &pFixture, &bHookCompleted, &bHooked]() {
		bHooked = Install(*pHook, *pFixture);
		bHookCompleted.store(true, std::memory_order_release);
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	CHECK(bHookCompleted.load(std::memory_order_acquire) == false);

	pBlockerState->m_unRelease.store(1, std::memory_order_release);
	TargetThread.join();
	bool const bCompletedWithFalseStackCandidate = WaitForTestCondition([&bHookCompleted]() {
		return bHookCompleted.load(std::memory_order_acquire);
	},
																		kParallelThreadWaitMilliseconds);
	for (auto& pFalseStackCandidate : arrFalseStackCandidates) {
		pFalseStackCandidate = nullptr;
		KeepHookTargetStackCandidate(&pFalseStackCandidate);
	}

	HookThread.join();
	ThreadCleanup.Release();
	CHECK(bCompletedWithFalseStackCandidate == true);
	CHECK(nTargetResult.load(std::memory_order_acquire) == kInlineUnHookOriginalValue);
	REQUIRE(bHooked == true);
	CHECK(pHook->UnHook() == true);
	bool const bReleased = pHook->Release();
	CHECK(bReleased == true);
	if (bReleased) {
		HookCleanup.Release();
	}
}

static void* GetInlineWrapperAddress(void* const pTargetAddress) noexcept {
	if (!pTargetAddress) {
		return nullptr;
	}

	unsigned char* const pTarget = static_cast<unsigned char*>(pTargetAddress);
	if (pTarget[0] == 0xE9) {
		std::int32_t nDisplacement = 0;
		std::memcpy(&nDisplacement, pTarget + 1, sizeof(nDisplacement));
		return reinterpret_cast<void*>(reinterpret_cast<std::intptr_t>(pTarget) + 5 + nDisplacement);
	}

#if defined(DETOURS_ARCH_X64)
	if ((pTarget[0] == 0xFF) && (pTarget[1] == 0x25)) {
		std::int32_t nDisplacement = 0;
		std::memcpy(&nDisplacement, pTarget + 2, sizeof(nDisplacement));
		void* pWrapper = nullptr;
		std::memcpy(&pWrapper, pTarget + 6 + nDisplacement, sizeof(pWrapper));
		return pWrapper;
	}
#elif defined(DETOURS_ARCH_X86)
	if ((pTarget[0] == 0xC7) &&
		(pTarget[1] == 0x44) &&
		(pTarget[2] == 0x24) &&
		(pTarget[3] == 0xFC)) {
		std::uint32_t unWrapperAddress = 0;
		std::memcpy(&unWrapperAddress, pTarget + 4, sizeof(unWrapperAddress));
		return reinterpret_cast<void*>(static_cast<std::uintptr_t>(unWrapperAddress));
	}
#endif

	return nullptr;
}

static bool InstallInlineWrapperLoop(void* const pWrapperAddress, InlineWrapperLoopState* const pState) noexcept {
	if (!pWrapperAddress || !pState) {
		return false;
	}

	std::array<unsigned char, HOOK_INLINE_WRAPPER_SIZE> arrCode {};
	arrCode.fill(0xCC);
#if defined(DETOURS_ARCH_X64)
	arrCode[0] = 0x48;
	arrCode[1] = 0xB8;
	std::memcpy(arrCode.data() + 2, &pState, sizeof(pState));
	arrCode[10] = 0xC7;
	arrCode[11] = 0x00;
	arrCode[12] = 0x01;
	arrCode[13] = 0x00;
	arrCode[14] = 0x00;
	arrCode[15] = 0x00;
	arrCode[16] = 0x83;
	arrCode[17] = 0x78;
	arrCode[18] = 0x04;
	arrCode[19] = 0x00;
	arrCode[20] = 0x74;
	arrCode[21] = 0xFA;
	arrCode[22] = 0xC3;
#elif defined(DETOURS_ARCH_X86)
	arrCode[0] = 0xB8;
	std::uint32_t const unStateAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pState));
	std::memcpy(arrCode.data() + 1, &unStateAddress, sizeof(unStateAddress));
	arrCode[5] = 0xC7;
	arrCode[6] = 0x00;
	arrCode[7] = 0x01;
	arrCode[8] = 0x00;
	arrCode[9] = 0x00;
	arrCode[10] = 0x00;
	arrCode[11] = 0x83;
	arrCode[12] = 0x78;
	arrCode[13] = 0x04;
	arrCode[14] = 0x00;
	arrCode[15] = 0x74;
	arrCode[16] = 0xFA;
	arrCode[17] = 0xC3;
#endif

	try {
		Detours::Memory::Protection WrapperProtection(pWrapperAddress, arrCode.size(), false);
#if defined(_WIN32)
		if (!WrapperProtection.Change(PAGE_READWRITE)) {
#elif defined(__linux__)
		if (!WrapperProtection.Change(PROT_READ | PROT_WRITE)) {
#endif
			return false;
		}

		std::memcpy(pWrapperAddress, arrCode.data(), arrCode.size());
#if defined(_WIN32)
		bool const bFlushed = FlushInstructionCache(GetCurrentProcess(), pWrapperAddress, arrCode.size()) != FALSE;
#elif defined(__linux__)
		__builtin___clear_cache(static_cast<char*>(pWrapperAddress), static_cast<char*>(pWrapperAddress) + arrCode.size());
		bool const bFlushed = true;
#endif
		return bFlushed && WrapperProtection.Restore();
	} catch (...) {
		return false;
	}
}

TEST_SUITE("Detours::Lifecycle") {
	TEST_CASE("ExceptionListener supports pre-main initialization") {
		CHECK(g_GlobalExceptionListenerFixture.WasEnabled() == true);
		CHECK(g_GlobalExceptionListenerFixture.WasDisabled() == true);
	}

	TEST_CASE("InlineHook supports pre-main initialization") {
		CHECK(g_GlobalInlineHookFixture.WasInstalled() == true);
		CHECK(g_GlobalInlineHookFixture.WasRedirectObserved() == true);
		CHECK(g_GlobalInlineHookFixture.IsRedirectActive() == true);
	}
}

TEST_SUITE("Detours::Parallel") {
	TEST_CASE("Thread reports callback failure and can restart") {
		std::atomic<unsigned int> unCalls = 0;
		Detours::Parallel::Thread Thread(ParallelThrowingCallBack, &unCalls);
		REQUIRE(Thread.Start() == true);
		CHECK(Thread.Join() == false);

		REQUIRE(Thread.SetCallBack(ParallelSuccessCallBack) == true);
		REQUIRE(Thread.Start() == true);
		CHECK(Thread.Join() == true);
		CHECK(unCalls.load(std::memory_order_relaxed) == 1);
	}

	TEST_CASE("Thread rejects self-join without detaching") {
		std::unique_ptr<ThreadSelfActionData> pActionData =
			std::make_unique<ThreadSelfActionData>();
		pActionData->m_bWaitAfterAction = true;
		std::unique_ptr<Detours::Parallel::Thread> pThread =
			std::make_unique<Detours::Parallel::Thread>(ThreadSelfActionCallBack, pActionData.get());
		pActionData->m_pThread = pThread.get();
		REQUIRE(pThread->Start() == true);
		pActionData->m_bProceed.store(true, std::memory_order_release);

		bool const bActionCompleted = WaitForTestCondition([&pActionData]() {
			return pActionData->m_bActionCompleted.load(std::memory_order_acquire);
		},
											 kParallelThreadWaitMilliseconds);
		CHECK(bActionCompleted == true);
		if (!bActionCompleted) {
			pThread.release();
			pActionData.release();
			return;
		}

		auto ReleaseGuard = MakeScopeExit([&pActionData]() noexcept {
			pActionData->m_bRelease.store(true, std::memory_order_release);
		});

		CHECK(pActionData->m_bSucceeded.load(std::memory_order_acquire) == false);
		CHECK(pThread->Suspend() == true);
		CHECK(pThread->Resume() == true);
		pActionData->m_bRelease.store(true, std::memory_order_release);
		REQUIRE(WaitForTestCondition([&pActionData]() {
			return pActionData->m_bCompleted.load(std::memory_order_acquire);
		},
			kParallelThreadWaitMilliseconds));
		CHECK(pThread->Join() == true);
		ReleaseGuard.Release();
	}

	TEST_CASE("Thread rejects self-suspend") {
		std::unique_ptr<ThreadSelfActionData> pActionData =
			std::make_unique<ThreadSelfActionData>();
		pActionData->m_bSuspend = true;
		std::unique_ptr<Detours::Parallel::Thread> pThread =
			std::make_unique<Detours::Parallel::Thread>(
			ThreadSelfActionCallBack, pActionData.get());
		pActionData->m_pThread = pThread.get();
		REQUIRE(pThread->Start() == true);
		pActionData->m_bProceed.store(true, std::memory_order_release);

		REQUIRE(WaitForTestCondition([&pActionData]() {
			return pActionData->m_bCompleted.load(std::memory_order_acquire);
		},
			kParallelThreadWaitMilliseconds));
		CHECK(pActionData->m_bSucceeded.load(std::memory_order_acquire) == false);
		CHECK(pThread->Join() == true);
	}

	TEST_CASE("Thread can destroy itself") {
		std::unique_ptr<ThreadSelfActionData> pActionData =
			std::make_unique<ThreadSelfActionData>();
		pActionData->m_bDestroy = true;
		std::unique_ptr<Detours::Parallel::Thread> pThread =
			std::make_unique<Detours::Parallel::Thread>(ThreadSelfActionCallBack, pActionData.get());
		pActionData->m_pThread = pThread.get();
		REQUIRE(pThread->Start() == true);
		pThread.release();
		pActionData->m_bProceed.store(true, std::memory_order_release);

		bool const bCompleted = WaitForTestCondition([&pActionData]() {
			return pActionData->m_bCompleted.load(std::memory_order_acquire);
		},
													 kParallelThreadWaitMilliseconds);
		CHECK(bCompleted == true);
		if (!bCompleted) {
			pActionData.release();
			return;
		}

		CHECK(pActionData->m_bSucceeded.load(std::memory_order_acquire) == true);
	}

	TEST_CASE("Fiber contains callback exceptions and remains reusable") {
#if defined(_WIN32)
		REQUIRE(IsThreadAFiber() == FALSE);
#endif
		std::atomic<unsigned int> unCalls = 0;
		Detours::Parallel::Fiber Fiber(ParallelThrowingCallBack, &unCalls);
		bool bSwitchResult = true;
		CHECK_NOTHROW(bSwitchResult = Fiber.Switch());
		CHECK(bSwitchResult == false);
#if defined(_WIN32)
		CHECK(IsThreadAFiber() == FALSE);
#endif

		REQUIRE(Fiber.SetCallBack(ParallelSuccessCallBack) == true);
		CHECK(Fiber.Switch() == true);
		CHECK(unCalls.load(std::memory_order_relaxed) == 1);
#if defined(_WIN32)
		CHECK(IsThreadAFiber() == FALSE);
#endif
	}
} // TEST_SUITE("Detours::Parallel")

TEST_SUITE("Detours::NamedObject") {
	TEST_CASE("Name getters reject undersized buffers without writing") {
		auto CheckNameGetter = [](auto& ServerReference, auto fnGetName) {
			constexpr TestNamedObjectCharacter kCanary = static_cast<TestNamedObjectCharacter>('#');
			TestNamedObjectCharacter szName[Detours::kNamedObjectNameCapacity] {};
			REQUIRE((ServerReference.*fnGetName)(szName, std::size(szName)) == true);
			CHECK(szName[0] != 0);

			TestNamedObjectCharacter szSmallName[1] { kCanary };
			CHECK((ServerReference.*fnGetName)(szSmallName, std::size(szSmallName)) == false);
			CHECK(szSmallName[0] == kCanary);
		};

		Detours::Sync::EventServer EventServer;
		Detours::Sync::MutexServer MutexServer;
		Detours::Sync::SemaphoreServer SemaphoreServer;
		Detours::Pipe::PipeServer PipeServer(1);
		Detours::Memory::SharedServer SharedServer(1);
		CheckNameGetter(EventServer, static_cast<EventNameGetter>(&Detours::Sync::EventServer::GetEventName));
		CheckNameGetter(MutexServer, static_cast<MutexNameGetter>(&Detours::Sync::MutexServer::GetMutexName));
		CheckNameGetter(SemaphoreServer, static_cast<SemaphoreNameGetter>(&Detours::Sync::SemaphoreServer::GetSemaphoreName));
		CheckNameGetter(PipeServer, static_cast<PipeNameGetter>(&Detours::Pipe::PipeServer::GetPipeName));
		CheckNameGetter(SharedServer, static_cast<SharedNameGetter>(&Detours::Memory::SharedServer::GetSharedName));
	}
} // TEST_SUITE("Detours::NamedObject")

TEST_SUITE("Detours::Memory") {
	TEST_CASE("Protected and Secure memory protection API") {
		auto CheckProtectionPolicy = [](auto& Memory) {
			TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
			CHECK(Memory.GetProtection(nullptr) == false);
			REQUIRE(Memory.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryDefaultTestProtection);

			REQUIRE(Memory.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
			REQUIRE(Memory.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);

			CHECK(Memory.SetProtection(kProtectedMemoryInvalidTestProtection) == false);
			REQUIRE(Memory.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		};

		Detours::Memory::ProtectedPage ProtectedPage;
		Detours::Memory::ProtectedRange ProtectedRange(37);
		Detours::Memory::ProtectedStorage ProtectedStorage(128);
		Detours::Memory::SecurePage SecurePage;
		Detours::Memory::SecureRange SecureRange(37);
		Detours::Memory::SecureStorage SecureStorage(128);
		CheckProtectionPolicy(ProtectedPage);
		CheckProtectionPolicy(ProtectedRange);
		CheckProtectionPolicy(ProtectedStorage);
		CheckProtectionPolicy(SecurePage);
		CheckProtectionPolicy(SecureRange);
		CheckProtectionPolicy(SecureStorage);

		TestMemoryProtection flReleasedProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(ProtectedPage.Release() == true);
		CHECK(ProtectedPage.GetProtection(&flReleasedProtection) == false);
		CHECK(ProtectedPage.SetProtection(kProtectedMemoryReadOnlyTestProtection) == false);
		REQUIRE(ProtectedRange.Release() == true);
		CHECK(ProtectedRange.GetProtection(&flReleasedProtection) == false);
		CHECK(ProtectedRange.SetProtection(kProtectedMemoryReadOnlyTestProtection) == false);
		REQUIRE(SecurePage.Release() == true);
		CHECK(SecurePage.GetProtection(&flReleasedProtection) == false);
		CHECK(SecurePage.SetProtection(kProtectedMemoryReadOnlyTestProtection) == false);
		REQUIRE(SecureRange.Release() == true);
		CHECK(SecureRange.GetProtection(&flReleasedProtection) == false);
		CHECK(SecureRange.SetProtection(kProtectedMemoryReadOnlyTestProtection) == false);
	}











	TEST_CASE("Protected and Secure storage protection policy") {
		Detours::Memory::ProtectedStorage ProtectedStorage(128);
		REQUIRE(ProtectedStorage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		void* const pFirstProtectedAddress = ProtectedStorage.Alloc(31);
		REQUIRE(pFirstProtectedAddress != nullptr);
		Detours::Memory::ProtectedRange FirstProtectedRange(pFirstProtectedAddress, 31);
		REQUIRE(FirstProtectedRange.GetRangeAddress() == pFirstProtectedAddress);

		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(FirstProtectedRange.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		REQUIRE(ProtectedStorage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
		REQUIRE(FirstProtectedRange.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);

		void* const pSecondProtectedAddress = ProtectedStorage.Alloc(29);
		REQUIRE(pSecondProtectedAddress != nullptr);
		Detours::Memory::ProtectedRange SecondProtectedRange(pSecondProtectedAddress, 29);
		REQUIRE(SecondProtectedRange.GetRangeAddress() == pSecondProtectedAddress);
		REQUIRE(SecondProtectedRange.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		CHECK(ProtectedStorage.SetProtection(kProtectedMemoryInvalidTestProtection) == false);
		REQUIRE(FirstProtectedRange.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		REQUIRE(SecondProtectedRange.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);

		Detours::Memory::SecureStorage SecureStorage(128);
		REQUIRE(SecureStorage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		void* const pFirstSecureAddress = SecureStorage.Alloc(31);
		REQUIRE(pFirstSecureAddress != nullptr);
		Detours::Memory::ProtectedRange FirstSecureRangeView(pFirstSecureAddress, 31);
		REQUIRE(FirstSecureRangeView.GetRangeAddress() == pFirstSecureAddress);
		REQUIRE(FirstSecureRangeView.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		REQUIRE(SecureStorage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
		REQUIRE(FirstSecureRangeView.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);

		void* const pSecondSecureAddress = SecureStorage.Alloc(29);
		REQUIRE(pSecondSecureAddress != nullptr);
		Detours::Memory::ProtectedRange SecondSecureRangeView(pSecondSecureAddress, 29);
		REQUIRE(SecondSecureRangeView.GetRangeAddress() == pSecondSecureAddress);
		REQUIRE(SecondSecureRangeView.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		CHECK(SecureStorage.SetProtection(kProtectedMemoryInvalidTestProtection) == false);
		REQUIRE(FirstSecureRangeView.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		REQUIRE(SecondSecureRangeView.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);

		REQUIRE(ProtectedStorage.DeAllocAll() == true);
		CHECK(ProtectedStorage.IsStorageEmpty() == true);
		REQUIRE(ProtectedStorage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		REQUIRE(SecureStorage.DeAllocAll() == true);
		CHECK(SecureStorage.IsStorageEmpty() == true);
		REQUIRE(SecureStorage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
	}

	TEST_CASE("ProtectedPage wraps SecurePage-owned memory") {
		Detours::Memory::SecurePage SecurePage;
		void* const pPageAddress = SecurePage.GetPageAddress();
		std::size_t const unPageCapacity = SecurePage.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);

		volatile unsigned char* pData = nullptr;
		{
			Detours::Memory::ProtectedPage ProtectedPage(pPageAddress, unPageCapacity);
			REQUIRE(ProtectedPage.GetPageAddress() == pPageAddress);
			REQUIRE(ProtectedPage.GetPageCapacity() == unPageCapacity);
			REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
			CHECK(ProtectedPage.IsProtected() == true);
			CHECK(SecurePage.IsSecured() == true);

			pData = static_cast<volatile unsigned char*>(ProtectedPage.Alloc(1));
			REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
			*pData = 0x5A;
			REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadOnlyTestProtection) == true);
			REQUIRE(SecurePage.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadOnlyTestProtection);
			CHECK(*pData == 0x5A);
			CHECK(ProtectedPage.GetDataSize() == 1);
			CHECK(SecurePage.GetDataSize() == 1);
			CHECK(ProtectedPage.IsCompromised() == false);
			CHECK(SecurePage.IsCompromised() == false);
		}

		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadOnlyTestProtection);
		CHECK(*pData == 0x5A);
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);
	}

	TEST_CASE("SecurePage wraps ProtectedPage-owned memory") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		std::size_t const unPageCapacity = ProtectedPage.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);

		volatile unsigned char* pData = nullptr;
		{
			Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
			REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
			REQUIRE(SecurePage.GetPageCapacity() == unPageCapacity);
			REQUIRE(SecurePage.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
			CHECK(SecurePage.IsSecured() == true);
			CHECK(ProtectedPage.IsProtected() == true);

			pData = static_cast<volatile unsigned char*>(SecurePage.Alloc(1));
			REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
			*pData = 0xA5;
			REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadOnlyTestProtection) == true);
			REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
			CHECK(flProtection == kProtectedMemoryReadOnlyTestProtection);
			CHECK(*pData == 0xA5);
			CHECK(SecurePage.GetDataSize() == 1);
			CHECK(ProtectedPage.GetDataSize() == 1);
			CHECK(SecurePage.IsCompromised() == false);
			CHECK(ProtectedPage.IsCompromised() == false);
		}

		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
		REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadOnlyTestProtection);
		CHECK(*pData == 0xA5);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);
	}

	TEST_CASE("ProtectedPage executes protected code") {
		constexpr unsigned char kCode[] = { 0xB0, 0x01, 0xC3 };
		Detours::Memory::ProtectedPage ProtectedPage;
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		volatile unsigned char* const pCode =
			static_cast<volatile unsigned char*>(ProtectedPage.Alloc(sizeof(kCode)));
		REQUIRE(const_cast<unsigned char*>(pCode) != nullptr);

		for (std::size_t unIndex = 0; unIndex < sizeof(kCode); ++unIndex) {
			pCode[unIndex] = kCode[unIndex];
		}

		unsigned char* const pExecutableCode = const_cast<unsigned char*>(pCode);
#if defined(_WIN32)
		REQUIRE(FlushInstructionCache(GetCurrentProcess(), pExecutableCode, sizeof(kCode)) != FALSE);
		using fnProtectedCode = bool(__cdecl*)();
#elif defined(__linux__)
		__builtin___clear_cache(
			reinterpret_cast<char*>(pExecutableCode),
			reinterpret_cast<char*>(pExecutableCode + sizeof(kCode)));
		using fnProtectedCode = bool (*)();
#endif

		REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
		REQUIRE(ProtectedPage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		CHECK(reinterpret_cast<fnProtectedCode>(pExecutableCode)() == true);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);
	}

	TEST_CASE("SecurePage executes encrypted code") {
		constexpr unsigned char kCode[] = { 0xB0, 0x01, 0xC3 };
		Detours::Memory::SecurePage SecurePage;
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		volatile unsigned char* const pCode =
			static_cast<volatile unsigned char*>(SecurePage.Alloc(sizeof(kCode)));
		REQUIRE(const_cast<unsigned char*>(pCode) != nullptr);

		for (std::size_t unIndex = 0; unIndex < sizeof(kCode); ++unIndex) {
			pCode[unIndex] = kCode[unIndex];
		}

		unsigned char* const pExecutableCode = const_cast<unsigned char*>(pCode);
#if defined(_WIN32)
		REQUIRE(FlushInstructionCache(GetCurrentProcess(), pExecutableCode, sizeof(kCode)) != FALSE);
		using fnSecureCode = bool(__cdecl*)();
#elif defined(__linux__)
		__builtin___clear_cache(
			reinterpret_cast<char*>(pExecutableCode),
			reinterpret_cast<char*>(pExecutableCode + sizeof(kCode)));
		using fnSecureCode = bool (*)();
#endif

		REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadExecuteTestProtection);
		CHECK(reinterpret_cast<fnSecureCode>(pExecutableCode)() == true);
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);
	}



#if defined(__linux__)
	TEST_CASE("SecurePage execution leaves the cleanup worker suspendable") {
		constexpr unsigned char kCode[] = { 0xB0, 0x01, 0xC3 };
		{
			Detours::Memory::SecurePage SecurePage;
			REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
			unsigned char* const pCode = static_cast<unsigned char*>(SecurePage.Alloc(sizeof(kCode)));
			REQUIRE(pCode != nullptr);

			for (std::size_t unIndex = 0; unIndex < sizeof(kCode); ++unIndex) {
				pCode[unIndex] = kCode[unIndex];
			}

			__builtin___clear_cache(
				reinterpret_cast<char*>(pCode),
				reinterpret_cast<char*>(pCode + sizeof(kCode)));
			REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
			using fnSecureCode = bool (*)();
			REQUIRE(reinterpret_cast<fnSecureCode>(pCode)() == true);
			REQUIRE(SecurePage.Release() == true);
		}

		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});

		Detours::Hook::InlineHook InlineHook(Fixture.m_pTarget);
		REQUIRE(InlineHook.Hook(Fixture.m_pRedirect, false) == true);
		CHECK(InlineHook.UnHook() == true);
		CHECK(InlineHook.Release() == true);
	}
#endif
} // TEST_SUITE("Detours::Memory")

TEST_SUITE("Detours::Hook") {
	TEST_CASE("VTableFunctionHook splices a newer non-LIFO hook") {
		void* pFunction = reinterpret_cast<void*>(ParallelSuccessCallBack);
		void* const pOriginal = pFunction;
		void* const pFirstHook = reinterpret_cast<void*>(ParallelThrowingCallBack);
		void* const pSecondHook = reinterpret_cast<void*>(ThreadSelfActionCallBack);

		{
			Detours::Hook::VTableFunctionHook FirstHook(&pFunction, 0);
			Detours::Hook::VTableFunctionHook SecondHook(&pFunction, 0);
			REQUIRE(FirstHook.Hook(pFirstHook) == true);
			REQUIRE(SecondHook.Hook(pSecondHook) == true);
			CHECK(pFunction == pSecondHook);

			REQUIRE(FirstHook.UnHook() == true);
			CHECK(FirstHook.IsHooked() == false);
			CHECK(pFunction == pSecondHook);

			REQUIRE(SecondHook.UnHook() == true);
			CHECK(pFunction == pOriginal);
			CHECK(SecondHook.Release() == true);
			CHECK(FirstHook.Release() == true);
		}

		{
			std::unique_ptr<Detours::Hook::VTableFunctionHook> pFirstHookOwner(
				new Detours::Hook::VTableFunctionHook(&pFunction, 0));
			REQUIRE(pFirstHookOwner != nullptr);
			Detours::Hook::VTableFunctionHook SecondHook(&pFunction, 0);
			REQUIRE(pFirstHookOwner->Hook(pFirstHook) == true);
			REQUIRE(SecondHook.Hook(pSecondHook) == true);

			pFirstHookOwner = nullptr;
			CHECK(pFunction == pSecondHook);
			REQUIRE(SecondHook.UnHook() == true);
			CHECK(pFunction == pOriginal);
			CHECK(SecondHook.Release() == true);
		}
	}




	TEST_CASE("InlineHook preserves a newer overlapping hook") {
		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		REQUIRE(Fixture.m_pTarget != nullptr);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});
		std::array<unsigned char, kInlineHookTargetSnapshotSize> arrOriginalBytes {};
		std::memcpy(arrOriginalBytes.data(), Fixture.m_pTarget, arrOriginalBytes.size());
		void* const pSecondHookAddress =
			static_cast<unsigned char*>(Fixture.m_pRedirect) + 16;

		Detours::Hook::InlineHook FirstHook(Fixture.m_pTarget);
		Detours::Hook::InlineHook SecondHook(Fixture.m_pTarget);
		auto HookCleanup = MakeScopeExit([&FirstHook, &SecondHook]() {
			SecondHook.UnHook();
			SecondHook.Release();
			FirstHook.UnHook();
			FirstHook.Release();
		});
		REQUIRE(FirstHook.Hook(Fixture.m_pRedirect, false) == true);
		void* const pFirstTrampoline = FirstHook.GetTrampoline();
		REQUIRE(pFirstTrampoline != nullptr);
		REQUIRE(SecondHook.Hook(pSecondHookAddress, false) == true);
		void* const pSecondTrampoline = SecondHook.GetTrampoline();
		REQUIRE(pSecondTrampoline != nullptr);

		CHECK(FirstHook.UnHook(false) == false);
		CHECK(FirstHook.GetTrampoline() == pFirstTrampoline);
		CHECK(SecondHook.GetTrampoline() == pSecondTrampoline);
		REQUIRE(SecondHook.UnHook() == true);
		REQUIRE(FirstHook.UnHook() == true);
		CHECK(std::memcmp(Fixture.m_pTarget, arrOriginalBytes.data(), arrOriginalBytes.size()) == 0);
		REQUIRE(SecondHook.Release() == true);
		REQUIRE(FirstHook.Release() == true);
		HookCleanup.Release();
	}


	TEST_CASE("InlineWrapperHook preserves a newer overlapping hook") {
		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		REQUIRE(Fixture.m_pTarget != nullptr);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});
		std::array<unsigned char, kInlineHookTargetSnapshotSize> arrOriginalBytes {};
		std::memcpy(arrOriginalBytes.data(), Fixture.m_pTarget, arrOriginalBytes.size());
		void* const pSecondHookAddress =
			static_cast<unsigned char*>(Fixture.m_pRedirect) + 16;

		Detours::Hook::InlineWrapperHook FirstHook(Fixture.m_pTarget);
		Detours::Hook::InlineWrapperHook SecondHook(Fixture.m_pTarget);
		auto HookCleanup = MakeScopeExit([&FirstHook, &SecondHook]() {
			SecondHook.UnHook();
			SecondHook.Release();
			FirstHook.UnHook();
			FirstHook.Release();
		});
		REQUIRE(FirstHook.Hook(Fixture.m_pRedirect, false) == true);
		void* const pFirstTrampoline = FirstHook.GetTrampoline();
		REQUIRE(pFirstTrampoline != nullptr);
		REQUIRE(SecondHook.Hook(pSecondHookAddress, false) == true);
		void* const pSecondTrampoline = SecondHook.GetTrampoline();
		REQUIRE(pSecondTrampoline != nullptr);

		CHECK(FirstHook.UnHook(false) == false);
		CHECK(FirstHook.GetTrampoline() == pFirstTrampoline);
		CHECK(SecondHook.GetTrampoline() == pSecondTrampoline);
		REQUIRE(SecondHook.UnHook() == true);
		REQUIRE(FirstHook.UnHook() == true);
		CHECK(std::memcmp(Fixture.m_pTarget, arrOriginalBytes.data(), arrOriginalBytes.size()) == 0);
		REQUIRE(SecondHook.Release() == true);
		REQUIRE(FirstHook.Release() == true);
		HookCleanup.Release();
	}


	TEST_CASE("RawHook preserves a newer overlapping hook") {
		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		REQUIRE(Fixture.m_pTarget != nullptr);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});
		std::array<unsigned char, kInlineHookTargetSnapshotSize> arrOriginalBytes {};
		std::memcpy(arrOriginalBytes.data(), Fixture.m_pTarget, arrOriginalBytes.size());

		Detours::Hook::RawHook FirstHook(Fixture.m_pTarget);
		Detours::Hook::RawHook SecondHook(Fixture.m_pTarget);
		auto HookCleanup = MakeScopeExit([&FirstHook, &SecondHook]() {
			SecondHook.UnHook();
			SecondHook.Release();
			FirstHook.UnHook();
			FirstHook.Release();
		});
		REQUIRE(FirstHook.Hook(BlockingCallRawHook, false, 0, false) == true);
		void* const pFirstTrampoline = FirstHook.GetTrampoline();
		REQUIRE(pFirstTrampoline != nullptr);
		REQUIRE(SecondHook.Hook(BlockingCallRawHook, false, 0, false) == true);
		void* const pSecondTrampoline = SecondHook.GetTrampoline();
		REQUIRE(pSecondTrampoline != nullptr);

		CHECK(FirstHook.UnHook(false) == false);
		CHECK(FirstHook.GetTrampoline() == pFirstTrampoline);
		CHECK(SecondHook.GetTrampoline() == pSecondTrampoline);
		REQUIRE(SecondHook.UnHook() == true);
		REQUIRE(FirstHook.UnHook() == true);
		CHECK(std::memcmp(Fixture.m_pTarget, arrOriginalBytes.data(), arrOriginalBytes.size()) == 0);
		REQUIRE(SecondHook.Release() == true);
		REQUIRE(FirstHook.Release() == true);
		HookCleanup.Release();
	}

	TEST_CASE("InlineHook non-wait unhook preserves an active trampoline return") {
		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});

		g_bInlineUnHookBlockerEntered.store(false, std::memory_order_relaxed);
		g_bInlineUnHookBlockerRelease.store(false, std::memory_order_relaxed);
		Detours::Hook::InlineHook InlineHook(Fixture.m_pTarget);
		g_pInlineUnHook = &InlineHook;
		auto GlobalCleanup = MakeScopeExit([]() {
			g_bInlineUnHookBlockerRelease.store(true, std::memory_order_release);
			g_pInlineUnHook = nullptr;
		});
		auto HookCleanup = MakeScopeExit([&InlineHook]() {
			InlineHook.UnHook();
			InlineHook.Release();
		});
		REQUIRE(InlineHook.Hook(Fixture.m_pRedirect, false) == true);

		using fnInlineUnHookTarget = int (*)();
		std::atomic<int> nResult = 0;
		std::thread TargetThread([&Fixture, &nResult]() {
			nResult.store(reinterpret_cast<fnInlineUnHookTarget>(Fixture.m_pTarget)(), std::memory_order_release);
		});
		auto ThreadCleanup = MakeScopeExit([&TargetThread]() {
			g_bInlineUnHookBlockerRelease.store(true, std::memory_order_release);
			if (TargetThread.joinable()) {
				TargetThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([]() {
			return g_bInlineUnHookBlockerEntered.load(std::memory_order_acquire);
		},
									 kParallelThreadWaitMilliseconds));
		CHECK(InlineHook.UnHook(false) == false);

		g_bInlineUnHookBlockerRelease.store(true, std::memory_order_release);
		TargetThread.join();
		ThreadCleanup.Release();
		CHECK(nResult.load(std::memory_order_acquire) == kInlineUnHookOriginalValue);
		CHECK(InlineHook.UnHook() == true);
		bool const bReleased = InlineHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("InlineWrapperHook rejects unhook while its callback has not entered the trampoline") {
		g_bInlineWrapperCallbackEntered.store(false, std::memory_order_relaxed);
		g_bInlineWrapperCallbackRelease.store(false, std::memory_order_relaxed);

		using fnInlineWrapperTarget = int (*)();
		fnInlineWrapperTarget const pTarget = InlineWrapperCallbackTarget;
		Detours::Hook::InlineWrapperHook Hook(reinterpret_cast<void*>(pTarget));
		g_pInlineWrapperCallbackHook = &Hook;
		auto GlobalCleanup = MakeScopeExit([]() {
			g_bInlineWrapperCallbackRelease.store(true, std::memory_order_release);
			g_pInlineWrapperCallbackHook = nullptr;
		});
		auto HookCleanup = MakeScopeExit([&Hook]() {
			Hook.UnHook();
			Hook.Release();
		});
		REQUIRE(Hook.Hook(reinterpret_cast<void*>(InlineWrapperBlockingCallback), false) == true);

		std::atomic<int> nResult = 0;
		std::thread TargetThread([pTarget, &nResult]() {
			nResult.store(pTarget(), std::memory_order_release);
		});
		auto ThreadCleanup = MakeScopeExit([&TargetThread]() {
			g_bInlineWrapperCallbackRelease.store(true, std::memory_order_release);
			if (TargetThread.joinable()) {
				TargetThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([]() {
			return g_bInlineWrapperCallbackEntered.load(std::memory_order_acquire);
		},
			kParallelThreadWaitMilliseconds));
		CHECK(Hook.UnHook(false) == false);

		g_bInlineWrapperCallbackRelease.store(true, std::memory_order_release);
		TargetThread.join();
		ThreadCleanup.Release();
		CHECK(nResult.load(std::memory_order_acquire) == kInlineUnHookOriginalValue);
		REQUIRE(Hook.UnHook() == true);
		REQUIRE(Hook.Release() == true);
		HookCleanup.Release();
		g_pInlineWrapperCallbackHook = nullptr;
		GlobalCleanup.Release();
	}

	TEST_CASE("InlineWrapperHook non-wait unhook preserves an active wrapper") {
		InlineUnHookCodeFixture Fixture {};
		REQUIRE(CreateInlineUnHookCodeFixture(&Fixture) == true);
		auto MappingCleanup = MakeScopeExit([&Fixture]() {
			DestroyInlineUnHookCodeFixture(&Fixture);
		});

		Detours::Hook::InlineWrapperHook InlineHook(Fixture.m_pTarget);
		auto HookCleanup = MakeScopeExit([&InlineHook]() {
			InlineHook.UnHook();
			InlineHook.Release();
		});
		REQUIRE(InlineHook.Hook(Fixture.m_pRedirect, false) == true);
		void* const pWrapper = GetInlineWrapperAddress(Fixture.m_pTarget);
		REQUIRE(pWrapper != nullptr);

		InlineWrapperLoopState LoopState {};
		REQUIRE(InstallInlineWrapperLoop(pWrapper, &LoopState) == true);
		using fnInlineUnHookTarget = int (*)();
		std::thread TargetThread([&Fixture]() {
			reinterpret_cast<fnInlineUnHookTarget>(Fixture.m_pTarget)();
		});
		auto ThreadCleanup = MakeScopeExit([&TargetThread, &LoopState]() {
			LoopState.m_unRelease.store(1, std::memory_order_release);
			if (TargetThread.joinable()) {
				TargetThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&LoopState]() {
			return LoopState.m_unEntered.load(std::memory_order_acquire) != 0;
		},
									 kParallelThreadWaitMilliseconds));
		CHECK(InlineHook.UnHook(false) == false);

		LoopState.m_unRelease.store(1, std::memory_order_release);
		TargetThread.join();
		ThreadCleanup.Release();
		CHECK(InlineHook.UnHook() == true);
		bool const bReleased = InlineHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("InlineHook installation waits for an active target call return") {
		VerifyBlockingCallHookInstallation<Detours::Hook::InlineHook>(
			[](Detours::Hook::InlineHook& Hook, InlineUnHookCodeFixture const& Fixture) {
				return Hook.Hook(Fixture.m_pRedirect, false, true);
			});
	}

	TEST_CASE("InlineWrapperHook installation waits for an active target call return") {
		VerifyBlockingCallHookInstallation<Detours::Hook::InlineWrapperHook>(
			[](Detours::Hook::InlineWrapperHook& Hook, InlineUnHookCodeFixture const& Fixture) {
				return Hook.Hook(Fixture.m_pRedirect, false, true);
			});
	}

	TEST_CASE("RawHook installation waits for an active target call return") {
		VerifyBlockingCallHookInstallation<Detours::Hook::RawHook>(
			[](Detours::Hook::RawHook& Hook, InlineUnHookCodeFixture const&) {
				return Hook.Hook(BlockingCallRawHook, false, 0, false, true);
			});
	}
} // TEST_SUITE("Detours::Hook")

#if defined(_WIN32)

// ================================================================
// Windows tests
// ================================================================

constexpr std::size_t kCPUIDRegisterCount = 4;
constexpr int kCPUIDBasicFeaturesLeaf = 1;
constexpr int kCPUIDExtendedFeaturesLeaf = 7;
constexpr int kCPUIDSSE2Mask = 1 << 26;
constexpr int kCPUIDXSAVEMask = 1 << 26;
constexpr int kCPUIDOSXSAVEMask = 1 << 27;
constexpr int kCPUIDAVXMask = 1 << 28;
constexpr int kCPUIDAVX2Mask = 1 << 5;
constexpr int kCPUIDAVX512FMask = 1 << 16;
constexpr int kCPUIDAVX512BWMask = 1 << 30;
constexpr unsigned __int64 kXCR0AVXStateMask = 0x6;
constexpr unsigned __int64 kXCR0AVX512StateMask = 0xE6;
constexpr DWORD kThreadSynchronizationWaitMilliseconds = 2000;
constexpr DWORD kThreadSuspendObservationMilliseconds = 50;
constexpr DWORD kWindowsTestChildWaitMilliseconds = 30'000;
constexpr DWORD kControlFlowGuardViolationExitCode = 0xC0000409;
constexpr unsigned int kThreadSuspendCleanupLimit = 4;
constexpr std::size_t kWindowsTestExecutablePathCapacity = 32'768;
constexpr std::size_t kControlFlowGuardInvalidTargetOffset = 16;
constexpr std::array<unsigned char, 32> kScanOutsideTextPattern = {
	0xD7, 0x19, 0xA4, 0x6E, 0x83, 0x2B, 0xF5, 0x40,
	0x9C, 0x61, 0x0D, 0xB8, 0x37, 0xEA, 0x52, 0x14,
	0xC6, 0x7F, 0x25, 0x93, 0x48, 0xBD, 0x01, 0xFE,
	0x6A, 0xD2, 0x8C, 0x35, 0xE9, 0x70, 0x1B, 0xA6
};

struct CPUFeatures {
	bool m_bHaveSSE2;
	bool m_bHaveAVX2;
	bool m_bHaveAVX512;
};

typedef struct _WINDOWS_THREAD_SUSPEND_TEST_DATA {
	std::atomic<DWORD> m_unThreadID;
	std::atomic<unsigned int> m_unIterations;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bStop;
} WINDOWS_THREAD_SUSPEND_TEST_DATA, *PWINDOWS_THREAD_SUSPEND_TEST_DATA;

class ScopedThread {
public:
	explicit ScopedThread(HANDLE hThread) noexcept;

	~ScopedThread() noexcept {
		Clear();
	}

	ScopedThread(ScopedThread const&) = delete;
	ScopedThread& operator=(ScopedThread const&) = delete;

	bool IsValid() const noexcept {
		return m_hThread && (m_hThread != INVALID_HANDLE_VALUE);
	}

	bool Resume() noexcept {
		if (!IsValid()) {
			return false;
		}

		if (ResumeThread(m_hThread) == static_cast<DWORD>(-1)) {
			return false;
		}

		m_bResumed = true;
		return true;
	}

	bool Wait(DWORD const unMilliseconds = kWindowsTestChildWaitMilliseconds) const noexcept {
		return IsValid() && m_bResumed &&
			(WaitForSingleObject(m_hThread, unMilliseconds) == WAIT_OBJECT_0);
	}

	bool Close() noexcept {
		if (!IsValid()) {
			m_hThread = nullptr;
			return true;
		}

		HANDLE const hThread = m_hThread;
		m_hThread = nullptr;
		return CloseHandle(hThread) != FALSE;
	}

private:
	void Clear() noexcept {
		if (!IsValid()) {
			m_hThread = nullptr;
			return;
		}

		if ((!m_bResumed && !Resume()) ||
			(WaitForSingleObject(m_hThread, kWindowsTestChildWaitMilliseconds) != WAIT_OBJECT_0)) {
			std::abort();
		}

		if (!Close()) {
			std::abort();
		}
	}

private:
	HANDLE m_hThread;
	bool m_bResumed;
};

ScopedThread::ScopedThread(HANDLE hThread) noexcept :
	m_hThread(hThread),
	m_bResumed(false)
{
}

// interrupts32.asm/interrupts64.asm
#if defined(_M_X64)
extern "C" unsigned long long __cdecl CallInterrupt(unsigned long long unRAX, unsigned long long unRCX, unsigned long long unRDX, unsigned long long unRBX, unsigned long long unRBP, unsigned long long unRSI, unsigned long long unRDI, unsigned long long unR8, unsigned long long unR9, unsigned long long unR10, unsigned long long unR11, unsigned long long unR12, unsigned long long unR13, unsigned long long unR14, unsigned long long unR15);
#elif defined(_M_IX86)
extern "C" unsigned int __cdecl CallInterrupt(unsigned int unEAX, unsigned int unECX, unsigned int unEDX, unsigned int unEBX, unsigned int unEBP, unsigned int unESI, unsigned int unEDI);
#endif

extern "C" unsigned char __cdecl TryRead(void* pData);

class BaseMessage {
public:
	virtual ~BaseMessage() = default;

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
	virtual bool Foo() {
		return false;
	}

	virtual bool Boo() {
		return true;
	}
};

class TestingRTTI : public BaseTestingRTTI {
public:
	TestingRTTI() noexcept;

	bool Foo() override {
		return m_bFoo;
	}

	bool Boo() override {
		return m_bBoo;
	}

private:
	bool m_bFoo;
	bool m_bBoo;
};

class ScopedTestingRTTIObjects {
public:
	ScopedTestingRTTIObjects(BaseTestingRTTI*& pBaseObject, TestingRTTI*& pObject) noexcept;

	~ScopedTestingRTTIObjects() noexcept {
		m_pObject = nullptr;
		m_pBaseObject = nullptr;
	}

	ScopedTestingRTTIObjects(ScopedTestingRTTIObjects const&) = delete;
	ScopedTestingRTTIObjects& operator=(ScopedTestingRTTIObjects const&) = delete;

private:
	BaseTestingRTTI*& m_pBaseObject;
	TestingRTTI*& m_pObject;
	BaseTestingRTTI m_BaseObject;
	TestingRTTI m_Object;
};

TestingRTTI::TestingRTTI() noexcept {
	m_bFoo = true;
	m_bBoo = false;
}

ScopedTestingRTTIObjects::ScopedTestingRTTIObjects(BaseTestingRTTI*& pBaseObject, TestingRTTI*& pObject) noexcept :
	m_pBaseObject(pBaseObject),
	m_pObject(pObject),
	m_BaseObject(),
	m_Object()
{
	m_pBaseObject = &m_BaseObject;
	m_pObject = &m_Object;
}

struct SI_Base {
	virtual ~SI_Base() = default;

	virtual int GetID() {
		return 1;
	}

	virtual bool IsBaseOnly() {
		return true;
	}
};

struct SI_Derived : SI_Base {
	~SI_Derived() override = default;

	int GetID() override {
		return 2;
	}

	bool IsBaseOnly() override {
		return false;
	}
};

struct MI_A {
	virtual ~MI_A() = default;

	virtual int GetA() {
		return 10;
	}
};

struct MI_B {
	virtual ~MI_B() = default;

	virtual int GetB() {
		return 20;
	}
};

struct MI_D : MI_A, MI_B {
	~MI_D() override = default;

	int GetA() override {
		return 11;
	}

	int GetB() override {
		return 21;
	}
};

struct VI_V {
	virtual ~VI_V() = default;

	virtual char const* GetValue() {
		return "V";
	}
};

struct VI_A : virtual VI_V {
	~VI_A() override = default;

	char const* GetValue() override {
		return "A";
	}
};

struct VI_B : virtual VI_V {
	~VI_B() override = default;

	char const* GetValue() override {
		return "B";
	}
};

struct VI_D : VI_A, VI_B {
	~VI_D() override = default;

	char const* GetValue() override {
		return "D";
	}
};

struct PrivBase {
	virtual ~PrivBase() = default;

	virtual int GetTag() {
		return 777;
	}
};

struct PrivDerived : private PrivBase {
public:
	~PrivDerived() override = default;

	PrivBase* AsBase() {
		return static_cast<PrivBase*>(this);
	}

	int GetTag() override {
		return 888;
	}
};

DEFINE_SECTION(".cdata", SECTION_READWRITE)
DEFINE_SECTION(".ctext", SECTION_EXECUTE_READ)

DEFINE_DATA_IN_SECTION(".cdata") __declspec(dllexport) BaseTestingRTTI* g_pBaseTestingRTTI = nullptr;
DEFINE_DATA_IN_SECTION(".cdata") __declspec(dllexport) TestingRTTI* g_pTestingRTTI = nullptr;

static bool RunWindowsTestChild(TCHAR const* const szTestCase, DWORD* const pExitCode) {
	if (!szTestCase || !pExitCode) {
		return false;
	}

	*pExitCode = 0;
	std::vector<TCHAR> vecExecutablePath(kWindowsTestExecutablePathCapacity);
	DWORD const unExecutablePathLength = GetModuleFileName(nullptr, vecExecutablePath.data(), static_cast<DWORD>(vecExecutablePath.size()));
	if (!unExecutablePathLength || (unExecutablePathLength >= vecExecutablePath.size())) {
		return false;
	}

	std::basic_string<TCHAR> strCommandLine = _T("\"");
	strCommandLine += vecExecutablePath.data();
	strCommandLine += _T("\" --test-case=\"");
	strCommandLine += szTestCase;
	strCommandLine += _T("\" --no-skip=true");
	std::vector<TCHAR> vecCommandLine(strCommandLine.cbegin(), strCommandLine.cend());
	vecCommandLine.push_back(_T('\0'));

	STARTUPINFO StartupInfo {};
	StartupInfo.cb = sizeof(StartupInfo);
	PROCESS_INFORMATION ProcessInformation {};
	if (!CreateProcess(
			vecExecutablePath.data(),
			vecCommandLine.data(),
			nullptr,
			nullptr,
			FALSE,
			CREATE_NO_WINDOW,
			nullptr,
			nullptr,
			&StartupInfo,
			&ProcessInformation)) {
		return false;
	}

	CloseHandle(ProcessInformation.hThread);
	ProcessInformation.hThread = nullptr;

	bool bChildRunning = true;
	auto ProcessCleanup = MakeScopeExit([&ProcessInformation, &bChildRunning]() {
		if (bChildRunning) {
			TerminateProcess(ProcessInformation.hProcess, 1);
			WaitForSingleObject(ProcessInformation.hProcess, kWindowsTestChildWaitMilliseconds);
		}

		CloseHandle(ProcessInformation.hProcess);
	});

	if (WaitForSingleObject(ProcessInformation.hProcess, kWindowsTestChildWaitMilliseconds) != WAIT_OBJECT_0) {
		return false;
	}

	bChildRunning = false;
	return GetExitCodeProcess(ProcessInformation.hProcess, pExitCode) != FALSE;
}

static CPUFeatures GetCPUFeatures() noexcept {
	CPUFeatures Features {};
	int nCPUIDRegisters[kCPUIDRegisterCount] {};
	__cpuidex(nCPUIDRegisters, 0, 0);
	int const nMaximumBasicLeaf = nCPUIDRegisters[0];
	if (nMaximumBasicLeaf < kCPUIDBasicFeaturesLeaf) {
		return Features;
	}

	__cpuidex(nCPUIDRegisters, kCPUIDBasicFeaturesLeaf, 0);
	Features.m_bHaveSSE2 = (nCPUIDRegisters[3] & kCPUIDSSE2Mask) != 0;

	int const nRequiredAVXFeatures = kCPUIDXSAVEMask | kCPUIDOSXSAVEMask | kCPUIDAVXMask;
	if ((nCPUIDRegisters[2] & nRequiredAVXFeatures) != nRequiredAVXFeatures) {
		return Features;
	}

	unsigned const __int64 unEnabledExtendedStates = _xgetbv(0);
	if ((unEnabledExtendedStates & kXCR0AVXStateMask) != kXCR0AVXStateMask) {
		return Features;
	}

	if (nMaximumBasicLeaf < kCPUIDExtendedFeaturesLeaf) {
		return Features;
	}

	__cpuidex(nCPUIDRegisters, kCPUIDExtendedFeaturesLeaf, 0);
	Features.m_bHaveAVX2 = (nCPUIDRegisters[1] & kCPUIDAVX2Mask) != 0;

	int const nRequiredAVX512Features = kCPUIDAVX512FMask | kCPUIDAVX512BWMask;
	Features.m_bHaveAVX512 =
		((unEnabledExtendedStates & kXCR0AVX512StateMask) == kXCR0AVX512StateMask) &&
		((nCPUIDRegisters[1] & nRequiredAVX512Features) == nRequiredAVX512Features);
	return Features;
}

template <typename T>
static char const* GetTypeName() noexcept {
	return typeid(T).raw_name();
}

DEFINE_CODE_IN_SECTION(".ctext") __declspec(dllexport) int DemoSum(int nFirstOperand, int nSecondOperand) {
	return nFirstOperand + nSecondOperand / nFirstOperand;
}

DWORD GetUBR() {
	static DWORD s_unKnownUBR = 0;
	if (s_unKnownUBR) {
		return s_unKnownUBR;
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
	s_unKnownUBR = unUBR;
	return unUBR;
}

TEST_SUITE("Detours::g_KUserSharedData") {
	TEST_CASE("Legacy alias") {
		bool const bSameAddress = &Detours::KUserSharedData == &Detours::g_KUserSharedData;
		CHECK(bSameAddress == true);
	}

	TEST_CASE("SystemTime") {
		ULONG const unLowPartTime = Detours::g_KUserSharedData.SystemTime.LowPart;
		Sleep(5250);
		ULONG const unElapsedTime = (Detours::g_KUserSharedData.SystemTime.LowPart - unLowPartTime) / 10000000;
		CHECK(unElapsedTime >= 5);
	}

	TEST_CASE("Cookie") {
		CHECK(Detours::g_KUserSharedData.Cookie != 0);
	}

	TEST_CASE("ActiveProcessorCount") {
		CHECK(Detours::g_KUserSharedData.ActiveProcessorCount != 0);
	}
} // TEST_SUITE("Detours::g_KUserSharedData")

TEST_SUITE("Detours::GetPEB") {
	TEST_CASE("Windows Version") {
		Detours::PPEB const pPEB = Detours::GetPEB();
		REQUIRE(pPEB != nullptr);
		constexpr std::size_t kBufferSize = 128;
		char szBuffer[kBufferSize] {};
		CHECK(sprintf_s(szBuffer, sizeof(szBuffer), "Microsoft Windows [Version %lu.%lu.%05lu.%lu]\n", pPEB->OSMajorVersion, pPEB->OSMinorVersion, pPEB->OSBuildNumber, GetUBR()) > 0);
		MESSAGE(szBuffer);
	}

	TEST_CASE("ProcessParameters") {
		Detours::PPEB const pPEB = Detours::GetPEB();
		REQUIRE(pPEB != nullptr);
		REQUIRE(pPEB->ProcessParameters != nullptr);
		CHECK(pPEB->ProcessParameters->CommandLine.Length > 0);
		REQUIRE(pPEB->ProcessParameters->CommandLine.Buffer != nullptr);
		constexpr std::size_t kBufferSize = 256;
		char szBuffer[kBufferSize] {};
		CHECK(sprintf_s(szBuffer, sizeof(szBuffer), "CommandLine = `%ws`\n", pPEB->ProcessParameters->CommandLine.Buffer) > 0);
		MESSAGE(szBuffer);
	}
} // TEST_SUITE("Detours::GetPEB")

TEST_SUITE("Detours::GetTEB") {
	TEST_CASE("Process ID and Thread ID") {
		Detours::PTEB const pTEB = Detours::GetTEB();
		REQUIRE(pTEB != nullptr);
		CHECK(pTEB->ClientId.UniqueProcess != 0);
		CHECK(pTEB->ClientId.UniqueThread != 0);
		CHECK(pTEB->RealClientId.UniqueProcess == pTEB->ClientId.UniqueProcess);
		CHECK(pTEB->RealClientId.UniqueThread == pTEB->ClientId.UniqueThread);
	}

	TEST_CASE("LastError") {
		Detours::PTEB const pTEB = Detours::GetTEB();
		REQUIRE(pTEB != nullptr);
		SetLastError(0x11223344);
		CHECK(pTEB->LastErrorValue == 0x11223344);
	}
} // TEST_SUITE("Detours::GetTEB")

TEST_SUITE("Detours::CallStack") {
	TEST_CASE("GetCallStack captures current and running worker threads") {
		std::vector<void*> const vecCurrentCallStack = Detours::CallStack::GetCallStack(GetCurrentThread(), 16);
		CHECK(vecCurrentCallStack.empty() == false);

		std::atomic<bool> bReady = false;
		std::atomic<bool> bRelease = false;
		std::thread Worker([&bReady, &bRelease]() {
			bReady.store(true, std::memory_order_release);
			while (!bRelease.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
		});
		auto WorkerCleanup = MakeScopeExit([&Worker, &bRelease]() {
			bRelease.store(true, std::memory_order_release);
			if (Worker.joinable()) {
				Worker.join();
			}
		});
		REQUIRE(WaitForTestCondition([&bReady]() {
			return bReady.load(std::memory_order_acquire);
		},
									 kParallelThreadWaitMilliseconds));

		std::vector<void*> const vecWorkerCallStack = Detours::CallStack::GetCallStack(Worker.native_handle(), 16);
		CHECK(vecWorkerCallStack.empty() == false);
		bRelease.store(true, std::memory_order_release);
		Worker.join();
		WorkerCleanup.Release();
	}

	TEST_CASE("GetShadowStack rejects the current running thread") {
		void** pShadowStack = reinterpret_cast<void**>(static_cast<std::uintptr_t>(1));
		std::size_t unSize = 1;
		CHECK(Detours::CallStack::GetShadowStack(GetCurrentThread(), &pShadowStack, &unSize) == false);
		CHECK(pShadowStack == reinterpret_cast<void**>(static_cast<std::uintptr_t>(1)));
		CHECK(unSize == 1);
	}

	TEST_CASE("CallStack rejects thread handles from another process") {
		std::vector<TCHAR> vecExecutablePath(kWindowsTestExecutablePathCapacity);
		DWORD const unExecutablePathLength = GetModuleFileName(nullptr, vecExecutablePath.data(), static_cast<DWORD>(vecExecutablePath.size()));
		REQUIRE(unExecutablePathLength != 0);
		REQUIRE(unExecutablePathLength < vecExecutablePath.size());

		STARTUPINFO StartupInfo {};
		StartupInfo.cb = sizeof(StartupInfo);
		PROCESS_INFORMATION ProcessInformation {};
		// The immediately following scope guard owns both returned handles.
#pragma warning(suppress: 6335)
		BOOL const bProcessCreated = CreateProcess(
			vecExecutablePath.data(),
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			CREATE_NO_WINDOW | CREATE_SUSPENDED,
			nullptr,
			nullptr,
			&StartupInfo,
			&ProcessInformation);
		auto ProcessCleanup = MakeScopeExit([&ProcessInformation]() {
			if (ProcessInformation.hThread) {
				CloseHandle(ProcessInformation.hThread);
			}

			if (ProcessInformation.hProcess) {
				TerminateProcess(ProcessInformation.hProcess, EXIT_FAILURE);
				WaitForSingleObject(ProcessInformation.hProcess, kWindowsTestChildWaitMilliseconds);
				CloseHandle(ProcessInformation.hProcess);
			}
		});
		REQUIRE(bProcessCreated == TRUE);

		CHECK(Detours::CallStack::GetCallStack(ProcessInformation.hThread, 16).empty() == true);
		void** pShadowStack = reinterpret_cast<void**>(static_cast<std::uintptr_t>(1));
		std::size_t unSize = 1;
		CHECK(Detours::CallStack::GetShadowStack(ProcessInformation.hThread, &pShadowStack, &unSize) == false);
		CHECK(pShadowStack == reinterpret_cast<void**>(static_cast<std::uintptr_t>(1)));
		CHECK(unSize == 1);
		CHECK(Detours::CallStack::GetShadowCallStack(ProcessInformation.hThread, 16).empty() == true);
	}
} // TEST_SUITE("Detours::CallStack")

TEST_SUITE("Detours::LDR") {
	TEST_CASE("ReLink survives loader topology churn and stale copies in child" * doctest::skip()) {
		WindowsTemporaryModule TargetModule;
		WindowsTemporaryModule LaterModule;
		REQUIRE(TargetModule.Create() == true);
		HMODULE const hTargetModule = TargetModule.GetModule();
		REQUIRE(hTargetModule != nullptr);
		Detours::PLDR_DATA_TABLE_ENTRY const pDTE = Detours::LDR::FindModuleDataTableEntry(hTargetModule);
		REQUIRE(pDTE != nullptr);
		auto IsSelfLinked = [](LIST_ENTRY const& Entry) noexcept {
			return (Entry.Flink == &Entry) && (Entry.Blink == &Entry);
		};

		Detours::LDR::LINK_DATA LinkData {};
		REQUIRE(Detours::LDR::UnLinkModule(hTargetModule, &LinkData) == true);
		Detours::LDR::LINK_DATA const StaleLinkData = LinkData;
		CHECK(IsSelfLinked(pDTE->InLoadOrderLinks));
		CHECK(IsSelfLinked(pDTE->InMemoryOrderLinks));
		CHECK(IsSelfLinked(pDTE->InInitializationOrderLinks));
		CHECK(IsSelfLinked(pDTE->HashLinks));
		CHECK(IsSelfLinked(pDTE->NodeModuleLink));
		REQUIRE(LaterModule.Create() == true);
		Detours::PLDR_DATA_TABLE_ENTRY const pLaterDTE = Detours::LDR::FindModuleDataTableEntry(LaterModule.GetModule());
		REQUIRE(pLaterDTE != nullptr);

		REQUIRE(Detours::LDR::TryReLinkModule(LinkData) == true);
		CHECK(GetModuleHandleW(TargetModule.GetPath()) == hTargetModule);
		CHECK(pDTE->InLoadOrderLinks.Flink ==
			&pLaterDTE->InLoadOrderLinks);
		auto IsReciprocallyLinked = [](LIST_ENTRY const& Entry) noexcept {
			return Entry.Flink && Entry.Blink &&
				(Entry.Flink->Blink == &Entry) &&
				(Entry.Blink->Flink == &Entry);
		};
		CHECK(IsReciprocallyLinked(pDTE->InLoadOrderLinks));
		CHECK(IsReciprocallyLinked(pDTE->InMemoryOrderLinks));
		CHECK(IsReciprocallyLinked(pDTE->InInitializationOrderLinks));
		CHECK(IsReciprocallyLinked(pDTE->HashLinks));
		CHECK(IsReciprocallyLinked(pDTE->NodeModuleLink));

		CHECK(Detours::LDR::TryReLinkModule(StaleLinkData) == false);
		CHECK(Detours::LDR::TryReLinkModule(StaleLinkData) == false);
		CHECK(GetModuleHandleW(TargetModule.GetPath()) == hTargetModule);
	}

	TEST_CASE("ReLink consumes copied tokens once in child" * doctest::skip()) {
		WindowsTemporaryModule TargetModule;
		REQUIRE(TargetModule.Create() == true);
		HMODULE const hTargetModule = TargetModule.GetModule();
		REQUIRE(hTargetModule != nullptr);

		Detours::LDR::LINK_DATA LinkData {};
		REQUIRE(Detours::LDR::UnLinkModule(hTargetModule, &LinkData) == true);
		Detours::LDR::LINK_DATA const FirstCopy = LinkData;
		Detours::LDR::LINK_DATA const SecondCopy = LinkData;

		std::atomic<unsigned int> unReadyCount = 0;
		std::atomic<unsigned int> unSuccessCount = 0;
		std::atomic<bool> bStart = false;
		auto ReLinkCopy = [&unReadyCount, &unSuccessCount, &bStart](
			Detours::LDR::LINK_DATA Copy) {
			unReadyCount.fetch_add(1, std::memory_order_release);
			while (!bStart.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			if (Detours::LDR::TryReLinkModule(Copy)) {
				unSuccessCount.fetch_add(1, std::memory_order_release);
			}
		};
		std::thread FirstThread(ReLinkCopy, FirstCopy);
		std::thread SecondThread(ReLinkCopy, SecondCopy);
		auto ThreadCleanup = MakeScopeExit([
			&FirstThread, &SecondThread, &bStart]() noexcept {
			bStart.store(true, std::memory_order_release);
			if (FirstThread.joinable()) {
				FirstThread.join();
			}

			if (SecondThread.joinable()) {
				SecondThread.join();
			}
		});
		REQUIRE(WaitForTestCondition([&unReadyCount]() {
			return unReadyCount.load(std::memory_order_acquire) == 2;
		},
			kParallelThreadWaitMilliseconds));
		bStart.store(true, std::memory_order_release);
		FirstThread.join();
		SecondThread.join();
		ThreadCleanup.Release();

		CHECK(unSuccessCount.load(std::memory_order_acquire) == 1);
		CHECK(GetModuleHandleW(TargetModule.GetPath()) == hTargetModule);
		CHECK(Detours::LDR::TryReLinkModule(FirstCopy) == false);
		CHECK(Detours::LDR::TryReLinkModule(SecondCopy) == false);
		REQUIRE(TargetModule.ReleaseCallerReference() == true);
		CHECK(WaitForTestCondition([&TargetModule]() {
			return GetModuleHandleW(TargetModule.GetPath()) == nullptr;
		},
			kWindowsModuleReferenceWaitMilliseconds));
	}

	TEST_CASE("Active link tokens cannot be overwritten in child" * doctest::skip()) {
		WindowsTemporaryModule FirstModule;
		WindowsTemporaryModule SecondModule;
		REQUIRE(FirstModule.Create() == true);
		REQUIRE(SecondModule.Create() == true);

		Detours::LDR::LINK_DATA LinkData {};
		REQUIRE(Detours::LDR::UnLinkModule(FirstModule.GetModule(), &LinkData) == true);
		Detours::LDR::LINK_DATA const OriginalLinkData = LinkData;
		CHECK(Detours::LDR::UnLinkModule(SecondModule.GetModule(), &LinkData) == false);
		CHECK(std::memcmp(&LinkData, &OriginalLinkData, sizeof(LinkData)) == 0);
		CHECK(GetModuleHandleW(SecondModule.GetPath()) ==
			SecondModule.GetModule());

		REQUIRE(Detours::LDR::TryReLinkModule(OriginalLinkData) == true);
		CHECK(GetModuleHandleW(FirstModule.GetPath()) ==
			FirstModule.GetModule());
	}

	TEST_CASE("LDR link tokens survive churn and concurrent stale copies") {
	constexpr TCHAR const* kChildTests[] = {
			_T("ReLink survives loader topology churn and stale copies in child"),
			_T("ReLink consumes copied tokens once in child"),
			_T("Active link tokens cannot be overwritten in child")
		};
		for (auto const szChildTest : kChildTests) {
			DWORD unExitCode = 0;
			REQUIRE(RunWindowsTestChild(szChildTest, &unExitCode) == true);
			CHECK(unExitCode == EXIT_SUCCESS);
		}
	}
} // TEST_SUITE("Detours::LDR")

TEST_SUITE("Detours::Codec") {
	TEST_CASE("UpperCase") {
		std::unique_ptr<char, decltype(&std::free)> pHelloWorld(_strdup("Hello, World!"), &std::free);
		REQUIRE(pHelloWorld != nullptr);
		std::size_t const unSize = strnlen(pHelloWorld.get(), 0x7FF);
		REQUIRE(unSize != 0x7FF);
		CHECK(Detours::Codec::UpperCase(pHelloWorld.get(), unSize) == true);
		CHECK(strcmp(pHelloWorld.get(), "HELLO, WORLD!") == 0);
	}

	TEST_CASE("LowerCase") {
		std::unique_ptr<char, decltype(&std::free)> pHelloWorld(_strdup("Hello, World!"), &std::free);
		REQUIRE(pHelloWorld != nullptr);
		std::size_t const unSize = strnlen(pHelloWorld.get(), 0x7FF);
		REQUIRE(unSize != 0x7FF);
		CHECK(Detours::Codec::LowerCase(pHelloWorld.get(), unSize) == true);
		CHECK(strcmp(pHelloWorld.get(), "hello, world!") == 0);
	}

#pragma warning(push)
#pragma warning(disable: 6001)

	TEST_CASE("Encode") {
		int nEncodeSize = Detours::Codec::Encode(CP_UTF8, "Hello, World!");
		REQUIRE(nEncodeSize > 0);
		HANDLE hHeap = GetProcessHeap();
		REQUIRE(hHeap != nullptr);
		REQUIRE(hHeap != INVALID_HANDLE_VALUE);
		wchar_t* pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<std::size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t)));
		REQUIRE(pBuffer != nullptr);
		memset(pBuffer, 0, static_cast<std::size_t>(nEncodeSize) * sizeof(wchar_t) + sizeof(wchar_t));
		CHECK(Detours::Codec::Encode(CP_UTF8, "Hello, World!", pBuffer, nEncodeSize) > 0);
		CHECK(wcscmp(pBuffer, L"Hello, World!") == 0);
		CHECK(HeapFree(hHeap, 0, pBuffer) == TRUE);
	}

	TEST_CASE("Decode") {
		int nDecodeSize = Detours::Codec::Decode(CP_UTF8, L"Hello, World!");
		REQUIRE(nDecodeSize > 0);
		HANDLE hHeap = GetProcessHeap();
		REQUIRE(hHeap != nullptr);
		REQUIRE(hHeap != INVALID_HANDLE_VALUE);
		char* pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, static_cast<std::size_t>(nDecodeSize) * sizeof(char) + sizeof(char)));
		REQUIRE(pBuffer != nullptr);
		memset(pBuffer, 0, static_cast<std::size_t>(nDecodeSize) * sizeof(char) + sizeof(char));
		CHECK(Detours::Codec::Decode(CP_UTF8, L"Hello, World!", pBuffer, nDecodeSize) > 0);
		CHECK(strcmp(pBuffer, "Hello, World!") == 0);
		CHECK(HeapFree(hHeap, 0, pBuffer) == TRUE);
	}

	TEST_CASE("Encode and Decode accept the active Windows code page") {
		constexpr char kNarrowText[] = "ASCII";
		constexpr wchar_t kWideText[] = L"ASCII";
		std::array<wchar_t, std::size(kWideText)> arrWideBuffer {};
		std::array<char, std::size(kNarrowText)> arrNarrowBuffer {};

		int const nWideSize = Detours::Codec::Encode(CP_ACP, kNarrowText);
		REQUIRE(nWideSize == static_cast<int>(std::size(kWideText) - 1));
		CHECK(Detours::Codec::Encode(CP_ACP, kNarrowText, arrWideBuffer.data(), nWideSize) == nWideSize);
		CHECK(std::equal(kWideText, kWideText + nWideSize, arrWideBuffer.begin()));

		int const nNarrowSize = Detours::Codec::Decode(CP_ACP, kWideText);
		REQUIRE(nNarrowSize == static_cast<int>(std::size(kNarrowText) - 1));
		CHECK(Detours::Codec::Decode(CP_ACP, kWideText, arrNarrowBuffer.data(), nNarrowSize) == nNarrowSize);
		CHECK(std::equal(kNarrowText, kNarrowText + nNarrowSize, arrNarrowBuffer.begin()));
	}

	TEST_CASE("Encode and Decode reject unterminated maximum-length input") {
		constexpr std::size_t kMaximumTextLength = 0x1000;
		std::array<char, kMaximumTextLength> arrNarrowText {};
		std::array<wchar_t, kMaximumTextLength> arrWideText {};
		arrNarrowText.fill('A');
		arrWideText.fill(L'A');

		CHECK(Detours::Codec::Encode(CP_UTF8, arrNarrowText.data(), arrNarrowText.size()) == -1);
		CHECK(Detours::Codec::Decode(CP_UTF8, arrWideText.data(), arrWideText.size()) == -1);
	}

	TEST_CASE("Encode and Decode reject invalid UTF-8 and undersized output buffers") {
		std::array<wchar_t, 2> arrWideBuffer = { L'x', L'y' };
		std::array<char, 2> arrNarrowBuffer = { 'x', 'y' };
		std::array<wchar_t, 2> const arrOriginalWideBuffer = arrWideBuffer;
		std::array<char, 2> const arrOriginalNarrowBuffer = arrNarrowBuffer;

		CHECK(Detours::Codec::Encode(CP_UTF8, "AB", arrWideBuffer.data(), 0) == -1);
		CHECK(Detours::Codec::Encode(CP_UTF8, "AB", arrWideBuffer.data(), 1) == -1);
		CHECK(Detours::Codec::Encode(CP_UTF8, "AB", arrWideBuffer.data(), -1) == -1);
		CHECK(arrWideBuffer == arrOriginalWideBuffer);

		CHECK(Detours::Codec::Decode(CP_UTF8, L"AB", arrNarrowBuffer.data(), 0) == -1);
		CHECK(Detours::Codec::Decode(CP_UTF8, L"AB", arrNarrowBuffer.data(), 1) == -1);
		CHECK(Detours::Codec::Decode(CP_UTF8, L"AB", arrNarrowBuffer.data(), -1) == -1);
		CHECK(arrNarrowBuffer == arrOriginalNarrowBuffer);

		char const arrInvalidUTF8[] = { static_cast<char>(0xC3), '(', 0 };
		wchar_t const arrInvalidWideText[] = { static_cast<wchar_t>(0xD800), 0 };
		CHECK(Detours::Codec::Encode(CP_UTF8, arrInvalidUTF8) == -1);
		CHECK(Detours::Codec::Decode(CP_UTF8, arrInvalidWideText) == -1);
	}

	TEST_CASE("Encode and Decode array frontends derive capacities") {
		wchar_t szWideBuffer[3] {};
		char szNarrowBuffer[3] {};
		CHECK(Detours::Codec::Encode(CP_UTF8, "AB", szWideBuffer) == 2);
		CHECK(wcscmp(szWideBuffer, L"AB") == 0);
		CHECK(Detours::Codec::Decode(CP_UTF8, L"AB", szNarrowBuffer) == 2);
		CHECK(strcmp(szNarrowBuffer, "AB") == 0);
	}

	TEST_CASE("Encode and Decode reject bounded guard-page input") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		REQUIRE(unPageSize >= sizeof(wchar_t));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		void* const pAllocation = VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pAllocation) {
			FAIL("Failed to allocate guarded Codec test memory.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pAllocation]() {
			VirtualFree(pAllocation, 0, MEM_RELEASE);
		});
		void* const pGuardPage = static_cast<unsigned char*>(pAllocation) + unPageSize;
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pGuardPage, unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);

		char* const szNarrowText = static_cast<char*>(pGuardPage) - 1;
		*szNarrowText = 'A';
		CHECK(Detours::Codec::Encode(CP_UTF8, szNarrowText, 1) == -1);

		wchar_t* const szWideText = reinterpret_cast<wchar_t*>(
			static_cast<unsigned char*>(pGuardPage) - sizeof(wchar_t));
		*szWideText = L'A';
		CHECK(Detours::Codec::Decode(CP_UTF8, szWideText, 1) == -1);
	}

#pragma warning(pop)
} // TEST_SUITE("Detours::Codec")

TEST_SUITE("Detours::Hexadecimal") {
	TEST_CASE("Encode accepts exact capacity and terminates output") {
		unsigned char const arrData[] = { 'A', 0x00, 'B' };
		char szNarrowHex[7] {};
		wchar_t szWideHex[7] {};
		TCHAR szHex[7] {};

		CHECK(Detours::Hexadecimal::EncodeA(arrData, sizeof(arrData), szNarrowHex, 0x00) == true);
		CHECK(strcmp(szNarrowHex, "410042") == 0);
		CHECK(szNarrowHex[6] == '\0');
		CHECK(Detours::Hexadecimal::EncodeW(arrData, sizeof(arrData), szWideHex, 0x00) == true);
		CHECK(wcscmp(szWideHex, L"410042") == 0);
		CHECK(szWideHex[6] == L'\0');
		CHECK(Detours::Hexadecimal::Encode(arrData, sizeof(arrData), szHex, 0x00) == true);
		CHECK(_tcscmp(szHex, _T("410042")) == 0);
		CHECK(szHex[6] == _T('\0'));
	}

	TEST_CASE("Encode rejects undersized and overflowing output without writes") {
		unsigned char const arrData[] = { 'A', 'B' };
		char szNarrowHex[] = { 'x', 'y', 'z', '!' };
		wchar_t szWideHex[] = { L'x', L'y', L'z', L'!' };
		TCHAR szHex[] = { _T('x'), _T('y'), _T('z'), _T('!') };
		char const szOriginalNarrowHex[] = { 'x', 'y', 'z', '!' };
		wchar_t const szOriginalWideHex[] = { L'x', L'y', L'z', L'!' };
		TCHAR const szOriginalHex[] = { _T('x'), _T('y'), _T('z'), _T('!') };

		CHECK(Detours::Hexadecimal::EncodeA(arrData, sizeof(arrData), szNarrowHex, 0x00) == false);
		CHECK(memcmp(szNarrowHex, szOriginalNarrowHex, sizeof(szNarrowHex)) == 0);
		CHECK(Detours::Hexadecimal::EncodeW(arrData, sizeof(arrData), szWideHex, 0x00) == false);
		CHECK(memcmp(szWideHex, szOriginalWideHex, sizeof(szWideHex)) == 0);
		CHECK(Detours::Hexadecimal::Encode(arrData, sizeof(arrData), szHex, 0x00) == false);
		CHECK(memcmp(szHex, szOriginalHex, sizeof(szHex)) == 0);

		char szOverflowNarrowHex[] = { 'N' };
		wchar_t szOverflowWideHex[] = { L'W' };
		CHECK(Detours::Hexadecimal::EncodeA(
			arrData,
			std::numeric_limits<std::size_t>::max(),
			szOverflowNarrowHex,
			sizeof(szOverflowNarrowHex),
			0x00) == false);
		CHECK(szOverflowNarrowHex[0] == 'N');
		CHECK(Detours::Hexadecimal::EncodeW(
			arrData,
			std::numeric_limits<std::size_t>::max(),
			szOverflowWideHex,
			sizeof(szOverflowWideHex) / sizeof(szOverflowWideHex[0]),
			0x00) == false);
		CHECK(szOverflowWideHex[0] == L'W');
	}

	TEST_CASE("Decode accepts exact capacity and preserves ignored bytes") {
		char szData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::Decode(_T("412A42"), szData, 0x2A) == true);
		CHECK(memcmp(szData, "AyB", sizeof(szData)) == 0);

		unsigned char arrNarrowData[2] {};
		unsigned char arrWideData[2] {};
		CHECK(Detours::Hexadecimal::DecodeA("4142", arrNarrowData, 0x00) == true);
		CHECK(memcmp(arrNarrowData, "AB", sizeof(arrNarrowData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142", arrWideData, 0x00) == true);
		CHECK(memcmp(arrWideData, "AB", sizeof(arrWideData)) == 0);
	}

	TEST_CASE("Decode rejects invalid or undersized output without writes") {
		char szData[] = { 'x', 'y', 'z' };
		char const szOriginalData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::Decode(_T("A"), szData, 0x2A) == false);
		CHECK(memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::Decode(_T("GG"), szData, 0x2A) == false);
		CHECK(memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeA("4142GG", szData, 0x2A) == false);
		CHECK(memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142GG", szData, 0x2A) == false);
		CHECK(memcmp(szData, szOriginalData, sizeof(szData)) == 0);

		unsigned char arrNarrowCanary[] = { 0xA5 };
		unsigned char arrWideCanary[] = { 0x5A };
		CHECK(Detours::Hexadecimal::DecodeA("4142", arrNarrowCanary, 0x00) == false);
		CHECK(arrNarrowCanary[0] == 0xA5);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142", arrWideCanary, 0x00) == false);
		CHECK(arrWideCanary[0] == 0x5A);
	}

	TEST_CASE("Decode rejects bounded guard-page input without writes") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		REQUIRE(unPageSize >= sizeof(wchar_t));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		void* const pAllocation = VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pAllocation) {
			FAIL("Failed to allocate guarded hexadecimal test memory.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pAllocation]() {
			VirtualFree(pAllocation, 0, MEM_RELEASE);
		});
		void* const pGuardPage = static_cast<unsigned char*>(pAllocation) + unPageSize;
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pGuardPage, unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);

		unsigned char arrData[] = { 0xA5, 0x5A };
		unsigned char const arrOriginalData[] = { 0xA5, 0x5A };
		char* const szNarrowHex = static_cast<char*>(pGuardPage) - 1;
		*szNarrowHex = 'A';
		CHECK(Detours::Hexadecimal::DecodeA(szNarrowHex, 1, arrData, sizeof(arrData), 0x00) == false);
		CHECK(memcmp(arrData, arrOriginalData, sizeof(arrData)) == 0);

		wchar_t* const szWideHex = reinterpret_cast<wchar_t*>(
			static_cast<unsigned char*>(pGuardPage) - sizeof(wchar_t));
		*szWideHex = L'A';
		CHECK(Detours::Hexadecimal::DecodeW(szWideHex, 1, arrData, sizeof(arrData), 0x00) == false);
		CHECK(memcmp(arrData, arrOriginalData, sizeof(arrData)) == 0);
	}
} // TEST_SUITE("Detours::Hexadecimal")

TEST_SUITE("Detours::Scan") {
	TEST_CASE("Name-based scan retains its module during the call") {
		CHECK(RunWindowsNamedModuleReferenceLifetimeTest(
			[](WindowsTemporaryModule const& Module) {
				constexpr std::array<unsigned char, 8> kPattern = {
					0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88
				};
				Detours::Scan::FindDataW(Module.GetPath(), kPattern.data(), kPattern.size());
				return true;
			}) == true);
	}

	TEST_CASE("FindSection") {
		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		CHECK(Detours::Scan::FindSection(GetModuleHandle(nullptr), { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize) == true);
		CHECK(pSection != nullptr);
		CHECK(unSectionSize != 0);
	}

	TEST_CASE("FindSignature rejects an overflowing result offset") {
		std::array<unsigned char, 1> const arrData = { 'A' };
		constexpr std::size_t kOverflowingOffset = std::numeric_limits<std::size_t>::max();
		CHECK(Detours::Scan::FindSignatureNative(arrData.data(), arrData.size(), "A", '*', kOverflowingOffset) == nullptr);
		CHECK(Detours::Scan::FindSignature(arrData.data(), arrData.size(), "A", '*', kOverflowingOffset) == nullptr);
	}

	TEST_CASE("FindSignature rejects an unterminated maximum-length signature before a guard page") {
		constexpr std::size_t kMaximumSignatureLength = 0x1000;
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() - (kMaximumSignatureLength - 1)));
		std::size_t const unReadableSize = ((kMaximumSignatureLength + unPageSize - 1) / unPageSize) * unPageSize;
		REQUIRE(unReadableSize <= (std::numeric_limits<std::size_t>::max() - unPageSize));

		void* const pAllocation = VirtualAlloc(nullptr, unReadableSize + unPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pAllocation) {
			FAIL("Failed to allocate guarded signature test memory.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pAllocation]() {
			VirtualFree(pAllocation, 0, MEM_RELEASE);
		});

		char* const szSignature = static_cast<char*>(pAllocation) + unReadableSize - kMaximumSignatureLength;
		void* const pGuardPage = static_cast<unsigned char*>(pAllocation) + unReadableSize;
		memset(szSignature, 'A', kMaximumSignatureLength);
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pGuardPage, unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);

		std::array<unsigned char, kMaximumSignatureLength> arrData {};
		arrData.fill('A');
		CPUFeatures const Features = GetCPUFeatures();
		CHECK(Detours::Scan::FindSignatureNative(arrData.data(), arrData.size(), szSignature) == nullptr);
		CHECK(Detours::Scan::FindSignature(arrData.data(), arrData.size(), szSignature) == nullptr);
		if (Features.m_bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrData.data(), arrData.size(), szSignature) == nullptr);
		}

		if (Features.m_bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrData.data(), arrData.size(), szSignature) == nullptr);
		}

		if (Features.m_bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrData.data(), arrData.size(), szSignature) == nullptr);
		}
	}

	TEST_CASE("Module and RTTI scans skip inaccessible image pages") {
		constexpr std::array<unsigned char const, Detours::Scan::kSectionNameSize> kTextSectionName = { '.', 't', 'e', 'x', 't', 0, 0, 0 };
		constexpr std::array<unsigned char, 16> kUnlikelyData = {
			0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88,
			0x79, 0x6A, 0x5B, 0x4C, 0x3D, 0x2E, 0x1F, 0xF0
		};
		HMODULE const hModule = LoadLibraryW(L"version.dll");
		REQUIRE(hModule != nullptr);
		auto ModuleCleanup = MakeScopeExit([hModule]() {
			FreeLibrary(hModule);
		});

		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		REQUIRE(Detours::Scan::FindSection(hModule, kTextSectionName, &pSection, &unSectionSize) == true);

		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		std::uintptr_t const unSectionStart = reinterpret_cast<std::uintptr_t>(pSection);
		std::uintptr_t const unSectionEnd = unSectionStart + static_cast<std::uintptr_t>(unSectionSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unSectionEnd > unSectionStart);
		REQUIRE(unSectionStart <= (std::numeric_limits<std::uintptr_t>::max() - (unPageSize - 1)));

		std::uintptr_t unProtectedPage = (unSectionStart + (unPageSize - 1)) & ~(unPageSize - 1);
		if (unProtectedPage == unSectionStart) {
			REQUIRE(unProtectedPage <= (std::numeric_limits<std::uintptr_t>::max() - unPageSize));
			unProtectedPage += unPageSize;
		}

		if ((unProtectedPage >= unSectionEnd) || (unPageSize > (unSectionEnd - unProtectedPage))) {
			MESSAGE("version.dll .text is too small for an isolated inaccessible-page test.");
			return;
		}

		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(reinterpret_cast<void*>(unProtectedPage), unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);
		auto ProtectionCleanup = MakeScopeExit([unProtectedPage, unPageSize, unOldProtection]() {
			DWORD unIgnoredProtection = 0;
			VirtualProtect(reinterpret_cast<void*>(unProtectedPage), unPageSize, unOldProtection, &unIgnoredProtection);
		});

		CHECK(Detours::Scan::FindSignature(hModule, kTextSectionName, "\xF1\xE2\xD3\xC4\xB5\xA6\x97\x88", '*') == nullptr);
		CHECK(Detours::Scan::FindData(hModule, kTextSectionName, kUnlikelyData.data(), kUnlikelyData.size()) == nullptr);
		CHECK_NOTHROW(Detours::RTTI::DumpRTTI(hModule));

		DWORD unIgnoredProtection = 0;
		REQUIRE(VirtualProtect(reinterpret_cast<void*>(unProtectedPage), unPageSize, unOldProtection, &unIgnoredProtection) != FALSE);
		ProtectionCleanup.Release();
	}

	TEST_CASE("FindSection [benchmark]" * doctest::skip() * doctest::timeout(1)) {
		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		HMODULE hModule = GetModuleHandle(nullptr);
		REQUIRE(hModule != nullptr);
		ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 10'000; ++unIteration) {
			if (!Detours::Scan::FindSection(hModule, { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize)) {
				FAIL("Fail in benchmark!");
			}
		}

		MESSAGE("Benchmark with 10 000 iterations: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSectionPOGO") {
		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		HMODULE const hModule = GetModuleHandle(nullptr);
		REQUIRE(hModule != nullptr);
		bool const bFound = Detours::Scan::FindSectionPOGO(hModule, ".rdata", &pSection, &unSectionSize);
		if (!bFound) {
			MESSAGE("The current executable does not expose POGO section metadata.");
			CHECK(pSection == nullptr);
			CHECK(unSectionSize == 0);
			return;
		}

		CHECK(pSection != nullptr);
		CHECK(unSectionSize != 0);
	}

	TEST_CASE("FindSectionPOGO [benchmark]" * doctest::skip() * doctest::timeout(1)) {
		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		HMODULE hModule = GetModuleHandle(nullptr);
		REQUIRE(hModule != nullptr);
		ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 10'000; ++unIteration) {
			if (!Detours::Scan::FindSectionPOGO(hModule, ".rdata", &pSection, &unSectionSize)) {
				FAIL("Fail in benchmark!");
			}
		}

		MESSAGE("Benchmark with 10 000 iterations: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSignature") {
		CPUFeatures const Features = GetCPUFeatures();
		bool const bHaveSSE2 = Features.m_bHaveSSE2;
		bool const bHaveAVX2 = Features.m_bHaveAVX2;
		bool const bHaveAVX512 = Features.m_bHaveAVX512;

		unsigned char arrLeakTestEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 2, "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 1, "\xDE\xED\x2A\xEF") == nullptr);
		}

		unsigned char arrAlignEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignBeginArray[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignBeginArray, sizeof(arrAlignBeginArray), "\xDE\xED\x2A\xEF") == arrAlignBeginArray);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginArray + 24);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginLeftArray + 28);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginRightArray + 32);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleEndArray + 36);
		CHECK(Detours::Scan::FindSignatureNative(arrAlignEndArray, sizeof(arrAlignEndArray), "\xDE\xED\x2A\xEF") == arrAlignEndArray + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignBeginArray, sizeof(arrAlignBeginArray), "\xDE\xED\x2A\xEF") == arrAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureSSE2(arrAlignEndArray, sizeof(arrAlignEndArray), "\xDE\xED\x2A\xEF") == arrAlignEndArray + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignBeginArray, sizeof(arrAlignBeginArray), "\xDE\xED\x2A\xEF") == arrAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureAVX2(arrAlignEndArray, sizeof(arrAlignEndArray), "\xDE\xED\x2A\xEF") == arrAlignEndArray + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignBeginArray, sizeof(arrAlignBeginArray), "\xDE\xED\x2A\xEF") == arrAlignBeginArray);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), "\xDE\xED\x2A\xEF") == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindSignatureAVX512(arrAlignEndArray, sizeof(arrAlignEndArray), "\xDE\xED\x2A\xEF") == arrAlignEndArray + 60);
		}

		unsigned char arrEmptyArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray1[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindSignatureNative(arrEmptyArray1, sizeof(arrEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrBeginArray1, sizeof(arrBeginArray1), "\xDE\xED\x2A\xEF") == arrBeginArray1 + 1);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray1 + 25);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray1 + 29);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray1 + 33);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), "\xDE\xED\x2A\xEF") == arrMiddleEndArray1 + 37);
		CHECK(Detours::Scan::FindSignatureNative(arrEndArray1, sizeof(arrEndArray1), "\xDE\xED\x2A\xEF") == arrEndArray1 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrEmptyArray1, sizeof(arrEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrBeginArray1, sizeof(arrBeginArray1), "\xDE\xED\x2A\xEF") == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), "\xDE\xED\x2A\xEF") == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureSSE2(arrEndArray1, sizeof(arrEndArray1), "\xDE\xED\x2A\xEF") == arrEndArray1 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrEmptyArray1, sizeof(arrEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrBeginArray1, sizeof(arrBeginArray1), "\xDE\xED\x2A\xEF") == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), "\xDE\xED\x2A\xEF") == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureAVX2(arrEndArray1, sizeof(arrEndArray1), "\xDE\xED\x2A\xEF") == arrEndArray1 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrEmptyArray1, sizeof(arrEmptyArray1), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrBeginArray1, sizeof(arrBeginArray1), "\xDE\xED\x2A\xEF") == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), "\xDE\xED\x2A\xEF") == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindSignatureAVX512(arrEndArray1, sizeof(arrEndArray1), "\xDE\xED\x2A\xEF") == arrEndArray1 + 61);
		}

		unsigned char arrEmptyArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray2[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindSignatureNative(arrEmptyArray2, sizeof(arrEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrBeginArray2, sizeof(arrBeginArray2), "\xDE\xED\x2A\xEF") == arrBeginArray2);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray2 + 24);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray2 + 28);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray2 + 32);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), "\xDE\xED\x2A\xEF") == arrMiddleEndArray2 + 36);
		CHECK(Detours::Scan::FindSignatureNative(arrEndArray2, sizeof(arrEndArray2), "\xDE\xED\x2A\xEF") == arrEndArray2 + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrEmptyArray2, sizeof(arrEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrBeginArray2, sizeof(arrBeginArray2), "\xDE\xED\x2A\xEF") == arrBeginArray2);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), "\xDE\xED\x2A\xEF") == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureSSE2(arrEndArray2, sizeof(arrEndArray2), "\xDE\xED\x2A\xEF") == arrEndArray2 + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrEmptyArray2, sizeof(arrEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrBeginArray2, sizeof(arrBeginArray2), "\xDE\xED\x2A\xEF") == arrBeginArray2);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), "\xDE\xED\x2A\xEF") == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureAVX2(arrEndArray2, sizeof(arrEndArray2), "\xDE\xED\x2A\xEF") == arrEndArray2 + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrEmptyArray2, sizeof(arrEmptyArray2), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrBeginArray2, sizeof(arrBeginArray2), "\xDE\xED\x2A\xEF") == arrBeginArray2);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), "\xDE\xED\x2A\xEF") == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindSignatureAVX512(arrEndArray2, sizeof(arrEndArray2), "\xDE\xED\x2A\xEF") == arrEndArray2 + 60);
		}

		unsigned char arrEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindSignatureNative(arrEmptyArray3, sizeof(arrEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
		CHECK(Detours::Scan::FindSignatureNative(arrBeginArray3, sizeof(arrBeginArray3), "\xDE\xED\x2A\xEF") == arrBeginArray3 + 1);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray3 + 25);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray3 + 29);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray3 + 33);
		CHECK(Detours::Scan::FindSignatureNative(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), "\xDE\xED\x2A\xEF") == arrMiddleEndArray3 + 37);
		CHECK(Detours::Scan::FindSignatureNative(arrEndArray3, sizeof(arrEndArray3), "\xDE\xED\x2A\xEF") == arrEndArray3 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindSignatureSSE2(arrEmptyArray3, sizeof(arrEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureSSE2(arrBeginArray3, sizeof(arrBeginArray3), "\xDE\xED\x2A\xEF") == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureSSE2(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), "\xDE\xED\x2A\xEF") == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureSSE2(arrEndArray3, sizeof(arrEndArray3), "\xDE\xED\x2A\xEF") == arrEndArray3 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindSignatureAVX2(arrEmptyArray3, sizeof(arrEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX2(arrBeginArray3, sizeof(arrBeginArray3), "\xDE\xED\x2A\xEF") == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureAVX2(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), "\xDE\xED\x2A\xEF") == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureAVX2(arrEndArray3, sizeof(arrEndArray3), "\xDE\xED\x2A\xEF") == arrEndArray3 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindSignatureAVX512(arrEmptyArray3, sizeof(arrEmptyArray3), "\xDE\xED\x2A\xEF") == nullptr);
			CHECK(Detours::Scan::FindSignatureAVX512(arrBeginArray3, sizeof(arrBeginArray3), "\xDE\xED\x2A\xEF") == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), "\xDE\xED\x2A\xEF") == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindSignatureAVX512(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), "\xDE\xED\x2A\xEF") == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindSignatureAVX512(arrEndArray3, sizeof(arrEndArray3), "\xDE\xED\x2A\xEF") == arrEndArray3 + 61);
		}
	}

	TEST_CASE("FindSignatureNative [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
			if (!Detours::Scan::FindSignatureNative(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
				FAIL("Fail in benchmark!");
			}
		}

		MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindSignatureSSE2 [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveSSE2 = GetCPUFeatures().m_bHaveSSE2;

		if (bHaveSSE2) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindSignatureSSE2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindSignatureAVX2 [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveAVX2 = GetCPUFeatures().m_bHaveAVX2;

		if (bHaveAVX2) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindSignatureAVX2(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindSignatureAVX512 [benchmark]" * doctest::skip()) {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveAVX512 = GetCPUFeatures().m_bHaveAVX512;

		if (bHaveAVX512) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindSignatureAVX512(pRandomData.get(), 0x800000, "\xDE\xED\x2A\xEF")) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindData") {
		CHECK(Detours::Scan::FindData(GetModuleHandle(nullptr), { '.', 'r', 'd', 'a', 't', 'a', 0, 0 }, reinterpret_cast<unsigned char const* const>("\xDE\xED\xBE\xEF"), 4) != nullptr);

		CPUFeatures const Features = GetCPUFeatures();
		bool const bHaveSSE2 = Features.m_bHaveSSE2;
		bool const bHaveAVX2 = Features.m_bHaveAVX2;
		bool const bHaveAVX512 = Features.m_bHaveAVX512;

		unsigned char arrLeakTestEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 4, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(arrLeakTestEmptyArray, sizeof(arrLeakTestEmptyArray) - 3, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		}

		unsigned char arrAlignEmptyArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignBeginArray[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginLeftArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleBeginRightArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignMiddleEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrAlignEndArray[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(arrAlignBeginArray, sizeof(arrAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignBeginArray);
		CHECK(Detours::Scan::FindDataNative(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginArray + 24);
		CHECK(Detours::Scan::FindDataNative(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginLeftArray + 28);
		CHECK(Detours::Scan::FindDataNative(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginRightArray + 32);
		CHECK(Detours::Scan::FindDataNative(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleEndArray + 36);
		CHECK(Detours::Scan::FindDataNative(arrAlignEndArray, sizeof(arrAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignEndArray + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignBeginArray, sizeof(arrAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignBeginArray);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataSSE2(arrAlignEndArray, sizeof(arrAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignEndArray + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignBeginArray, sizeof(arrAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignBeginArray);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataAVX2(arrAlignEndArray, sizeof(arrAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignEndArray + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(arrAlignEmptyArray, sizeof(arrAlignEmptyArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignBeginArray, sizeof(arrAlignBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignBeginArray);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignMiddleBeginArray, sizeof(arrAlignMiddleBeginArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginArray + 24);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignMiddleBeginLeftArray, sizeof(arrAlignMiddleBeginLeftArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginLeftArray + 28);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignMiddleBeginRightArray, sizeof(arrAlignMiddleBeginRightArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleBeginRightArray + 32);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignMiddleEndArray, sizeof(arrAlignMiddleEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignMiddleEndArray + 36);
			CHECK(Detours::Scan::FindDataAVX512(arrAlignEndArray, sizeof(arrAlignEndArray), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrAlignEndArray + 60);
		}

		unsigned char arrEmptyArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray1[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindDataNative(arrEmptyArray1, sizeof(arrEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(arrBeginArray1, sizeof(arrBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray1 + 1);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray1 + 25);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray1 + 29);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray1 + 33);
		CHECK(Detours::Scan::FindDataNative(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray1 + 37);
		CHECK(Detours::Scan::FindDataNative(arrEndArray1, sizeof(arrEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray1 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(arrEmptyArray1, sizeof(arrEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(arrBeginArray1, sizeof(arrBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataSSE2(arrEndArray1, sizeof(arrEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray1 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(arrEmptyArray1, sizeof(arrEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(arrBeginArray1, sizeof(arrBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataAVX2(arrEndArray1, sizeof(arrEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray1 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(arrEmptyArray1, sizeof(arrEmptyArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(arrBeginArray1, sizeof(arrBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray1 + 1);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginArray1, sizeof(arrMiddleBeginArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray1 + 25);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginLeftArray1, sizeof(arrMiddleBeginLeftArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray1 + 29);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginRightArray1, sizeof(arrMiddleBeginRightArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray1 + 33);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleEndArray1, sizeof(arrMiddleEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray1 + 37);
			CHECK(Detours::Scan::FindDataAVX512(arrEndArray1, sizeof(arrEndArray1), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray1 + 61);
		}

		unsigned char arrEmptyArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray2[] = { 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00 };

		CHECK(Detours::Scan::FindDataNative(arrEmptyArray2, sizeof(arrEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(arrBeginArray2, sizeof(arrBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray2);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray2 + 24);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray2 + 28);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray2 + 32);
		CHECK(Detours::Scan::FindDataNative(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray2 + 36);
		CHECK(Detours::Scan::FindDataNative(arrEndArray2, sizeof(arrEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray2 + 60);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(arrEmptyArray2, sizeof(arrEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(arrBeginArray2, sizeof(arrBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray2);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataSSE2(arrEndArray2, sizeof(arrEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray2 + 60);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(arrEmptyArray2, sizeof(arrEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(arrBeginArray2, sizeof(arrBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray2);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataAVX2(arrEndArray2, sizeof(arrEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray2 + 60);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(arrEmptyArray2, sizeof(arrEmptyArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(arrBeginArray2, sizeof(arrBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray2);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginArray2, sizeof(arrMiddleBeginArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray2 + 24);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginLeftArray2, sizeof(arrMiddleBeginLeftArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray2 + 28);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginRightArray2, sizeof(arrMiddleBeginRightArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray2 + 32);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleEndArray2, sizeof(arrMiddleEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray2 + 36);
			CHECK(Detours::Scan::FindDataAVX512(arrEndArray2, sizeof(arrEndArray2), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray2 + 60);
		}

		unsigned char arrEmptyArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrBeginArray3[] = { 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginLeftArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleBeginRightArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrMiddleEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		unsigned char arrEndArray3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xED, 0xBE, 0xEF };

		CHECK(Detours::Scan::FindDataNative(arrEmptyArray3, sizeof(arrEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
		CHECK(Detours::Scan::FindDataNative(arrBeginArray3, sizeof(arrBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray3 + 1);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray3 + 25);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray3 + 29);
		CHECK(Detours::Scan::FindDataNative(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray3 + 33);
		CHECK(Detours::Scan::FindDataNative(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray3 + 37);
		CHECK(Detours::Scan::FindDataNative(arrEndArray3, sizeof(arrEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray3 + 61);

		if (bHaveSSE2) {
			CHECK(Detours::Scan::FindDataSSE2(arrEmptyArray3, sizeof(arrEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataSSE2(arrBeginArray3, sizeof(arrBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataSSE2(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataSSE2(arrEndArray3, sizeof(arrEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray3 + 61);
		}

		if (bHaveAVX2) {
			CHECK(Detours::Scan::FindDataAVX2(arrEmptyArray3, sizeof(arrEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX2(arrBeginArray3, sizeof(arrBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataAVX2(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataAVX2(arrEndArray3, sizeof(arrEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray3 + 61);
		}

		if (bHaveAVX512) {
			CHECK(Detours::Scan::FindDataAVX512(arrEmptyArray3, sizeof(arrEmptyArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == nullptr);
			CHECK(Detours::Scan::FindDataAVX512(arrBeginArray3, sizeof(arrBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrBeginArray3 + 1);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginArray3, sizeof(arrMiddleBeginArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginArray3 + 25);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginLeftArray3, sizeof(arrMiddleBeginLeftArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginLeftArray3 + 29);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleBeginRightArray3, sizeof(arrMiddleBeginRightArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleBeginRightArray3 + 33);
			CHECK(Detours::Scan::FindDataAVX512(arrMiddleEndArray3, sizeof(arrMiddleEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrMiddleEndArray3 + 37);
			CHECK(Detours::Scan::FindDataAVX512(arrEndArray3, sizeof(arrEndArray3), reinterpret_cast<unsigned char const*>("\xDE\xED"), 2) == arrEndArray3 + 61);
		}
	}

	TEST_CASE("FindDataNative [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
			if (!Detours::Scan::FindDataNative(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
				FAIL("Fail in benchmark!");
			}
		}

		MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
	}

	TEST_CASE("FindDataSSE2 [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveSSE2 = GetCPUFeatures().m_bHaveSSE2;

		if (bHaveSSE2) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindDataSSE2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindDataAVX2 [benchmark]") {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveAVX2 = GetCPUFeatures().m_bHaveAVX2;

		if (bHaveAVX2) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindDataAVX2(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}

	TEST_CASE("FindDataAVX512A respects the requested POGO section") {
		if (!GetCPUFeatures().m_bHaveAVX512) {
			return;
		}

		HMODULE const hModule = GetModuleHandle(nullptr);
		REQUIRE(hModule != nullptr);

		void* pText = nullptr;
		std::size_t unTextSize = 0;
		if (!Detours::Scan::FindSectionPOGO(hModule, ".text", &pText, &unTextSize)) {
			MESSAGE("The current executable does not expose a .text POGO section.");
			return;
		}

		std::uintptr_t const unTextBegin = reinterpret_cast<std::uintptr_t>(pText);
		std::uintptr_t const unPatternAddress = reinterpret_cast<std::uintptr_t>(kScanOutsideTextPattern.data());
		REQUIRE(unTextBegin <= (std::numeric_limits<std::uintptr_t>::max() - static_cast<std::uintptr_t>(unTextSize)));
		bool const bPatternOutsideText = (unPatternAddress < unTextBegin) || (unPatternAddress >= (unTextBegin + static_cast<std::uintptr_t>(unTextSize)));
		REQUIRE(bPatternOutsideText == true);

		std::array<char, MAX_PATH> arrModulePath {};
		DWORD const unModulePathLength = GetModuleFileNameA(nullptr, arrModulePath.data(), static_cast<DWORD>(arrModulePath.size()));
		REQUIRE(unModulePathLength != 0);
		REQUIRE(unModulePathLength < arrModulePath.size());
		char const* szModuleName = arrModulePath.data();
		if (char const* const szSeparator = std::strrchr(szModuleName, '\\')) {
			szModuleName = szSeparator + 1;
		}

		REQUIRE(Detours::Scan::FindDataAVX512A(szModuleName, kScanOutsideTextPattern.data(), kScanOutsideTextPattern.size()) != nullptr);
		CHECK(Detours::Scan::FindDataAVX512A(szModuleName, ".text", kScanOutsideTextPattern.data(), kScanOutsideTextPattern.size()) == nullptr);
	}

	TEST_CASE("FindDataAVX512 [benchmark]" * doctest::skip()) {
		std::unique_ptr<unsigned char[]> pRandomData = std::make_unique<unsigned char[]>(0x800000); // 8 MiB
		REQUIRE(pRandomData != nullptr);

		memset(pRandomData.get(), 0, 0x800000);

		pRandomData[0x800000 - 4] = 0xDE;
		pRandomData[0x800000 - 3] = 0xED;
		pRandomData[0x800000 - 2] = 0xBE;
		pRandomData[0x800000 - 1] = 0xEF;

		bool const bHaveAVX512 = GetCPUFeatures().m_bHaveAVX512;

		if (bHaveAVX512) {
			ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
			for (std::size_t unIteration = 0; unIteration < 1'000; ++unIteration) {
				if (!Detours::Scan::FindDataAVX512(pRandomData.get(), 0x800000, reinterpret_cast<unsigned char const*>("\xDE\xED"), 2)) {
					FAIL("Fail in benchmark!");
				}
			}

			MESSAGE("Benchmark with 1 000 iterations over 8 MiB memory: ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		}
	}
} // TEST_SUITE("Detours::Scan")

#ifndef _DEBUG
DISABLE_OPTIMIZATION_BEGIN("") {
#endif

	TEST_SUITE("Detours::RTTI") {
		TEST_CASE("Name-based RTTI discovery retains its module during the call") {
			CHECK(RunWindowsNamedModuleReferenceLifetimeTest(
				[](WindowsTemporaryModule const& Module) {
					std::unique_ptr<Detours::RTTI::Object> pObject = Detours::RTTI::FindObjectA(
						Module.GetAnsiBaseName(),
						".?AV__DetoursMissingTemporaryModuleType__@@");
					return pObject == nullptr;
				}) == true);
		}

		TEST_CASE("DumpRTTI") {
			std::vector<std::unique_ptr<Detours::RTTI::Object>> vecRTTIObjects = Detours::RTTI::DumpRTTI(GetModuleHandle(nullptr));
			for (auto& pRTTIObject : vecRTTIObjects) {
				printf("Name: `%s`\n", pRTTIObject->GetTypeDescriptor()->m_szName);
			}
		}

		TEST_CASE("FindRTTI") {
			// Construct a small hierarchy and verify we can locate RTTI for a derived type
			// and extract a working vtable to call through.
			ScopedTestingRTTIObjects TestingObjects(g_pBaseTestingRTTI, g_pTestingRTTI);

			// Find TestingRTTI while asserting it has BaseTestingRTTI as a parent.
			std::unique_ptr<Detours::RTTI::Object> pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@", ".?AVBaseTestingRTTI@@");
			REQUIRE(pObject != nullptr);

			// Pull vtable for direct call tests.
			void** pVTable = pObject->GetVTable();
			REQUIRE(pVTable != nullptr);

			// The test interface: two virtuals with boolean returns.
			using fnFoo = bool(__fastcall*)(void* pThis, void*);
			using fnBoo = bool(__fastcall*)(void* pThis, void*);

			// Validate the vtable entries invoke expected implementations.
			CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
			CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);
		}

		TEST_CASE("DynamicCastingRTTI") {
			// Cross-check base->derived selection using our dynamic cast engine.
			MessageOne Message1;
			MessageTwo Message2;

			// Query RTTI nodes for BaseMessage and the two derived message types.
			std::unique_ptr<Detours::RTTI::Object> pBaseMessageObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVBaseMessage@@", nullptr, false);
			REQUIRE(pBaseMessageObject != nullptr);

			std::unique_ptr<Detours::RTTI::Object> pMessageOneObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVMessageOne@@", ".?AVBaseMessage@@");
			REQUIRE(pMessageOneObject != nullptr);

			std::unique_ptr<Detours::RTTI::Object> pMessageTwoObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVMessageTwo@@");
			REQUIRE(pMessageTwoObject != nullptr);

			// base -> MessageOne should succeed for Msg1; fail for Msg2 (and vice versa).
			CHECK(pBaseMessageObject->DynamicCast(&Message1, pMessageOneObject.get()) != nullptr);
			CHECK(pBaseMessageObject->DynamicCast(&Message1, pMessageTwoObject.get()) == nullptr);
			CHECK(pBaseMessageObject->DynamicCast(&Message2, pMessageOneObject.get()) == nullptr);
			CHECK(pBaseMessageObject->DynamicCast(&Message2, pMessageTwoObject.get()) != nullptr);
		}

		TEST_CASE("FindRTTI_SI_by_typeid") {
			// Validate simple single-inheritance upcast and downcast using RTTI graph.
			SI_Derived Derived;
			SI_Derived* pDerived = &Derived;

			// Fetch RTTI nodes by typeid-mangled name: SI_Base and SI_Derived.
			std::unique_ptr<Detours::RTTI::Object> pBaseObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<SI_Base>(), nullptr, /*bCompleteObject*/ false);
			std::unique_ptr<Detours::RTTI::Object> pDerivedObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<SI_Derived>(), GetTypeName<SI_Base>());

			REQUIRE(pBaseObject != nullptr);
			REQUIRE(pDerivedObject != nullptr);

			// Upcast: Derived* -> Base* must succeed.
			CHECK(pDerivedObject->DynamicCast(pDerived, pBaseObject.get()) != nullptr);

			// Downcast: Base* -> Derived* must succeed too (same most-derived).
			SI_Base* pBase = pDerived;
			CHECK(pBaseObject->DynamicCast(pBase, pDerivedObject.get()) != nullptr);
		}

		TEST_CASE("FindRTTI_ParentFilter_Positive_and_Negative") {
			// Verify the optional "parent" filter in FindObject acts as expected.

			// Positive: MI_D has MI_A somewhere in its ancestry.
			std::unique_ptr<Detours::RTTI::Object> pDerivedWithBaseAObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_D>(), GetTypeName<MI_A>());
			REQUIRE(pDerivedWithBaseAObject != nullptr);

			// Negative: MI_D is not derived from SI_Derived.
			std::unique_ptr<Detours::RTTI::Object> pDerivedWithInvalidBaseObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_D>(), GetTypeName<SI_Derived>());
			CHECK(pDerivedWithInvalidBaseObject == nullptr);
		}

		TEST_CASE("FindRTTI_MI_CompleteObject_Offsets") {
			// When searching for a complete object, the offset must match the
			// subobject layout of the most-derived (MI) object.
			MI_D Derived;
			MI_D* pDerived = &Derived;

			// Take subobject pointers and compute their offsets within D.
			MI_A* pBaseA = static_cast<MI_A*>(pDerived);
			MI_B* pBaseB = static_cast<MI_B*>(pDerived);
			void* pDerivedAddress = static_cast<void*>(pDerived);

			std::ptrdiff_t nBaseAOffset = reinterpret_cast<char const*>(static_cast<void*>(pBaseA)) - reinterpret_cast<char const*>(pDerivedAddress);
			std::ptrdiff_t nBaseBOffset = reinterpret_cast<char const*>(static_cast<void*>(pBaseB)) - reinterpret_cast<char const*>(pDerivedAddress);

			// Correct offset for A must yield a valid object with vtable.
			std::unique_ptr<Detours::RTTI::Object> pDerivedAtBaseAOffsetObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(nBaseAOffset));
			REQUIRE(pDerivedAtBaseAOffsetObject != nullptr);
			CHECK(pDerivedAtBaseAOffsetObject->GetVTable() != nullptr);

			// Wrong offset should not match.
			std::unique_ptr<Detours::RTTI::Object> pDerivedAtInvalidOffsetObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(nBaseBOffset + 4));
			CHECK(pDerivedAtInvalidOffsetObject == nullptr);

			// Correct offset for B must also match.
			std::unique_ptr<Detours::RTTI::Object> pDerivedAtBaseBOffsetObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_D>(), /*parent*/ nullptr, /*bCompleteObject*/ true, static_cast<unsigned>(nBaseBOffset));
			REQUIRE(pDerivedAtBaseBOffsetObject != nullptr);
			CHECK(pDerivedAtBaseBOffsetObject->GetVTable() != nullptr);
		}

		TEST_CASE("DynamicCast_CrossCast_MI") {
			// Cross-cast across branches in an MI diamond:
			//   D : A, B - casting A* -> B* and B* -> A* should succeed via D.
			MI_D Derived;
			MI_D* pDerived = &Derived;

			std::unique_ptr<Detours::RTTI::Object> pBaseAObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_A>(), nullptr, false);
			std::unique_ptr<Detours::RTTI::Object> pBaseBObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<MI_B>(), nullptr, false);
			REQUIRE(pBaseAObject != nullptr);
			REQUIRE(pBaseBObject != nullptr);

			MI_A* pBaseA = pDerived;
			CHECK(pBaseAObject->DynamicCast(pBaseA, pBaseBObject.get()) != nullptr);

			MI_B* pBaseB = pDerived;
			CHECK(pBaseBObject->DynamicCast(pBaseB, pBaseAObject.get()) != nullptr);
		}

		TEST_CASE("DynamicCast_CrossCast_VI") {
			// Cross-cast through a virtual base path:
			//   D : VI_A, VI_B; both are virtually derived from VI_V.
			VI_D Derived;
			VI_D* pDerived = &Derived;

			std::unique_ptr<Detours::RTTI::Object> pBaseAObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<VI_A>(), nullptr, false);
			std::unique_ptr<Detours::RTTI::Object> pBaseBObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<VI_B>(), nullptr, false);
			REQUIRE(pBaseAObject != nullptr);
			REQUIRE(pBaseBObject != nullptr);

			VI_A* pBaseA = pDerived;
			CHECK(pBaseAObject->DynamicCast(pBaseA, pBaseBObject.get()) != nullptr);

			VI_B* pBaseB = pDerived;
			CHECK(pBaseBObject->DynamicCast(pBaseB, pBaseAObject.get()) != nullptr);
		}

		TEST_CASE("DynamicCast_PrivateBase_is_blocked") {
			// Access control must be enforced: private base prevents a legal up/down cast.
			PrivDerived Derived;
			PrivDerived* pDerived = &Derived;

			std::unique_ptr<Detours::RTTI::Object> pBaseObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<PrivBase>(), nullptr, false);
			std::unique_ptr<Detours::RTTI::Object> pDerivedObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<PrivDerived>(), GetTypeName<PrivBase>());
			REQUIRE(pBaseObject != nullptr);
			REQUIRE(pDerivedObject != nullptr);

			PrivBase* pBase = pDerived->AsBase();                                    // returns pointer to private base subobject
			CHECK(pBaseObject->DynamicCast(pBase, pDerivedObject.get()) == nullptr); // cast must be blocked
		}

		TEST_CASE("FindObject_Wide_and_Ansi_ModuleName") {
			// The ANSI and WIDE variants must both locate the same type in the same module.
			wchar_t szWideModulePath[MAX_PATH] = {};
			DWORD unWideModulePathLength = GetModuleFileNameW(nullptr, szWideModulePath, MAX_PATH);
			REQUIRE(unWideModulePathLength > 0);
			REQUIRE(unWideModulePathLength < MAX_PATH);

			char szAnsiModulePath[MAX_PATH] = {};
			DWORD unAnsiModulePathLength = GetModuleFileNameA(nullptr, szAnsiModulePath, MAX_PATH);
			REQUIRE(unAnsiModulePathLength > 0);
			REQUIRE(unAnsiModulePathLength < MAX_PATH);

			std::unique_ptr<Detours::RTTI::Object> pWideObject = Detours::RTTI::FindObjectW(szWideModulePath, GetTypeName<SI_Derived>(), GetTypeName<SI_Base>());
			std::unique_ptr<Detours::RTTI::Object> pAnsiObject = Detours::RTTI::FindObjectA(szAnsiModulePath, GetTypeName<SI_Derived>(), GetTypeName<SI_Base>());
			REQUIRE(pWideObject != nullptr);
			REQUIRE(pAnsiObject != nullptr);
		}

		TEST_CASE("FindRTTI_NotFound_WrongName") {
			// Gracefully returns nullptr for non-existent type names.
			std::unique_ptr<Detours::RTTI::Object> pObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AV__Definitely_No_Such_Type__@@", nullptr, false);
			CHECK(pObject == nullptr);
		}

		TEST_CASE("FindRTTI_Complete_vs_Partial_paths") {
			// Compare the partial (no strict COL) and complete (strict COL + offset) paths.

			std::unique_ptr<Detours::RTTI::Object> pPartialObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<SI_Derived>(), GetTypeName<SI_Base>(), /*bCompleteObject*/ false);
			REQUIRE(pPartialObject != nullptr);

			std::unique_ptr<Detours::RTTI::Object> pCompleteObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<SI_Derived>(), GetTypeName<SI_Base>(), /*bCompleteObject*/ true, /*unOffset*/ 0);
			REQUIRE(pCompleteObject != nullptr);

			std::unique_ptr<Detours::RTTI::Object> pInvalidOffsetObject = Detours::RTTI::FindObject(GetModuleHandle(nullptr), GetTypeName<SI_Derived>(), GetTypeName<SI_Base>(), /*bCompleteObject*/ true, /*unOffset*/ 4);
			CHECK(pInvalidOffsetObject == nullptr);
		}

		TEST_CASE("RTCastToVoid_returns_complete_object_SI_MI_VI") {
			// RTCastToVoid should return the most-derived (complete object) pointer.

			// --- SI case ---
			{
				SI_Derived Derived;
				SI_Derived* pDerived = &Derived;

				SI_Base* pBase = pDerived;
				void* pCompleteObject = static_cast<void*>(pDerived);
				CHECK(Detours::RTTI::RTCastToVoid(pBase) == pCompleteObject);
			}

			// --- MI case ---
			{
				MI_D Derived;
				MI_D* pDerived = &Derived;

				MI_A* pBaseA = pDerived;
				MI_B* pBaseB = pDerived;
				void* pCompleteObject = static_cast<void*>(pDerived);

				CHECK(Detours::RTTI::RTCastToVoid(pBaseA) == pCompleteObject);
				CHECK(Detours::RTTI::RTCastToVoid(pBaseB) == pCompleteObject);
			}

			// --- VI case ---
			{
				VI_D Derived;
				VI_D* pDerived = &Derived;

				VI_A* pBaseA = pDerived;
				VI_B* pBaseB = pDerived;
				void* pCompleteObject = static_cast<void*>(pDerived);

				CHECK(Detours::RTTI::RTCastToVoid(pBaseA) == pCompleteObject);
				CHECK(Detours::RTTI::RTCastToVoid(pBaseB) == pCompleteObject);
			}
		}

		TEST_CASE("RTCastToVoid rejects readable invalid RTTI metadata") {
			constexpr std::size_t kFakeObjectPointerCount = (0x80 / sizeof(void*)) + 1;
			Detours::RTTI::RTTI_COMPLETE_OBJECT_LOCATOR InvalidLocator {};
			InvalidLocator.m_unOffset = sizeof(void*);
			void* arrVTableStorage[] = { &InvalidLocator, nullptr };
			std::array<void*, kFakeObjectPointerCount> arrObjectStorage {};
			arrObjectStorage[0] = &arrVTableStorage[1];

			CHECK_THROWS_AS(Detours::RTTI::RTCastToVoid(arrObjectStorage.data()), std::runtime_error);
		}

		TEST_CASE("RTDynamicCast preserves pointer and reference failure semantics for invalid input") {
#if defined(_M_X64)
			CHECK(Detours::RTTI::RTDynamicCast(nullptr, nullptr, 0, nullptr, nullptr, FALSE) == nullptr);
			CHECK_THROWS_AS(
				Detours::RTTI::RTDynamicCast(nullptr, nullptr, 0, nullptr, nullptr, TRUE),
				std::bad_cast);
#elif defined(_M_IX86)
			CHECK(Detours::RTTI::RTDynamicCast(nullptr, 0, nullptr, nullptr, FALSE) == nullptr);
			CHECK_THROWS_AS(
				Detours::RTTI::RTDynamicCast(nullptr, 0, nullptr, nullptr, TRUE),
				std::bad_cast);
#endif
		}

		TEST_CASE("RTDynamicCast reference failure throws bad_cast after access violation") {
			void* const pInvalidAddress = reinterpret_cast<void*>(static_cast<std::size_t>(1));
			Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pInvalidTypeDescriptor = reinterpret_cast<Detours::RTTI::PRTTI_TYPE_DESCRIPTOR>(static_cast<std::size_t>(1));
#if defined(_M_X64)
			CHECK_THROWS_AS(Detours::RTTI::RTDynamicCast(GetModuleHandle(nullptr), pInvalidAddress, 0, pInvalidTypeDescriptor, pInvalidTypeDescriptor, TRUE), std::bad_cast);
#elif defined(_M_IX86)
			CHECK_THROWS_AS(Detours::RTTI::RTDynamicCast(pInvalidAddress, 0, pInvalidTypeDescriptor, pInvalidTypeDescriptor, TRUE), std::bad_cast);
#endif
		}

		TEST_CASE("RTtypeid_dynamic_type_matches") {
			// RTtypeid should reflect the dynamic type of the most-derived object
			// no matter which base-subobject pointer is used.

			// --- SI: Base* -> Derived dynamic type ---
			{
				SI_Derived Derived;
				SI_Derived* pDerived = &Derived;

				SI_Base* pBase = pDerived;
#if defined(_M_X64)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptor = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(pBase));
#elif defined(_M_IX86)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptor = Detours::RTTI::RTtypeid(static_cast<void*>(pBase));
#endif
				REQUIRE(pTypeDescriptor != nullptr);
				CHECK(strncmp(pTypeDescriptor->m_szName, GetTypeName<SI_Derived>(), 0x1000) == 0);
			}

			// --- MI: Any base subobject must yield MI_D as dynamic type ---
			{
				MI_D Derived;
				MI_D* pDerived = &Derived;

				MI_A* pBaseA = pDerived;
#if defined(_M_X64)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptorA = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(pBaseA));
#elif defined(_M_IX86)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptorA = Detours::RTTI::RTtypeid(static_cast<void*>(pBaseA));
#endif
				REQUIRE(pTypeDescriptorA != nullptr);
				CHECK(strncmp(pTypeDescriptorA->m_szName, GetTypeName<MI_D>(), 0x1000) == 0);

				MI_B* pBaseB = pDerived;
#if defined(_M_X64)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptorB = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(pBaseB));
#elif defined(_M_IX86)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptorB = Detours::RTTI::RTtypeid(static_cast<void*>(pBaseB));
#endif
				REQUIRE(pTypeDescriptorB != nullptr);
				CHECK(strncmp(pTypeDescriptorB->m_szName, GetTypeName<MI_D>(), 0x1000) == 0);
			}

			// --- VI: Through virtually inherited subobject, dynamic must be VI_D ---
			{
				VI_D Derived;
				VI_D* pDerived = &Derived;

				VI_A* pBaseA = pDerived;
#if defined(_M_X64)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptor = Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(pBaseA));
#elif defined(_M_IX86)
				Detours::RTTI::PRTTI_TYPE_DESCRIPTOR const pTypeDescriptor = Detours::RTTI::RTtypeid(static_cast<void*>(pBaseA));
#endif
				REQUIRE(pTypeDescriptor != nullptr);
				CHECK(strncmp(pTypeDescriptor->m_szName, GetTypeName<VI_D>(), 0x1000) == 0);
			}
		}

		TEST_CASE("RTtypeid_nullptr_throws_bad_typeid") {
			// Standard compliance: typeid(*p) with p == nullptr should throw std::bad_typeid.
#if defined(_M_X64)
			CHECK_THROWS_AS(Detours::RTTI::RTtypeid(GetModuleHandle(nullptr), static_cast<void*>(nullptr)), std::bad_typeid);
#elif defined(_M_IX86)
		CHECK_THROWS_AS(Detours::RTTI::RTtypeid(static_cast<void*>(nullptr)), std::bad_typeid);
#endif
		}
	} // TEST_SUITE("Detours::RTTI")

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
		TCHAR m_szEventName[Detours::kNamedObjectNameCapacity];
	} EVENTCLIENT_DATA, *PEVENTCLIENT_DATA;

	typedef struct _MUTEX_DATA {
		Detours::Sync::Event* m_pEvent;
		Detours::Sync::Mutex* m_pMutex;
		std::atomic<bool>* m_pResult;
	} MUTEX_DATA, *PMUTEX_DATA;

	typedef struct _MUTEXCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		std::atomic<bool>* m_pResult;
		TCHAR m_szMutexName[Detours::kNamedObjectNameCapacity];
	} MUTEXCLIENT_DATA, *PMUTEXCLIENT_DATA;

	typedef struct _SEMAPHORE_DATA {
		Detours::Sync::Event* m_pEvent;
		Detours::Sync::Semaphore* m_pSemaphore;
	} SEMAPHORE_DATA, *PSEMAPHORE_DATA;

	typedef struct _SEMAPHORECLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szSemaphoreName[Detours::kNamedObjectNameCapacity];
	} SEMAPHORECLIENT_DATA, *PSEMAPHORECLIENT_DATA;

	void OnEventThread(void* pData) {
		PEVENT_DATA pEventData = reinterpret_cast<PEVENT_DATA>(pData);
		if (!pEventData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pEventData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		pEventData->m_unData = 0xBEEFDEED;
	}

	void OnEventClientThread(void* pData) {
		PEVENTCLIENT_DATA pEventClientData = reinterpret_cast<PEVENTCLIENT_DATA>(pData);
		if (!pEventClientData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pEventClientData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Sync::EventClient EventClient(pEventClientData->m_szEventName);
		EventClient.Signal();
	}

	void OnMutexThread(void* pData) {
		PMUTEX_DATA pMutexData = reinterpret_cast<PMUTEX_DATA>(pData);
		if (!pMutexData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pMutexData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Sync::Mutex* const pMutex = pMutexData->m_pMutex;
		std::atomic<bool>* const pResult = pMutexData->m_pResult;
		if (pMutex && pResult) {
			pResult->store(pMutex->UnLock(), std::memory_order_release);
		}
	}

	void OnMutexClientThread(void* pData) {
		PMUTEXCLIENT_DATA pMutexClientData = reinterpret_cast<PMUTEXCLIENT_DATA>(pData);
		if (!pMutexClientData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pMutexClientData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Sync::MutexClient MutexClient(pMutexClientData->m_szMutexName);
		std::atomic<bool>* const pResult = pMutexClientData->m_pResult;
		if (pResult) {
			pResult->store(MutexClient.UnLock(), std::memory_order_release);
		}
	}

	void OnSemaphoreThread(void* pData) {
		PSEMAPHORE_DATA pSemaphoreData = reinterpret_cast<PSEMAPHORE_DATA>(pData);
		if (!pSemaphoreData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pSemaphoreData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Sync::Semaphore* const pSemaphore = pSemaphoreData->m_pSemaphore;
		if (pSemaphore) {
			pSemaphore->Leave();
		}
	}

	void OnSemaphoreClientThread(void* pData) {
		PSEMAPHORECLIENT_DATA pSemaphoreClientData = reinterpret_cast<PSEMAPHORECLIENT_DATA>(pData);
		if (!pSemaphoreClientData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pSemaphoreClientData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Sync::SemaphoreClient SemaphoreClient(pSemaphoreClientData->m_szSemaphoreName);
		SemaphoreClient.Leave();
	}

	TEST_CASE("Event" * doctest::timeout(10)) {
		Detours::Sync::Event Event;

		EVENT_DATA EventData {};
		EventData.m_pEvent = &Event;
		EventData.m_unData = 0xDEEDBEEF;

		Detours::Parallel::Thread Thread(OnEventThread, &EventData);
		REQUIRE(Thread.Start() == true);

		CHECK(EventData.m_unData == 0xDEEDBEEF);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(EventData.m_unData == 0xBEEFDEED);
	}

	TEST_CASE("EventServer and EventClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::EventServer EventServer;

		EVENTCLIENT_DATA EventClientData {};
		EventClientData.m_pEvent = &Event;

		REQUIRE(EventServer.GetEventName(EventClientData.m_szEventName) == true);

		Detours::Parallel::Thread Thread(OnEventClientThread, &EventClientData);
		REQUIRE(Thread.Start() == true);

		CHECK(EventServer.Wait(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(EventServer.Wait(kThreadSynchronizationWaitMilliseconds) == true);
	}

	TEST_CASE("Mutex" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::Mutex Mutex;
		std::atomic<bool> bForeignUnlockResult = true;

		MUTEX_DATA MutexData {};
		MutexData.m_pEvent = &Event;
		MutexData.m_pMutex = &Mutex;
		MutexData.m_pResult = &bForeignUnlockResult;

		Detours::Parallel::Thread Thread(OnMutexThread, &MutexData);
		REQUIRE(Thread.Start() == true);

		CHECK(Mutex.Lock() == true);
		CHECK(Mutex.Lock(1000) == true);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(bForeignUnlockResult.load(std::memory_order_acquire) == false);
		CHECK(Mutex.Lock() == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == false);
	}

	TEST_CASE("MutexServer and MutexClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::MutexServer MutexServer;
		std::atomic<bool> bForeignUnlockResult = true;

		MUTEXCLIENT_DATA MutexClientData {};
		MutexClientData.m_pEvent = &Event;
		MutexClientData.m_pResult = &bForeignUnlockResult;

		REQUIRE(MutexServer.GetMutexName(MutexClientData.m_szMutexName) == true);

		Detours::Parallel::Thread Thread(OnMutexClientThread, &MutexClientData);
		REQUIRE(Thread.Start() == true);

		CHECK(MutexServer.Lock() == true);
		CHECK(MutexServer.Lock(1000) == true);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(bForeignUnlockResult.load(std::memory_order_acquire) == false);
		CHECK(MutexServer.Lock() == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == false);
	}

	TEST_CASE("Semaphore" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::Semaphore Semaphore;

		SEMAPHORE_DATA SemaphoreData {};
		SemaphoreData.m_pEvent = &Event;
		SemaphoreData.m_pSemaphore = &Semaphore;

		Detours::Parallel::Thread Thread(OnSemaphoreThread, &SemaphoreData);
		REQUIRE(Thread.Start() == true);

		CHECK(Semaphore.Enter(kThreadSynchronizationWaitMilliseconds) == true);
		CHECK(Semaphore.Enter(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(Semaphore.Enter(kThreadSynchronizationWaitMilliseconds) == true);
		CHECK(Semaphore.Leave() == true);
	}

	TEST_CASE("SemaphoreServer and SemaphoreClient" * doctest::timeout(10)) {
		Detours::Sync::Event Event;
		Detours::Sync::SemaphoreServer SemaphoreServer;

		SEMAPHORECLIENT_DATA SemaphoreClientData {};
		SemaphoreClientData.m_pEvent = &Event;

		REQUIRE(SemaphoreServer.GetSemaphoreName(SemaphoreClientData.m_szSemaphoreName) == true);

		Detours::Parallel::Thread Thread(OnSemaphoreClientThread, &SemaphoreClientData);
		REQUIRE(Thread.Start() == true);

		CHECK(SemaphoreServer.Enter(kThreadSynchronizationWaitMilliseconds) == true);
		CHECK(SemaphoreServer.Enter(1000) == false);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(SemaphoreServer.Enter(kThreadSynchronizationWaitMilliseconds) == true);
		CHECK(SemaphoreServer.Leave() == true);
	}

	TEST_CASE("Mutex initial ownership is recursive and thread-owned") {
		Detours::Sync::Mutex Mutex(true);
		REQUIRE(Mutex.GetMutex() != nullptr);
		std::atomic<bool> bForeignLockResult = true;
		std::thread ForeignThread([&Mutex, &bForeignLockResult]() {
			bool const bLocked = Mutex.Lock(0);
			bForeignLockResult.store(bLocked, std::memory_order_release);
			if (bLocked) {
				Mutex.UnLock();
			}
		});
		ForeignThread.join();

		CHECK(bForeignLockResult.load(std::memory_order_acquire) == false);
		CHECK(Mutex.Lock(0) == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == false);
	}

	TEST_CASE("Named mutex initial ownership is recursive and thread-owned") {
		Detours::Sync::MutexServer MutexServer(false, true);
		REQUIRE(MutexServer.GetMutex() != nullptr);
		TCHAR szMutexName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(MutexServer.GetMutexName(szMutexName) == true);
		std::atomic<bool> bClientOpened = false;
		std::atomic<bool> bForeignLockResult = true;
		std::thread ForeignThread([&szMutexName, &bClientOpened, &bForeignLockResult]() {
			Detours::Sync::MutexClient MutexClient(szMutexName);
			bClientOpened.store(MutexClient.GetMutex() != nullptr, std::memory_order_release);
			bool const bLocked = MutexClient.Lock(0);
			bForeignLockResult.store(bLocked, std::memory_order_release);
			if (bLocked) {
				MutexClient.UnLock();
			}
		});
		ForeignThread.join();

		CHECK(bClientOpened.load(std::memory_order_acquire) == true);
		CHECK(bForeignLockResult.load(std::memory_order_acquire) == false);
		CHECK(MutexServer.Lock(0) == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == false);
	}

	TEST_CASE("Mutex lock acquires abandoned ownership") {
		Detours::Sync::Mutex Mutex;
		REQUIRE(Mutex.GetMutex() != nullptr);
		std::atomic<bool> bOwnerLocked = false;
		std::thread OwnerThread([&Mutex, &bOwnerLocked]() {
			bOwnerLocked.store(Mutex.Lock(), std::memory_order_release);
		});
		OwnerThread.join();

		REQUIRE(bOwnerLocked.load(std::memory_order_acquire) == true);
		CHECK(Mutex.Lock(0) == true);
		CHECK(Mutex.UnLock() == true);
	}

	TEST_CASE("Named mutex lock acquires abandoned ownership") {
		Detours::Sync::MutexServer MutexServer;
		REQUIRE(MutexServer.GetMutex() != nullptr);
		TCHAR szMutexName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(MutexServer.GetMutexName(szMutexName) == true);
		std::atomic<bool> bOwnerOpened = false;
		std::atomic<bool> bOwnerLocked = false;
		std::thread OwnerThread([&szMutexName, &bOwnerOpened, &bOwnerLocked]() {
			Detours::Sync::MutexClient MutexClient(szMutexName);
			bOwnerOpened.store(MutexClient.GetMutex() != nullptr, std::memory_order_release);
			bOwnerLocked.store(MutexClient.Lock(), std::memory_order_release);
		});
		OwnerThread.join();

		REQUIRE(bOwnerOpened.load(std::memory_order_acquire) == true);
		REQUIRE(bOwnerLocked.load(std::memory_order_acquire) == true);
		CHECK(MutexServer.Lock(0) == true);
		CHECK(MutexServer.UnLock() == true);
	}

	TEST_CASE("Mutex serializes concurrent access on one handle") {
		MutexStressResult const Result = RunMutexStress();
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kMutexStressThreadCount * kMutexStressIterations));
	}

	TEST_CASE("Mutex move assignment releases recursive ownership") {
		Detours::Sync::Mutex OwnedMutex(true);
		REQUIRE(OwnedMutex.GetMutex() != nullptr);
		REQUIRE(OwnedMutex.Lock() == true);
		void* pReplacementMutex = nullptr;
		{
			Detours::Sync::Mutex ReplacementMutex;
			pReplacementMutex = ReplacementMutex.GetMutex();
			REQUIRE(pReplacementMutex != nullptr);
			OwnedMutex = std::move(ReplacementMutex);
		}

		CHECK(OwnedMutex.GetMutex() == pReplacementMutex);
		CHECK(OwnedMutex.Lock(0) == true);
		CHECK(OwnedMutex.UnLock() == true);

		TCHAR szOwnedName[Detours::kNamedObjectNameCapacity] {};
		Detours::Sync::MutexServer OwnedServer(false, true);
		REQUIRE(OwnedServer.GetMutex() != nullptr);
		REQUIRE(OwnedServer.GetMutexName(szOwnedName) == true);
		REQUIRE(OwnedServer.Lock() == true);
		void* pReplacementServer = nullptr;
		{
			Detours::Sync::MutexServer ReplacementServer;
			pReplacementServer = ReplacementServer.GetMutex();
			REQUIRE(pReplacementServer != nullptr);
			OwnedServer = std::move(ReplacementServer);
		}

		CHECK(OwnedServer.GetMutex() == pReplacementServer);
		CHECK(OwnedServer.Lock(0) == true);
		CHECK(OwnedServer.UnLock() == true);
		Detours::Sync::MutexClient RemovedClient(szOwnedName);
		CHECK(RemovedClient.GetMutex() == nullptr);
	}

	TEST_CASE("Semaphore enforces initial and maximum counts") {
		Detours::Sync::Semaphore NegativeInitial(-1, 1);
		Detours::Sync::Semaphore ExcessiveInitial(2, 1);
		Detours::Sync::Semaphore InvalidMaximum(0, 0);
		CHECK(NegativeInitial.GetSemaphore() == nullptr);
		CHECK(ExcessiveInitial.GetSemaphore() == nullptr);
		CHECK(InvalidMaximum.GetSemaphore() == nullptr);

		Detours::Sync::Semaphore Semaphore(1, 2);
		REQUIRE(Semaphore.GetSemaphore() != nullptr);
		CHECK(Semaphore.Leave(0) == false);
		CHECK(Semaphore.Leave(-1) == false);
		CHECK(Semaphore.Leave(2) == false);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == false);
		CHECK(Semaphore.Leave(2) == true);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == false);

		Detours::Sync::SemaphoreServer InvalidServer(false, 2, 1);
		CHECK(InvalidServer.GetSemaphore() == nullptr);
		Detours::Sync::SemaphoreServer SemaphoreServer(false, 1, 2);
		REQUIRE(SemaphoreServer.GetSemaphore() != nullptr);
		TCHAR szSemaphoreName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(SemaphoreServer.GetSemaphoreName(szSemaphoreName) == true);
		Detours::Sync::SemaphoreClient SemaphoreClient(szSemaphoreName);
		REQUIRE(SemaphoreClient.GetSemaphore() != nullptr);
		CHECK(SemaphoreClient.Leave(2) == false);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == false);
		CHECK(SemaphoreClient.Leave(2) == true);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == false);
	}

	TEST_CASE("Named clients reject an undersized non-NUL name before a guard page") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		constexpr std::size_t kInputCapacity = 1;
		constexpr std::size_t kNameSize = kInputCapacity * sizeof(TCHAR);
		REQUIRE(unPageSize >= kNameSize);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		unsigned char* const pAllocation = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!pAllocation) {
			FAIL("Failed to allocate guarded named-object test memory.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pAllocation]() {
			VirtualFree(pAllocation, 0, MEM_RELEASE);
		});

		TCHAR* const szName = reinterpret_cast<TCHAR*>(pAllocation + unPageSize - kNameSize);
		szName[0] = _T('A');
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pAllocation, unPageSize, PAGE_READONLY, &unOldProtection) != FALSE);
		REQUIRE(VirtualProtect(pAllocation + unPageSize, unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);

		Detours::Sync::EventClient EventClient(szName, kInputCapacity);
		Detours::Sync::MutexClient MutexClient(szName, kInputCapacity);
		Detours::Sync::SemaphoreClient SemaphoreClient(szName, kInputCapacity);
		Detours::Memory::SharedClient SharedClient(szName, kInputCapacity);
		Detours::Pipe::PipeClient PipeClient(1);
		CHECK(EventClient.GetEvent() == nullptr);
		CHECK(MutexClient.GetMutex() == nullptr);
		CHECK(SemaphoreClient.GetSemaphore() == nullptr);
		CHECK(SharedClient.GetShared() == nullptr);
		CHECK(PipeClient.Open(szName, kInputCapacity) == false);
		CHECK(szName[0] == _T('A'));
	}

	TEST_CASE("Suspender") {
		Detours::Sync::SuspendTransaction Transaction(Detours::Sync::g_Suspender);
		CHECK(static_cast<bool>(Transaction) == true);
	}

	TEST_CASE("SuspendTransaction rejects a second Begin") {
		Detours::Sync::Suspender Suspender;
		Detours::Sync::SuspendTransaction Transaction(Suspender, false);
		REQUIRE(Transaction.IsActive() == true);
		CHECK(Transaction.Begin(false) == false);
		CHECK(Transaction.IsActive() == true);
		REQUIRE(Transaction.End() == true);
		CHECK(Transaction.IsActive() == false);
	}


} // TEST_SUITE("Detours::Sync")

TEST_SUITE("Detours::Pipe") {
	constexpr DWORD kPipeClientOpenTimeoutMilliseconds = 2000;
	constexpr DWORD kPipeClientRetryMilliseconds = 10;
	constexpr std::size_t kPipeBufferSize = sizeof(DWORD);
	constexpr std::size_t kUndersizedPipeBufferSize = kPipeBufferSize - 1;

	typedef struct _PIPECLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		std::atomic<bool>* m_pBoundsResult;
		std::atomic<bool>* m_pOpenResult;
		std::atomic<bool>* m_pSendResult;
		HANDLE m_hServerThread;
		TCHAR m_szPipeName[Detours::kNamedObjectNameCapacity];
	} PIPECLIENT_DATA, *PPIPECLIENT_DATA;

	void OnPipeClientThread(void* pData) {
		PPIPECLIENT_DATA pPipeClientData = reinterpret_cast<PPIPECLIENT_DATA>(pData);
		if (!pPipeClientData || !pPipeClientData->m_pEvent || !pPipeClientData->m_pBoundsResult ||
			!pPipeClientData->m_pOpenResult || !pPipeClientData->m_pSendResult || !pPipeClientData->m_hServerThread) {
			return;
		}

		Detours::Pipe::PipeClient PipeClient(kPipeBufferSize);
		ULONGLONG const unOpenStart = GetTickCount64();
		while ((GetTickCount64() - unOpenStart) < kPipeClientOpenTimeoutMilliseconds) {
			if (!PipeClient.Open(pPipeClientData->m_szPipeName)) {
				Sleep(kPipeClientRetryMilliseconds);
				continue;
			}

			pPipeClientData->m_pOpenResult->store(true, std::memory_order_release);
			break;
		}

		if (!pPipeClientData->m_pOpenResult->load(std::memory_order_acquire)) {
			CancelSynchronousIo(pPipeClientData->m_hServerThread);
			return;
		}

		unsigned char arrCanary[kUndersizedPipeBufferSize] = { 0xA5, 0x5A, 0xC3 };
		unsigned char const arrOriginalCanary[kUndersizedPipeBufferSize] = { 0xA5, 0x5A, 0xC3 };
		bool const bReceiveRejected = !PipeClient.Receive(arrCanary);
		bool const bSendRejected = !PipeClient.Send(arrCanary);
		pPipeClientData->m_pBoundsResult->store(
			bReceiveRejected && bSendRejected &&
				(memcmp(arrCanary, arrOriginalCanary, sizeof(arrCanary)) == 0),
			std::memory_order_release);

		if (!pPipeClientData->m_pEvent->Wait(kPipeClientOpenTimeoutMilliseconds)) {
			return;
		}

		DWORD unData = 0xBEEFDEED;
		pPipeClientData->m_pSendResult->store(PipeClient.Send(reinterpret_cast<unsigned char const*>(&unData), sizeof(unData)), std::memory_order_release);
		PipeClient.Close();
	}

	TEST_CASE("Pipe lifecycle reports inactive state") {
		TCHAR szPipeName[Detours::kNamedObjectNameCapacity] {};
		Detours::Pipe::PipeServer InvalidServer(0);
		CHECK(InvalidServer.GetPipeName(szPipeName) == false);
		CHECK(InvalidServer.Close() == false);

		Detours::Pipe::PipeServer SourceServer(1);
		REQUIRE(SourceServer.GetPipeName(szPipeName) == true);
		Detours::Pipe::PipeServer MovedServer(std::move(SourceServer));
		CHECK(MovedServer.GetPipeName(szPipeName) == true);

		Detours::Pipe::PipeClient PipeClient(1);
		CHECK(PipeClient.Close() == false);
	}

	TEST_CASE("Pipe endpoints reject undersized buffers before I/O") {
		Detours::Sync::Event Event;
		Detours::Pipe::PipeServer PipeServer(kPipeBufferSize);
		std::atomic<bool> bPipeClientBounds = false;
		std::atomic<bool> bPipeClientOpened = false;
		std::atomic<bool> bPipeClientSent = false;
		HANDLE hServerThread = nullptr;
		REQUIRE(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &hServerThread, 0, FALSE, DUPLICATE_SAME_ACCESS) != FALSE);
		auto ServerThreadCleanup = MakeScopeExit([hServerThread]() {
			CloseHandle(hServerThread);
		});

		PIPECLIENT_DATA PipeClientData {};
		PipeClientData.m_pEvent = &Event;
		PipeClientData.m_pBoundsResult = &bPipeClientBounds;
		PipeClientData.m_pOpenResult = &bPipeClientOpened;
		PipeClientData.m_pSendResult = &bPipeClientSent;
		PipeClientData.m_hServerThread = hServerThread;

		REQUIRE(PipeServer.GetPipeName(PipeClientData.m_szPipeName) == true);

		Detours::Parallel::Thread Thread(OnPipeClientThread, &PipeClientData);
		REQUIRE(Thread.Start() == true);

		bool const bServerOpened = PipeServer.Open();
		unsigned char arrCanary[kUndersizedPipeBufferSize] = { 0x3C, 0xC3, 0x69 };
		unsigned char const arrOriginalCanary[kUndersizedPipeBufferSize] = { 0x3C, 0xC3, 0x69 };
		bool const bReceiveRejected = !PipeServer.Receive(arrCanary);
		bool const bSendRejected = !PipeServer.Send(arrCanary);
		bool const bEventSignaled = Event.Signal();
		bool const bThreadJoined = Thread.Join();
		REQUIRE(bServerOpened == true);
		REQUIRE(bEventSignaled == true);
		REQUIRE(bThreadJoined == true);
		REQUIRE(bReceiveRejected == true);
		REQUIRE(bSendRejected == true);
		REQUIRE(memcmp(arrCanary, arrOriginalCanary, sizeof(arrCanary)) == 0);
		REQUIRE(bPipeClientBounds.load(std::memory_order_acquire) == true);
		REQUIRE(bPipeClientOpened.load(std::memory_order_acquire) == true);
		REQUIRE(bPipeClientSent.load(std::memory_order_acquire) == true);

		DWORD unData = 0;
		CHECK(PipeServer.Receive(reinterpret_cast<unsigned char*>(&unData), sizeof(unData)) == true);
		CHECK(unData == 0xBEEFDEED);
	}
} // TEST_SUITE("Detours::Pipe")

static void WindowsThreadSuspendTestCallBack(void* pData) {
	PWINDOWS_THREAD_SUSPEND_TEST_DATA const pSuspendData = static_cast<PWINDOWS_THREAD_SUSPEND_TEST_DATA>(pData);
	if (!pSuspendData) {
		return;
	}

	pSuspendData->m_unThreadID.store(GetCurrentThreadId(), std::memory_order_release);
	pSuspendData->m_bReady.store(true, std::memory_order_release);
	while (!pSuspendData->m_bStop.load(std::memory_order_acquire)) {
		pSuspendData->m_unIterations.fetch_add(1, std::memory_order_relaxed);
		std::this_thread::yield();
	}
}

static void ResumeNativeThreadSuspensionsForCleanup(HANDLE hThread) noexcept {
	if (!hThread || (hThread == INVALID_HANDLE_VALUE)) {
		return;
	}

	for (std::size_t unIndex = 0; unIndex < kThreadSuspendCleanupLimit; ++unIndex) {
		DWORD const unPreviousSuspendCount = ResumeThread(hThread);
		if ((unPreviousSuspendCount == static_cast<DWORD>(-1)) || !unPreviousSuspendCount) {
			return;
		}
	}
}

TEST_SUITE("Detours::Parallel") {

	void OnThread(void* pData) {
		if (!pData) {
			return;
		}

		*reinterpret_cast<unsigned int*>(pData) = 0xBEEFDEED;
	}

	void OnFiber(void* pData) {
		if (!pData) {
			return;
		}

		*reinterpret_cast<unsigned int*>(pData) = 0xBEEFDEED;
	}

	TEST_CASE("Thread") {
		unsigned int unData = 0xDEEDBEEF;
		Detours::Parallel::Thread Thread(OnThread, &unData);
		CHECK(Thread.Start() == true);
		CHECK(Thread.Join() == true);
		CHECK(unData == 0xBEEFDEED);
	}

	TEST_CASE("Thread tracks only its own suspend depth") {
		WINDOWS_THREAD_SUSPEND_TEST_DATA SuspendData {};
		Detours::Parallel::Thread Thread(WindowsThreadSuspendTestCallBack, &SuspendData);
		HANDLE hNativeThread = nullptr;
		auto Cleanup = MakeScopeExit([&Thread, &SuspendData, &hNativeThread]() {
			SuspendData.m_bStop.store(true, std::memory_order_release);
			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
			Thread.Join();
			Thread.Join();
			if (hNativeThread && (hNativeThread != INVALID_HANDLE_VALUE)) {
				CloseHandle(hNativeThread);
				hNativeThread = nullptr;
			}
		});

		REQUIRE(Thread.Start() == true);
		REQUIRE(WaitForTestCondition(
			[&SuspendData]() {
				return SuspendData.m_bReady.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds));

		hNativeThread = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, SuspendData.m_unThreadID.load(std::memory_order_acquire));
		REQUIRE(hNativeThread != nullptr);
		REQUIRE(hNativeThread != INVALID_HANDLE_VALUE);
		CHECK(Thread.Resume() == false);
		REQUIRE(Thread.Suspend() == true);
		REQUIRE(Thread.Suspend() == true);

		DWORD const unPreviousExternalSuspendCount = SuspendThread(hNativeThread);
		REQUIRE(unPreviousExternalSuspendCount != static_cast<DWORD>(-1));
		CHECK(unPreviousExternalSuspendCount == 2);
		unsigned int const unSuspendedIterations = SuspendData.m_unIterations.load(std::memory_order_relaxed);
		Sleep(kThreadSuspendObservationMilliseconds);
		CHECK(SuspendData.m_unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);

		REQUIRE(Thread.Resume() == true);
		REQUIRE(Thread.Resume() == true);
		CHECK(Thread.Resume() == false);
		Sleep(kThreadSuspendObservationMilliseconds);
		CHECK(SuspendData.m_unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);

		CHECK(ResumeThread(hNativeThread) == 1);
		REQUIRE(WaitForTestCondition(
			[&SuspendData, unSuspendedIterations]() {
				return SuspendData.m_unIterations.load(std::memory_order_relaxed) > unSuspendedIterations;
			},
			kThreadSynchronizationWaitMilliseconds));

		SuspendData.m_bStop.store(true, std::memory_order_release);
		CHECK(Thread.Join() == true);
	}

	TEST_CASE("Thread Join clears stale owned depth after exit") {
		WINDOWS_THREAD_SUSPEND_TEST_DATA SuspendData {};
		Detours::Parallel::Thread Thread(WindowsThreadSuspendTestCallBack, &SuspendData);
		HANDLE hNativeThread = nullptr;
		auto Cleanup = MakeScopeExit([&Thread, &SuspendData, &hNativeThread]() {
			SuspendData.m_bStop.store(true, std::memory_order_release);
			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
			Thread.Join();
			Thread.Join();
			if (hNativeThread && (hNativeThread != INVALID_HANDLE_VALUE)) {
				CloseHandle(hNativeThread);
				hNativeThread = nullptr;
			}
		});

		REQUIRE(Thread.Start() == true);
		REQUIRE(WaitForTestCondition(
			[&SuspendData]() {
				return SuspendData.m_bReady.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds));
		hNativeThread = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, SuspendData.m_unThreadID.load(std::memory_order_acquire));
		REQUIRE(hNativeThread != nullptr);
		REQUIRE(hNativeThread != INVALID_HANDLE_VALUE);
		REQUIRE(Thread.Suspend() == true);
		REQUIRE(Thread.Suspend() == true);
		CHECK(ResumeThread(hNativeThread) == 2);
		CHECK(ResumeThread(hNativeThread) == 1);

		SuspendData.m_bStop.store(true, std::memory_order_release);
		REQUIRE(WaitForSingleObject(hNativeThread, kThreadSynchronizationWaitMilliseconds) == WAIT_OBJECT_0);
		CHECK(Thread.Join() == true);
	}

	TEST_CASE("Thread destructor drains repeated owned suspensions") {
		WINDOWS_THREAD_SUSPEND_TEST_DATA SuspendData {};
		std::atomic<bool> bSetupCompleted { false };
		std::atomic<bool> bSetupSucceeded { false };
		std::atomic<bool> bDestroyRequested { false };
		std::atomic<bool> bDestructorCompleted { false };
		HANDLE hNativeThread = nullptr;
		std::thread OwnerThread([&SuspendData, &bSetupCompleted, &bSetupSucceeded, &bDestroyRequested, &bDestructorCompleted]() {
			{
				Detours::Parallel::Thread Thread(WindowsThreadSuspendTestCallBack, &SuspendData);
				bool bSuccess = Thread.Start();
				if (bSuccess) {
					bSuccess = WaitForTestCondition(
						[&SuspendData]() {
							return SuspendData.m_bReady.load(std::memory_order_acquire);
						},
						kThreadSynchronizationWaitMilliseconds);
				}

				if (bSuccess) {
					bSuccess = Thread.Suspend();
				}

				if (bSuccess) {
					bSuccess = Thread.Suspend();
				}

				bSetupSucceeded.store(bSuccess, std::memory_order_release);
				bSetupCompleted.store(true, std::memory_order_release);
				while (!bDestroyRequested.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}

				SuspendData.m_bStop.store(true, std::memory_order_release);
			}

			bDestructorCompleted.store(true, std::memory_order_release);
		});
		auto Cleanup = MakeScopeExit([&SuspendData, &bDestroyRequested, &hNativeThread, &OwnerThread]() {
			bDestroyRequested.store(true, std::memory_order_release);
			SuspendData.m_bStop.store(true, std::memory_order_release);
			if (!hNativeThread || (hNativeThread == INVALID_HANDLE_VALUE)) {
				DWORD const unThreadID = SuspendData.m_unThreadID.load(std::memory_order_acquire);
				if (unThreadID) {
					hNativeThread = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, unThreadID);
				}
			}

			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
			if (OwnerThread.joinable()) {
				OwnerThread.join();
			}

			if (hNativeThread && (hNativeThread != INVALID_HANDLE_VALUE)) {
				CloseHandle(hNativeThread);
				hNativeThread = nullptr;
			}
		});

		bool const bSetupFinished = WaitForTestCondition(
			[&bSetupCompleted]() {
				return bSetupCompleted.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds);
		CHECK(bSetupFinished == true);
		CHECK(bSetupSucceeded.load(std::memory_order_acquire) == true);
		if (SuspendData.m_unThreadID.load(std::memory_order_acquire)) {
			hNativeThread = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, SuspendData.m_unThreadID.load(std::memory_order_acquire));
		}

		CHECK(hNativeThread != nullptr);
		CHECK(hNativeThread != INVALID_HANDLE_VALUE);

		bDestroyRequested.store(true, std::memory_order_release);
		bool const bCompletedWithoutCleanup = WaitForTestCondition(
			[&bDestructorCompleted]() {
				return bDestructorCompleted.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds);
		CHECK(bCompletedWithoutCleanup == true);
		if (!bCompletedWithoutCleanup) {
			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
		}

		OwnerThread.join();
		CHECK(bDestructorCompleted.load(std::memory_order_acquire) == true);
	}

	TEST_CASE("Thread Join drains repeated owned suspensions") {
		WINDOWS_THREAD_SUSPEND_TEST_DATA SuspendData {};
		Detours::Parallel::Thread Thread(WindowsThreadSuspendTestCallBack, &SuspendData);
		HANDLE hNativeThread = nullptr;
		std::thread JoinThread;
		auto Cleanup = MakeScopeExit([&Thread, &SuspendData, &hNativeThread, &JoinThread]() {
			SuspendData.m_bStop.store(true, std::memory_order_release);
			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
			if (JoinThread.joinable()) {
				JoinThread.join();
			}

			Thread.Join();
			Thread.Join();
			if (hNativeThread && (hNativeThread != INVALID_HANDLE_VALUE)) {
				CloseHandle(hNativeThread);
				hNativeThread = nullptr;
			}
		});

		REQUIRE(Thread.Start() == true);
		REQUIRE(WaitForTestCondition(
			[&SuspendData]() {
				return SuspendData.m_bReady.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds));
		hNativeThread = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, SuspendData.m_unThreadID.load(std::memory_order_acquire));
		REQUIRE(hNativeThread != nullptr);
		REQUIRE(hNativeThread != INVALID_HANDLE_VALUE);
		REQUIRE(Thread.Suspend() == true);
		REQUIRE(Thread.Suspend() == true);
		SuspendData.m_bStop.store(true, std::memory_order_release);

		std::atomic<bool> bJoinCompleted { false };
		std::atomic<bool> bJoinSucceeded { false };
		JoinThread = std::thread([&Thread, &bJoinCompleted, &bJoinSucceeded]() {
			bJoinSucceeded.store(Thread.Join(), std::memory_order_release);
			bJoinCompleted.store(true, std::memory_order_release);
		});
		bool const bCompletedWithoutCleanup = WaitForTestCondition(
			[&bJoinCompleted]() {
				return bJoinCompleted.load(std::memory_order_acquire);
			},
			kThreadSynchronizationWaitMilliseconds);
		CHECK(bCompletedWithoutCleanup == true);
		if (!bCompletedWithoutCleanup) {
			ResumeNativeThreadSuspensionsForCleanup(hNativeThread);
		}

		JoinThread.join();
		CHECK(bJoinSucceeded.load(std::memory_order_acquire) == true);
	}

	TEST_CASE("Fiber") {
		REQUIRE(IsThreadAFiber() == FALSE);
		unsigned int unData = 0xDEEDBEEF;
		Detours::Parallel::Fiber Fiber(OnFiber, &unData);
		CHECK(Fiber.Switch() == true);
		CHECK(unData == 0xBEEFDEED);
		CHECK(IsThreadAFiber() == FALSE);
	}

	TEST_CASE("Fiber preserves an existing fiber") {
		REQUIRE(IsThreadAFiber() == FALSE);
		void* const pMainFiber = ConvertThreadToFiber(nullptr);
		REQUIRE(pMainFiber != nullptr);
		auto FiberCleanup = MakeScopeExit([]() {
			if (IsThreadAFiber()) {
				ConvertFiberToThread();
			}
		});

		unsigned int unData = 0xDEEDBEEF;
		Detours::Parallel::Fiber Fiber(ParallelThrowingCallBack, &unData);
		bool bSwitchResult = true;
		CHECK_NOTHROW(bSwitchResult = Fiber.Switch());
		CHECK(bSwitchResult == false);
		CHECK(IsThreadAFiber() != FALSE);
		REQUIRE(Fiber.SetCallBack(OnFiber) == true);
		CHECK(Fiber.Switch() == true);
		CHECK(unData == 0xBEEFDEED);
		CHECK(IsThreadAFiber() != FALSE);
		bool const bConverted = ConvertFiberToThread() != FALSE;
		CHECK(bConverted == true);
		if (bConverted) {
			FiberCleanup.Release();
		}
	}
} // TEST_SUITE("Detours::Parallel")

TEST_SUITE("Detours::Memory") {
	constexpr std::size_t kProcessScannerChunkSize = 1024 * 1024;

	typedef struct _TEST_PROCESS_SCAN_RESULT {
		_TEST_PROCESS_SCAN_RESULT() noexcept;

		bool m_bCompleted;
		std::size_t m_unBytesScanned;
		std::size_t m_unReadFailures;
		std::vector<void*> m_vecMatches;
	} TEST_PROCESS_SCAN_RESULT, *PTEST_PROCESS_SCAN_RESULT;

	_TEST_PROCESS_SCAN_RESULT::_TEST_PROCESS_SCAN_RESULT() noexcept {
		m_bCompleted = false;
		m_unBytesScanned = 0;
		m_unReadFailures = 0;
	}

	typedef struct _SHAREDCLIENT_DATA {
		Detours::Sync::Event* m_pEvent;
		TCHAR m_szSharedName[Detours::kNamedObjectNameCapacity];
	} SHAREDCLIENT_DATA, *PSHAREDCLIENT_DATA;

	class TestProcessScanner {
	public:
		explicit TestProcessScanner(HANDLE hProcess = GetCurrentProcess()) noexcept;

	public:
		bool Find(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress = nullptr, std::size_t unRangeSize = 0) const;

	private:
		bool FindInternal(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress, std::size_t unRangeSize) const;

	private:
		HANDLE m_hProcess;
	};

	void CollectProcessScannerMatches(unsigned char const* pBuffer, std::size_t unBufferSize, unsigned char const* pData, std::size_t unDataSize, std::uintptr_t unBaseAddress, std::size_t unCandidateCount, std::vector<void*>& vecMatches) {
		if (!pBuffer || !pData || !unDataSize || (unBufferSize < unDataSize)) {
			return;
		}

		std::size_t const unAvailableCandidates = unBufferSize - unDataSize + 1;
		std::size_t const unCandidates = std::min(unCandidateCount, unAvailableCandidates);
		for (std::size_t unIndex = 0; unIndex < unCandidates; ++unIndex) {
			if (std::memcmp(pBuffer + unIndex, pData, unDataSize) == 0) {
				vecMatches.push_back(reinterpret_cast<void*>(unBaseAddress + static_cast<std::uintptr_t>(unIndex)));
			}
		}
	}

	static std::size_t CollectProcessScannerChunk(std::vector<unsigned char>& vecBuffer, std::size_t unCarrySize, std::size_t unBytesRead, unsigned char const* pData, std::size_t unDataSize, std::uintptr_t unReadAddress, std::vector<void*>& vecMatches) {
		if (!unBytesRead) {
			return unCarrySize;
		}

		std::size_t const unBufferSize = unCarrySize + unBytesRead;
		CollectProcessScannerMatches(vecBuffer.data(), unBufferSize, pData, unDataSize, unReadAddress - static_cast<std::uintptr_t>(unCarrySize), unBytesRead, vecMatches);

		std::size_t const unNewCarrySize = std::min(unDataSize - 1, unBufferSize);
		if (unNewCarrySize) {
			std::memmove(vecBuffer.data(), vecBuffer.data() + unBufferSize - unNewCarrySize, unNewCarrySize);
		}

		return unNewCarrySize;
	}

	bool IsProcessScannerProtectionReadable(DWORD unProtection) noexcept {
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

	TestProcessScanner::TestProcessScanner(HANDLE hProcess) noexcept :
		m_hProcess(hProcess)
	{
	}

	bool TestProcessScanner::Find(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress, std::size_t unRangeSize) const {
		if (!pResult) {
			return false;
		}

		*pResult = {};
		try {
			if (FindInternal(pData, unDataSize, pResult, pBeginAddress, unRangeSize)) {
				return true;
			}
		} catch (...) {
		}

		*pResult = {};
		return false;
	}

	bool TestProcessScanner::FindInternal(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress, std::size_t unRangeSize) const {
		std::vector<void*>& vecMatches = pResult->m_vecMatches;
		if (!pData || !unDataSize || (unDataSize > (std::numeric_limits<std::size_t>::max() - kProcessScannerChunkSize + 1)) || !m_hProcess) {
			return false;
		}

		std::vector<unsigned char> vecData(unDataSize);
		std::memcpy(vecData.data(), pData, unDataSize);
		std::vector<unsigned char> vecBuffer(kProcessScannerChunkSize + unDataSize - 1);

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		if (!unPageSize) {
			return false;
		}

		std::uintptr_t const unMinimumAddress = reinterpret_cast<std::uintptr_t>(SystemInfo.lpMinimumApplicationAddress);
		std::uintptr_t const unMaximumAddress = reinterpret_cast<std::uintptr_t>(SystemInfo.lpMaximumApplicationAddress);
		std::uintptr_t const unSystemEnd = (unMaximumAddress == std::numeric_limits<std::uintptr_t>::max()) ? std::numeric_limits<std::uintptr_t>::max() : unMaximumAddress + 1;
		std::uintptr_t const unBeginAddress = pBeginAddress ? reinterpret_cast<std::uintptr_t>(pBeginAddress) : unMinimumAddress;
		std::uintptr_t unEndAddress = unSystemEnd;
		if (unRangeSize) {
			unEndAddress = (unRangeSize > (std::numeric_limits<std::uintptr_t>::max() - unBeginAddress)) ? std::numeric_limits<std::uintptr_t>::max() : unBeginAddress + static_cast<std::uintptr_t>(unRangeSize);
		}

		if ((unBeginAddress >= unEndAddress) || (unEndAddress <= unMinimumAddress)) {
			return false;
		}

		std::size_t unCarrySize = 0;
		std::uintptr_t unNextAddress = std::max(unBeginAddress, unMinimumAddress);
		std::uintptr_t unCursor = std::max(unBeginAddress, unMinimumAddress);
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

			std::uintptr_t const unRegionBase = reinterpret_cast<std::uintptr_t>(MemoryInfo.BaseAddress);
			std::uintptr_t const unRegionEnd = (MemoryInfo.RegionSize > (std::numeric_limits<std::uintptr_t>::max() - unRegionBase)) ? std::numeric_limits<std::uintptr_t>::max() : unRegionBase + static_cast<std::uintptr_t>(MemoryInfo.RegionSize);
			std::uintptr_t const unScanBegin = std::max(unCursor, unRegionBase);
			std::uintptr_t const unScanEnd = std::min(unEndAddress, unRegionEnd);
			if ((MemoryInfo.State == MEM_COMMIT) && IsProcessScannerProtectionReadable(MemoryInfo.Protect) && (unScanBegin < unScanEnd)) {
				if (unScanBegin != unNextAddress) {
					unCarrySize = 0;
				}

				std::uintptr_t unChunkAddress = unScanBegin;
				while (unChunkAddress < unScanEnd) {
					std::size_t const unReadSize = std::min(kProcessScannerChunkSize, unScanEnd - unChunkAddress);
					SIZE_T unBytesRead = 0;
					bool const bRead = ReadProcessMemory(m_hProcess, reinterpret_cast<void*>(unChunkAddress), vecBuffer.data() + unCarrySize, unReadSize, &unBytesRead) != FALSE;
					std::size_t const unProgress = std::min(static_cast<std::size_t>(unBytesRead), unReadSize);
					pResult->m_unBytesScanned += unProgress;
					if (unProgress) {
						unCarrySize = CollectProcessScannerChunk(vecBuffer, unCarrySize, unProgress, vecData.data(), unDataSize, unChunkAddress, vecMatches);
					}

					if (!bRead || (unProgress != unReadSize)) {
						++pResult->m_unReadFailures;
					}

					if (unProgress) {
						unChunkAddress += unProgress;
						unNextAddress = unChunkAddress;
						continue;
					}

					unCarrySize = 0;
					const std::uintptr_t unPageRemainder = static_cast<std::uintptr_t>(unPageSize) - (unChunkAddress % static_cast<std::uintptr_t>(unPageSize));
					unChunkAddress += std::min(unPageRemainder, unScanEnd - unChunkAddress);
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

	bool FreeScannerTestMemory(void* pAddress) noexcept {
		if (!pAddress) {
			return false;
		}

		return VirtualFree(pAddress, 0, MEM_RELEASE) != FALSE;
	}

	bool CollectNoAccessTestMemoryRanges(std::vector<TestMemoryRange>* pRanges) {
		if (!pRanges) {
			return false;
		}

		pRanges->clear();
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::uintptr_t unCurrentAddress = reinterpret_cast<std::uintptr_t>(SystemInfo.lpMinimumApplicationAddress);
		std::uintptr_t const unMaximumAddress = reinterpret_cast<std::uintptr_t>(SystemInfo.lpMaximumApplicationAddress);
		try {
			while (unCurrentAddress <= unMaximumAddress) {
				MEMORY_BASIC_INFORMATION MemoryInfo {};
				if (VirtualQuery(reinterpret_cast<void*>(unCurrentAddress), &MemoryInfo, sizeof(MemoryInfo)) != sizeof(MemoryInfo)) {
					pRanges->clear();
					return false;
				}

				std::uintptr_t const unRegionAddress = reinterpret_cast<std::uintptr_t>(MemoryInfo.BaseAddress);
				if (!MemoryInfo.RegionSize || (MemoryInfo.RegionSize > (std::numeric_limits<std::uintptr_t>::max() - unRegionAddress))) {
					pRanges->clear();
					return false;
				}

				std::uintptr_t const unRegionEnd = unRegionAddress + static_cast<std::uintptr_t>(MemoryInfo.RegionSize);
				if (unRegionEnd <= unCurrentAddress) {
					pRanges->clear();
					return false;
				}

				if ((MemoryInfo.State == MEM_COMMIT) && ((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS)) {
					pRanges->push_back({ unRegionAddress, unRegionEnd });
				}

				unCurrentAddress = unRegionEnd;
			}
		} catch (...) {
			pRanges->clear();
			return false;
		}

		return true;
	}

	bool CopyProtectedTestMemory(void* pAddress, std::size_t unSize, std::vector<unsigned char>* pData) {
		if (!pAddress || !unSize || !pData) {
			return false;
		}

		DWORD unOldProtection = 0;
		if (!VirtualProtect(pAddress, unSize, PAGE_READONLY, &unOldProtection)) {
			return false;
		}

		auto ProtectionCleanup = MakeScopeExit([pAddress, unSize, unOldProtection]() {
			DWORD unTemporaryProtection = 0;
			VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection);
		});

		pData->resize(unSize);
		std::memcpy(pData->data(), pAddress, unSize);
		DWORD unTemporaryProtection = 0;
		bool const bRestored = VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection) != FALSE;
		if (bRestored) {
			ProtectionCleanup.Release();
		}

		return bRestored;
	}

	bool TamperProtectedTestMemory(void* pAddress, std::size_t unSize) {
		if (!pAddress || !unSize) {
			return false;
		}

		DWORD unOldProtection = 0;
		if (!VirtualProtect(pAddress, unSize, PAGE_EXECUTE_READWRITE, &unOldProtection)) {
			return false;
		}

		auto ProtectionCleanup = MakeScopeExit([pAddress, unSize, unOldProtection]() {
			DWORD unTemporaryProtection = 0;
			VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection);
		});

		unsigned char* const pData = static_cast<unsigned char*>(pAddress);
		pData[0] = static_cast<unsigned char>(pData[0] ^ 1);
		DWORD unTemporaryProtection = 0;
		bool const bRestored = VirtualProtect(pAddress, unSize, unOldProtection, &unTemporaryProtection) != FALSE;
		if (bRestored) {
			ProtectionCleanup.Release();
		}

		return bRestored;
	}

	using fnProtectedPolicyCode = bool(__cdecl*)();

	__declspec(noinline) bool TryReadProtectedPolicyMemory(volatile unsigned char const* const pAddress, unsigned char* const pValue) noexcept {
		if (!pAddress || !pValue) {
			return false;
		}

		__try {
			*pValue = *pAddress;
			return true;
		} __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			return false;
		}
	}

	__declspec(noinline) bool TryWriteProtectedPolicyMemory(volatile unsigned char* const pAddress, unsigned char const unValue) noexcept {
		if (!pAddress) {
			return false;
		}

		__try {
			*pAddress = unValue;
			return true;
		} __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			return false;
		}
	}

	__declspec(noinline) bool TryExecuteProtectedPolicyMemory(void* const pAddress, bool* const pResult) noexcept {
		if (!pAddress || !pResult) {
			return false;
		}

		__try {
			*pResult = reinterpret_cast<fnProtectedPolicyCode>(pAddress)();
			return true;
		} __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			return false;
		}
	}

	static decltype(&SetProcessValidCallTargets) ResolveSetProcessValidCallTargets() noexcept {
		HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
		if (!hModule) {
			return nullptr;
		}

		FARPROC pFunction = GetProcAddress(hModule, "SetProcessValidCallTargets");
		if (!pFunction) {
			hModule = GetModuleHandleW(L"KernelBase.dll");
			pFunction = hModule ? GetProcAddress(hModule, "SetProcessValidCallTargets") : nullptr;
		}

		return reinterpret_cast<decltype(&SetProcessValidCallTargets)>(pFunction);
	}

	static bool CreateSelectiveControlFlowGuardPage(void** const pPageAddress, std::size_t* const pPageSize) {
		if (!pPageAddress || !pPageSize) {
			return false;
		}

		*pPageAddress = nullptr;
		*pPageSize = 0;

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		constexpr unsigned char kCode[] = { 0xB0, 0x01, 0xC3 };
		if (!unPageSize || ((kControlFlowGuardInvalidTargetOffset + sizeof(kCode)) > unPageSize)) {
			return false;
		}

		void* const pAddress = VirtualAlloc(nullptr, unPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ | PAGE_TARGETS_INVALID);
		if (!pAddress) {
			return false;
		}

		auto PageCleanup = MakeScopeExit([pAddress]() {
			VirtualFree(pAddress, 0, MEM_RELEASE);
		});

		DWORD unOldProtection = 0;
		if (!VirtualProtect(pAddress, unPageSize, PAGE_READWRITE, &unOldProtection)) {
			return false;
		}

		unsigned char* const pCode = static_cast<unsigned char*>(pAddress);
		std::memcpy(pCode, kCode, sizeof(kCode));
		std::memcpy(pCode + kControlFlowGuardInvalidTargetOffset, kCode, sizeof(kCode));
		if (!VirtualProtect(pAddress, unPageSize, PAGE_EXECUTE_READ | PAGE_TARGETS_NO_UPDATE, &unOldProtection) ||
			!FlushInstructionCache(GetCurrentProcess(), pAddress, unPageSize)) {
			return false;
		}

		CFG_CALL_TARGET_INFO CallTargetInfo {};
		CallTargetInfo.Offset = 0;
		CallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
		decltype(&SetProcessValidCallTargets) const pSetProcessValidCallTargets = ResolveSetProcessValidCallTargets();
		if (!pSetProcessValidCallTargets || !pSetProcessValidCallTargets(GetCurrentProcess(), pAddress, unPageSize, 1, &CallTargetInfo)) {
			return false;
		}

		*pPageAddress = pAddress;
		*pPageSize = unPageSize;
		PageCleanup.Release();
		return true;
	}

	static void RunExternalControlFlowGuardScenario(bool const bReleaseBeforeInvalidTarget) {
		void* pPageAddress = nullptr;
		std::size_t unPageSize = 0;
		REQUIRE(CreateSelectiveControlFlowGuardPage(&pPageAddress, &unPageSize) == true);
		auto PageCleanup = MakeScopeExit([pPageAddress]() {
			VirtualFree(pPageAddress, 0, MEM_RELEASE);
		});

		Detours::Memory::SecurePage SecurePage(pPageAddress, unPageSize);
		REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
		Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
		REQUIRE(ProtectedPage.GetPageAddress() == pPageAddress);

		DWORD unProtection = PAGE_NOACCESS;
		REQUIRE(SecurePage.GetProtection(&unProtection) == true);
		CHECK(unProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(ProtectedPage.SetProtection(PAGE_EXECUTE_READ) == true);
		REQUIRE(SecurePage.GetProtection(&unProtection) == true);
		CHECK(unProtection == PAGE_EXECUTE_READ);

		bool bCodeResult = false;
		REQUIRE(TryExecuteProtectedPolicyMemory(pPageAddress, &bCodeResult) == true);
		CHECK(bCodeResult == true);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pPageAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		if (bReleaseBeforeInvalidTarget) {
			REQUIRE(ProtectedPage.Release() == true);
			REQUIRE(SecurePage.Release() == true);
			REQUIRE(VirtualQuery(pPageAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
			CHECK((MemoryInfo.Protect & 0xFF) == PAGE_EXECUTE_READ);

			bCodeResult = false;
			REQUIRE(TryExecuteProtectedPolicyMemory(pPageAddress, &bCodeResult) == true);
			CHECK(bCodeResult == true);
		}

		void* const pInvalidTarget =
			static_cast<unsigned char*>(pPageAddress) + kControlFlowGuardInvalidTargetOffset;
		bCodeResult = false;
		if (TryExecuteProtectedPolicyMemory(pInvalidTarget, &bCodeResult)) {
			FAIL("The invalid CFG call target executed successfully.");
			return;
		}

		FAIL("The invalid CFG call target returned without terminating the child process.");
	}

	void OnSharedClientThread(void* pData) {
		PSHAREDCLIENT_DATA pSharedClientData = reinterpret_cast<PSHAREDCLIENT_DATA>(pData);
		if (!pSharedClientData) {
			return;
		}

		Detours::Sync::Event* const pEvent = pSharedClientData->m_pEvent;
		if (!pEvent || !pEvent->Wait(kThreadSynchronizationWaitMilliseconds)) {
			return;
		}

		Detours::Memory::SharedClient SharedClient(pSharedClientData->m_szSharedName);
		void* const pAddress = SharedClient.GetAddress();
		if (!pAddress) {
			return;
		}

		*reinterpret_cast<unsigned int*>(pAddress) = 0xBEEFDEED;
	}

	TEST_CASE("Shared") {
		Detours::Memory::Shared Shared(4);
		REQUIRE(Shared.GetAddress() != nullptr);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(Shared.GetAddress(), &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READWRITE);
	}

	TEST_CASE("SharedServer") {
		Detours::Sync::Event Event;
		Detours::Memory::SharedServer SharedServer(4);

		SHAREDCLIENT_DATA SharedClientData {};
		SharedClientData.m_pEvent = &Event;

		REQUIRE(SharedServer.GetAddress() != nullptr);
		REQUIRE(SharedServer.GetSharedName(SharedClientData.m_szSharedName) == true);
		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(SharedServer.GetAddress(), &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READWRITE);

		Detours::Parallel::Thread Thread(OnSharedClientThread, &SharedClientData);
		REQUIRE(Thread.Start() == true);

		unsigned int* pData = reinterpret_cast<unsigned int*>(SharedServer.GetAddress());
		*pData = 0;
		CHECK(*pData == 0);
		CHECK(Event.Signal() == true);
		CHECK(Thread.Join() == true);
		CHECK(*pData == 0xBEEFDEED);
	}

	TEST_CASE("Page") {
		Detours::Memory::Page Page;
		CHECK(Page.GetProtection(nullptr) == false);
		CHECK(Page.GetOriginalProtection(nullptr) == false);
		CHECK(Page.Alloc(std::numeric_limits<std::size_t>::max(), 2) == nullptr);
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
		constexpr std::size_t kMaximumRelativeJumpDistance = 0x7FFFFFFB;

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		REQUIRE(hKernel32 != INVALID_HANDLE_VALUE);

#pragma warning(suppress: 6387) // doctest REQUIRE is not modeled by code analysis.
		void* const pDesiredAddress = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pDesiredAddress != nullptr);

		auto IsWithinRelativeDistance = [kMaximumRelativeJumpDistance](void const* const pFirstAddress, void const* const pSecondAddress) -> bool {
			std::uintptr_t const unFirstAddress = reinterpret_cast<std::uintptr_t>(pFirstAddress);
			std::uintptr_t const unSecondAddress = reinterpret_cast<std::uintptr_t>(pSecondAddress);
			std::uintptr_t const unDistance = (unFirstAddress > unSecondAddress) ? (unFirstAddress - unSecondAddress) : (unSecondAddress - unFirstAddress);
			return unDistance <= kMaximumRelativeJumpDistance;
		};

		{
			Detours::Memory::Page NearPage(pDesiredAddress);
			void* const pPageAddress = NearPage.GetPageAddress();
			REQUIRE(pPageAddress != nullptr);
			CHECK((reinterpret_cast<std::uintptr_t>(pPageAddress) % SystemInfo.dwAllocationGranularity) == 0);
			CHECK(IsWithinRelativeDistance(pDesiredAddress, pPageAddress));
		}

		{
			std::size_t const unRegionCapacity = static_cast<std::size_t>(SystemInfo.dwPageSize) * 2;
			Detours::Memory::Region NearRegion(pDesiredAddress, unRegionCapacity);
			void* const pRegionAddress = NearRegion.GetRegionAddress();
			REQUIRE(pRegionAddress != nullptr);
			CHECK(NearRegion.GetRegionCapacity() == unRegionCapacity);
			CHECK((reinterpret_cast<std::uintptr_t>(pRegionAddress) % SystemInfo.dwAllocationGranularity) == 0);
			CHECK(IsWithinRelativeDistance(pDesiredAddress, pRegionAddress));
		}
	}

	TEST_CASE("Region") {
		Detours::Memory::Region Region;
		CHECK(Region.GetProtection(nullptr) == false);
		CHECK(Region.GetOriginalProtection(nullptr) == false);
		CHECK(Region.Alloc(std::numeric_limits<std::size_t>::max(), 2) == nullptr);
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

	TEST_CASE("Region spanning deallocation preflights every page") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		Detours::Memory::Region Region(nullptr, unPageSize * 2);
		void* const pSuccessfulAllocation = Region.Alloc(unPageSize + 1);
		REQUIRE(pSuccessfulAllocation != nullptr);
		CHECK(Region.GetDataSize() == (unPageSize + 1));
		CHECK(Region.DeAlloc(static_cast<unsigned char*>(pSuccessfulAllocation) + unPageSize) == false);
		CHECK(Region.GetDataSize() == (unPageSize + 1));
		CHECK(Region.DeAlloc(pSuccessfulAllocation) == true);
		CHECK(Region.IsRegionEmpty() == true);

		Detours::Memory::Storage Storage(unPageSize * 2, unPageSize * 2);
		void* const pStorageAllocation = Storage.Alloc(unPageSize + 1);
		REQUIRE(pStorageAllocation != nullptr);
		CHECK(Storage.GetDataSize() == (unPageSize + 1));
		CHECK(Storage.DeAlloc(static_cast<unsigned char*>(pStorageAllocation) + unPageSize) == false);
		CHECK(Storage.GetDataSize() == (unPageSize + 1));
		CHECK(Storage.DeAlloc(pStorageAllocation) == true);
		CHECK(Storage.IsStorageEmpty() == true);

		Detours::Memory::Page* pFirstPage = nullptr;
		void* const pAllocation = Region.Alloc(unPageSize + 1, 1, 1, &pFirstPage);
		REQUIRE(pAllocation != nullptr);
		REQUIRE(pFirstPage != nullptr);
		REQUIRE(pFirstPage->DeAlloc(pAllocation) == true);
		REQUIRE(Region.GetDataSize() == 1);
		CHECK(Region.DeAlloc(pAllocation) == false);
		CHECK(Region.GetDataSize() == 1);
		Region.DeAllocAll();
		CHECK(Region.IsRegionEmpty() == true);
	}

	TEST_CASE("Storage") {
		constexpr unsigned char kStoredCode[] = { 0xB0, 0x01, 0xC3 };
		Detours::Memory::Storage Storage;
		CHECK(Storage.DeAllocAll() == true);
		unsigned char* pCodeMemory = reinterpret_cast<unsigned char*>(Storage.Alloc(sizeof(kStoredCode)));
		REQUIRE(pCodeMemory != nullptr);
		Detours::Memory::Protection CodeMemoryProtection(pCodeMemory, sizeof(kStoredCode), false);
		REQUIRE(CodeMemoryProtection.Change(PAGE_READWRITE) == true);
		std::memcpy(pCodeMemory, kStoredCode, sizeof(kStoredCode));
		REQUIRE(CodeMemoryProtection.Change(PAGE_EXECUTE_READ) == true);
		REQUIRE(FlushInstructionCache(GetCurrentProcess(), pCodeMemory, sizeof(kStoredCode)) != FALSE);
		using fnStoredCode = bool(__cdecl*)();
		CHECK(reinterpret_cast<fnStoredCode>(pCodeMemory)() == true);
		CHECK(Storage.DeAlloc(pCodeMemory) == true);
		CHECK(Storage.DeAllocAll() == true);
	}

	TEST_CASE("Storage validates the actual aligned allocation against the desired address") {
		static constexpr std::size_t kMaximumRelativeJumpDistance = 0x7FFFFFFB;
		constexpr std::size_t kFarDistance = 0x80010000;
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage Storage(unPageSize * 4, unPageSize);
		Detours::Memory::Region* pFirstRegion = nullptr;
		void* const pFirst = Storage.Alloc(1, 1, 1, nullptr, nullptr, &pFirstRegion);
		REQUIRE(pFirst != nullptr);
		REQUIRE(pFirstRegion != nullptr);
		void* const pDesiredAddress = pFirstRegion->GetRegionAddress();
		REQUIRE(pDesiredAddress != nullptr);

		void* const pAligned = Storage.Alloc(17, 32, 64, pDesiredAddress);
		REQUIRE(pAligned != nullptr);
		std::uintptr_t const unDesiredAddress = reinterpret_cast<std::uintptr_t>(pDesiredAddress);
		std::uintptr_t const unAlignedAddress = reinterpret_cast<std::uintptr_t>(pAligned);
		std::uintptr_t const unAlignedEnd = unAlignedAddress + 31;
		CHECK(((unAlignedAddress > unDesiredAddress) ? (unAlignedAddress - unDesiredAddress) : (unDesiredAddress - unAlignedAddress)) <= kMaximumRelativeJumpDistance);
		CHECK(((unAlignedEnd > unDesiredAddress) ? (unAlignedEnd - unDesiredAddress) : (unDesiredAddress - unAlignedEnd)) <= kMaximumRelativeJumpDistance);

		std::uintptr_t const unFarAddress = (unDesiredAddress <= (std::numeric_limits<std::uintptr_t>::max() - kFarDistance)) ? (unDesiredAddress + kFarDistance) : (unDesiredAddress - kFarDistance);
		Detours::Memory::Region* pFarRegion = nullptr;
		void* const pFar = Storage.Alloc(1, 1, 1, reinterpret_cast<void*>(unFarAddress), nullptr, &pFarRegion);
		if (pFar) {
			REQUIRE(pFarRegion != nullptr);
			CHECK(pFarRegion != pFirstRegion);
			std::uintptr_t const unFarAllocationAddress = reinterpret_cast<std::uintptr_t>(pFar);
			CHECK(((unFarAllocationAddress > unFarAddress) ? (unFarAllocationAddress - unFarAddress) : (unFarAddress - unFarAllocationAddress)) <= kMaximumRelativeJumpDistance);
		}

		CHECK(Storage.DeAllocAll() == true);
	}

	TEST_CASE("Storage sizes a new region from the aligned allocation") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize > 8);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		Detours::Memory::Storage Storage(unPageSize * 2, unPageSize);
		void* const pAllocation = Storage.Alloc(unPageSize - 6, unPageSize * 2, 1);
		REQUIRE(pAllocation != nullptr);
		CHECK(Storage.GetDataSize() == (unPageSize * 2));
		CHECK(Storage.DeAlloc(pAllocation) == true);
	}

	TEST_CASE("Allocators reject non-power-of-two alignment without changing state") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);

		Detours::Memory::Page Page;
		REQUIRE(Page.GetPageAddress() != nullptr);
		CHECK(Page.GetProtection(nullptr) == false);
		CHECK(Page.GetOriginalProtection(nullptr) == false);
		CHECK(Page.Alloc(1, 3, 1) == nullptr);
		CHECK(Page.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(Page.GetDataSize() == 0);
		CHECK(Page.IsPageEmpty() == true);
		void* const pPageAllocation = Page.Alloc(Page.GetPageCapacity(), 1, 1);
		REQUIRE(pPageAllocation != nullptr);
		CHECK(Page.DeAlloc(pPageAllocation) == true);

		Detours::Memory::Region Region(nullptr, unPageSize);
		REQUIRE(Region.GetRegionAddress() != nullptr);
		Detours::Memory::Page* pRegionUsedPage = nullptr;
		CHECK(Region.Alloc(1, 3, 1, &pRegionUsedPage) == nullptr);
		CHECK(pRegionUsedPage == nullptr);
		CHECK(Region.ZeroAlloc(1, 1, 3, &pRegionUsedPage) == nullptr);
		CHECK(pRegionUsedPage == nullptr);
		CHECK(Region.GetDataSize() == 0);
		CHECK(Region.IsRegionEmpty() == true);
		void* const pRegionAllocation = Region.Alloc(Region.GetRegionCapacity(), 1, 1);
		REQUIRE(pRegionAllocation != nullptr);
		CHECK(Region.DeAlloc(pRegionAllocation) == true);

		Detours::Memory::Storage Storage(unPageSize, unPageSize);
		Detours::Memory::Page* pStorageUsedPage = nullptr;
		Detours::Memory::Region* pStorageUsedRegion = nullptr;
		CHECK(Storage.Alloc(1, 3, 1, nullptr, &pStorageUsedPage, &pStorageUsedRegion) == nullptr);
		CHECK(pStorageUsedPage == nullptr);
		CHECK(pStorageUsedRegion == nullptr);
		CHECK(Storage.ZeroAlloc(1, 1, 3, nullptr, &pStorageUsedPage, &pStorageUsedRegion) == nullptr);
		CHECK(pStorageUsedPage == nullptr);
		CHECK(pStorageUsedRegion == nullptr);
		CHECK(Storage.GetDataSize() == 0);
		CHECK(Storage.IsStorageEmpty() == true);
		void* const pStorageAllocation = Storage.Alloc(Storage.GetStorageCapacity(), 1, 1);
		REQUIRE(pStorageAllocation != nullptr);
		CHECK(Storage.DeAlloc(pStorageAllocation) == true);

		Detours::Memory::ProtectedPage ProtectedPage;
		REQUIRE(ProtectedPage.GetPageAddress() != nullptr);
		CHECK(ProtectedPage.Alloc(1, 3, 1) == nullptr);
		CHECK(ProtectedPage.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(ProtectedPage.GetDataSize() == 0);
		CHECK(ProtectedPage.IsPageEmpty() == true);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);
		void* const pProtectedPageAllocation = ProtectedPage.Alloc(ProtectedPage.GetPageCapacity(), 1, 1);
		REQUIRE(pProtectedPageAllocation != nullptr);
		CHECK(ProtectedPage.DeAlloc(pProtectedPageAllocation) == true);

		Detours::Memory::ProtectedRange ProtectedRange(unPageSize);
		REQUIRE(ProtectedRange.GetRangeAddress() != nullptr);
		CHECK(ProtectedRange.Alloc(1, 3, 1) == nullptr);
		CHECK(ProtectedRange.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(ProtectedRange.GetDataSize() == 0);
		CHECK(ProtectedRange.IsRangeEmpty() == true);
		CHECK(ProtectedRange.IsProtected() == true);
		CHECK(ProtectedRange.IsCompromised() == false);
		void* const pProtectedRangeAllocation = ProtectedRange.Alloc(ProtectedRange.GetRangeSize(), 1, 1);
		REQUIRE(pProtectedRangeAllocation != nullptr);
		CHECK(ProtectedRange.DeAlloc(pProtectedRangeAllocation) == true);

		Detours::Memory::SecurePage SecurePage;
		REQUIRE(SecurePage.GetPageAddress() != nullptr);
		CHECK(SecurePage.Alloc(1, 3, 1) == nullptr);
		CHECK(SecurePage.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(SecurePage.GetDataSize() == 0);
		CHECK(SecurePage.IsPageEmpty() == true);
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);
		void* const pSecurePageAllocation = SecurePage.Alloc(SecurePage.GetPageCapacity(), 1, 1);
		REQUIRE(pSecurePageAllocation != nullptr);
		CHECK(SecurePage.DeAlloc(pSecurePageAllocation) == true);

		Detours::Memory::SecureRange SecureRange(unPageSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		CHECK(SecureRange.Alloc(1, 3, 1) == nullptr);
		CHECK(SecureRange.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(SecureRange.GetDataSize() == 0);
		CHECK(SecureRange.IsRangeEmpty() == true);
		CHECK(SecureRange.IsSecured() == true);
		CHECK(SecureRange.IsCompromised() == false);
		void* const pSecureRangeAllocation = SecureRange.Alloc(SecureRange.GetRangeSize(), 1, 1);
		REQUIRE(pSecureRangeAllocation != nullptr);
		CHECK(SecureRange.DeAlloc(pSecureRangeAllocation) == true);
	}

	TEST_CASE("Invalid Storage capacities are inert and rejected by MemoryManager") {
		constexpr std::size_t kMaximumSize = std::numeric_limits<std::size_t>::max();
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage InvalidTotalStorage(kMaximumSize, unPageSize);
		CHECK(InvalidTotalStorage.GetStorageCapacity() == 0);
		CHECK(InvalidTotalStorage.GetDataSize() == 0);
		CHECK(InvalidTotalStorage.IsStorageEmpty() == true);
		CHECK(InvalidTotalStorage.Alloc(1) == nullptr);
		CHECK(InvalidTotalStorage.ZeroAlloc(1) == nullptr);

		Detours::Memory::Storage InvalidRegionStorage(unPageSize, kMaximumSize);
		CHECK(InvalidRegionStorage.GetStorageCapacity() == 0);
		CHECK(InvalidRegionStorage.GetDataSize() == 0);
		CHECK(InvalidRegionStorage.IsStorageEmpty() == true);
		CHECK(InvalidRegionStorage.Alloc(1) == nullptr);

		Detours::Memory::Storage InvalidStorage(kMaximumSize, kMaximumSize);
		CHECK(InvalidStorage.GetStorageCapacity() == 0);
		CHECK(InvalidStorage.GetDataSize() == 0);
		CHECK(InvalidStorage.IsStorageEmpty() == true);
		CHECK(InvalidStorage.Alloc(1) == nullptr);

		Detours::Memory::MemoryManager Manager;
		CHECK(Manager.CreateStorage(kMaximumSize, unPageSize) == nullptr);
		CHECK(Manager.CreateStorage(unPageSize, kMaximumSize) == nullptr);
		CHECK(Manager.CreateStorage(kMaximumSize, kMaximumSize) == nullptr);
		Detours::Memory::Storage* const pValidStorage = Manager.CreateStorage(unPageSize, unPageSize);
		REQUIRE(pValidStorage != nullptr);
		CHECK(Manager.DestroyStorage(pValidStorage) == true);
	}

	TEST_CASE("MemoryManager rejects reserved and free address space") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);

		void* const pAddress = VirtualAlloc(nullptr, unPageSize, MEM_RESERVE, PAGE_NOACCESS);
		REQUIRE(pAddress != nullptr);
		if (!pAddress) {
			return;
		}

		auto ReservationCleanup = MakeScopeExit([pAddress]() {
			VirtualFree(pAddress, 0, MEM_RELEASE);
		});

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		REQUIRE(MemoryInfo.State == MEM_RESERVE);

		Detours::Memory::MemoryManager Manager;
		CHECK(Manager.GetPage(pAddress) == nullptr);
		CHECK(Manager.GetRegion(pAddress) == nullptr);
		Detours::Memory::Page ReservedPage(pAddress, false, false);
		CHECK(ReservedPage.GetPageAddress() == nullptr);
		Detours::Memory::Region ReservedRegion(pAddress, false);
		CHECK(ReservedRegion.GetRegionAddress() == nullptr);
		Detours::Memory::Protection ReservedProtection(pAddress, unPageSize, false);
		CHECK(ReservedProtection.Change(PAGE_READWRITE) == false);
		CHECK(ReservedProtection.Restore() == false);

		std::uintptr_t const unReleasedAddress = reinterpret_cast<std::uintptr_t>(pAddress);
		bool const bReleased = VirtualFree(pAddress, 0, MEM_RELEASE) != FALSE;
		REQUIRE(bReleased == true);
		ReservationCleanup.Release();
		void* const pFreeAddress = reinterpret_cast<void*>(unReleasedAddress);

		MemoryInfo = {};
#pragma warning(suppress: 6001) // The address value is queried after the allocation is intentionally released.
		REQUIRE(VirtualQuery(pFreeAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		REQUIRE(MemoryInfo.State == MEM_FREE);
		CHECK(Manager.GetPage(pFreeAddress) == nullptr);
		CHECK(Manager.GetRegion(pFreeAddress) == nullptr);
		Detours::Memory::Page FreePage(pFreeAddress, false, false);
		CHECK(FreePage.GetPageAddress() == nullptr);
		Detours::Memory::Region FreeRegion(pFreeAddress, false);
		CHECK(FreeRegion.GetRegionAddress() == nullptr);
		Detours::Memory::Protection FreeProtection(pFreeAddress, unPageSize, false);
		CHECK(FreeProtection.Change(PAGE_READWRITE) == false);
		CHECK(FreeProtection.Restore() == false);
	}

	TEST_CASE("Protected and Secure ranges roll back partially mapped external memory") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		void* const pReservation = VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE, PAGE_NOACCESS);
		REQUIRE(pReservation != nullptr);
		auto ReservationCleanup = MakeScopeExit([pReservation]() {
			VirtualFree(pReservation, 0, MEM_RELEASE);
		});
		void* const pCommittedPage = VirtualAlloc(pReservation, unPageSize * 2, MEM_COMMIT, PAGE_READWRITE);
		REQUIRE(pCommittedPage == pReservation);
		Detours::Memory::Protection PartialProtection(pReservation, unPageSize * 2, false);
		REQUIRE(PartialProtection.Change(PAGE_READONLY) == true);
#pragma warning(suppress: 6250) // The second page is intentionally decommitted while the reservation remains owned by this test.
		REQUIRE(VirtualFree(static_cast<unsigned char*>(pReservation) + unPageSize, unPageSize, MEM_DECOMMIT) != FALSE);
		CHECK(PartialProtection.Change(PAGE_EXECUTE_READ) == false);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pCommittedPage, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		REQUIRE(MemoryInfo.State == MEM_COMMIT);
		REQUIRE((MemoryInfo.Protect & 0xFF) == PAGE_READONLY);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		{
			Detours::Memory::ProtectedRange ProtectedRange(pReservation, unPageSize * 2);
			CHECK(ProtectedRange.GetRangeAddress() == nullptr);
			CHECK(ProtectedRange.GetRangeSize() == 0);
			CHECK(ProtectedRange.IsProtected() == false);

			Detours::Memory::SecureRange SecureRange(pReservation, unPageSize * 2);
			CHECK(SecureRange.GetRangeAddress() == nullptr);
			CHECK(SecureRange.GetRangeSize() == 0);
			CHECK(SecureRange.IsSecured() == false);
		}

		std::vector<TestMemoryRange> vecAfter;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfter) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(vecBefore, vecAfter, nullptr, 0, unPageSize, &vecNewPages) == true);
		CHECK(vecNewPages.empty());

		MemoryInfo = {};
		REQUIRE(VirtualQuery(pCommittedPage, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK(MemoryInfo.State == MEM_COMMIT);
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READONLY);
	}

	TEST_CASE("MemoryManager normalizes an interior page address") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		void* const pMapping = VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		REQUIRE(pMapping != nullptr);
		auto MappingCleanup = MakeScopeExit([pMapping]() {
			VirtualFree(pMapping, 0, MEM_RELEASE);
		});

		void* const pInteriorAddress = static_cast<unsigned char*>(pMapping) + unPageSize + 17;
		Detours::Memory::MemoryManager Manager;
		std::unique_ptr<Detours::Memory::Page> pPage = Manager.GetPage(pInteriorAddress);
		REQUIRE(pPage != nullptr);
		CHECK(pPage->GetPageAddress() == (static_cast<unsigned char*>(pMapping) + unPageSize));
	}

	TEST_CASE("ProcessScanner chunk boundary") {
		constexpr std::size_t kScannerChunkSize = 1024 * 1024;
		constexpr std::size_t kNeedleSize = sizeof(unsigned long long);
		constexpr std::size_t kNeedleSplit = kNeedleSize / 2;
		std::size_t const unAllocationSize = kScannerChunkSize + kNeedleSize;
		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMemory]() {
			FreeScannerTestMemory(pMemory);
		});

		unsigned long long const unNeedle = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pMemory);
		unsigned char* const pNeedleAddress = pMemory + kScannerChunkSize - kNeedleSplit;
		unsigned char const* const pNeedleData = reinterpret_cast<unsigned char const*>(&unNeedle);
		for (std::size_t unIndex = 0; unIndex < sizeof(unNeedle); ++unIndex) {
			pNeedleAddress[unIndex] = pNeedleData[unIndex];
		}

		TestProcessScanner Scanner;
		TEST_PROCESS_SCAN_RESULT ScanResult {};
		REQUIRE(Scanner.Find(&unNeedle, sizeof(unNeedle), &ScanResult, pMemory, unAllocationSize) == true);
		CHECK(ScanResult.m_bCompleted == true);
		CHECK(ScanResult.m_unBytesScanned == unAllocationSize);
		CHECK(ScanResult.m_unReadFailures == 0);
		CHECK(std::find(ScanResult.m_vecMatches.begin(), ScanResult.m_vecMatches.end(), pNeedleAddress) != ScanResult.m_vecMatches.end());

		bool const bFreed = FreeScannerTestMemory(pMemory);
		CHECK(bFreed == true);
		if (bFreed) {
			MemoryCleanup.Release();
		}
	}

	TEST_CASE("ProcessScanner readable region boundary") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize >= sizeof(unsigned long long));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));
		std::size_t const unAllocationSize = unPageSize * 2;
		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMemory]() {
			FreeScannerTestMemory(pMemory);
		});

		unsigned long long const unNeedle = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pMemory);
		unsigned char* const pNeedleAddress = pMemory + unPageSize - (sizeof(unNeedle) / 2);
		unsigned char const* const pNeedleData = reinterpret_cast<unsigned char const*>(&unNeedle);
		for (std::size_t unIndex = 0; unIndex < sizeof(unNeedle); ++unIndex) {
			pNeedleAddress[unIndex] = pNeedleData[unIndex];
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

		bool const bFreed = FreeScannerTestMemory(pMemory);
		CHECK(bFreed == true);
		if (bFreed) {
			MemoryCleanup.Release();
		}
	}

	TEST_CASE("Protected and Secure ranges reject wrapping external addresses") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		REQUIRE(unPageSize != 0);
		std::uintptr_t const unWrappingAddress = std::numeric_limits<std::uintptr_t>::max() - (std::numeric_limits<std::uintptr_t>::max() % static_cast<std::uintptr_t>(unPageSize));

		Detours::Memory::ProtectedRange ProtectedRange(reinterpret_cast<void*>(unWrappingAddress), unPageSize);
		CHECK(ProtectedRange.GetRangeAddress() == nullptr);
		CHECK(ProtectedRange.GetRangeSize() == 0);
		CHECK(ProtectedRange.IsProtected() == false);

		Detours::Memory::SecureRange SecureRange(reinterpret_cast<void*>(unWrappingAddress), unPageSize);
		CHECK(SecureRange.GetRangeAddress() == nullptr);
		CHECK(SecureRange.GetRangeSize() == 0);
		CHECK(SecureRange.IsSecured() == false);
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
		REQUIRE(const_cast<unsigned long long*>(pData) != nullptr);
		unsigned long long const unValue = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pPageAddress);
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

	TEST_CASE("ProtectedPage externally synchronized access restores protection") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		volatile unsigned int* const pValues = static_cast<volatile unsigned int*>(ProtectedPage.ZeroAlloc(sizeof(unsigned int) * kProtectedStressThreadCount));
		REQUIRE(const_cast<unsigned int*>(pValues) != nullptr);

		ProtectedStressResult const Result = RunProtectedMemoryStress(pValues);
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kProtectedStressThreadCount * kProtectedStressIterations));
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pPageAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);
	}

	TEST_CASE("SecurePage externally synchronized access restores protection") {
		Detours::Memory::SecurePage SecurePage;
		void* const pPageAddress = SecurePage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		volatile unsigned int* const pValues = static_cast<volatile unsigned int*>(SecurePage.ZeroAlloc(sizeof(unsigned int) * kProtectedStressThreadCount));
		REQUIRE(const_cast<unsigned int*>(pValues) != nullptr);

		ProtectedStressResult const Result = RunProtectedMemoryStress(pValues);
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kProtectedStressThreadCount * kProtectedStressIterations));
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pPageAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);
	}

	TEST_CASE("Protected and Secure pages enforce configured access") {
		constexpr unsigned char kCode[] = { 0xB0, 0x01, 0xC3 };
		auto CheckAccessPolicy = [&kCode](auto& Memory) {
			REQUIRE(Memory.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
			volatile unsigned char* const pCode =
				static_cast<volatile unsigned char*>(Memory.Alloc(sizeof(kCode)));
			REQUIRE(const_cast<unsigned char*>(pCode) != nullptr);
			for (std::size_t unIndex = 0; unIndex < sizeof(kCode); ++unIndex) {
				pCode[unIndex] = kCode[unIndex];
			}

			unsigned char* const pExecutableCode = const_cast<unsigned char*>(pCode);
			REQUIRE(FlushInstructionCache(GetCurrentProcess(), pExecutableCode, sizeof(kCode)) != FALSE);
			REQUIRE(Memory.SetProtection(kProtectedMemoryReadOnlyTestProtection) == true);
			unsigned char unValue = 0;
			CHECK(TryReadProtectedPolicyMemory(pCode, &unValue) == true);
			CHECK(unValue == kCode[0]);
			bool bCodeResult = false;
			CHECK(TryExecuteProtectedPolicyMemory(pExecutableCode, &bCodeResult) == false);

			REQUIRE(Memory.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
			CHECK(TryExecuteProtectedPolicyMemory(pExecutableCode, &bCodeResult) == true);
			CHECK(bCodeResult == true);
			CHECK(TryWriteProtectedPolicyMemory(pCode, kCode[0]) == false);

			REQUIRE(Memory.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
			CHECK(TryExecuteProtectedPolicyMemory(pExecutableCode, &bCodeResult) == false);
			CHECK(TryWriteProtectedPolicyMemory(pCode, kCode[0]) == true);
			CHECK(Memory.IsCompromised() == false);

			MEMORY_BASIC_INFORMATION MemoryInfo {};
			REQUIRE(VirtualQuery(pExecutableCode, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
			CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);
		};

		Detours::Memory::ProtectedPage ProtectedPage;
		CheckAccessPolicy(ProtectedPage);
		Detours::Memory::ProtectedRange ProtectedRange(64);
		CheckAccessPolicy(ProtectedRange);
		Detours::Memory::ProtectedStorage ProtectedStorage(64);
		CheckAccessPolicy(ProtectedStorage);
		Detours::Memory::SecurePage SecurePage;
		CheckAccessPolicy(SecurePage);
		Detours::Memory::SecureRange SecureRange(64);
		CheckAccessPolicy(SecureRange);
		Detours::Memory::SecureStorage SecureStorage(64);
		CheckAccessPolicy(SecureStorage);
	}

	TEST_CASE("External CFG target is rejected while Protected and Secure layers are active" * doctest::skip()) {
		RunExternalControlFlowGuardScenario(false);
	}

	TEST_CASE("External CFG target is rejected after Protected and Secure layers are released" * doctest::skip()) {
		RunExternalControlFlowGuardScenario(true);
	}

	TEST_CASE("Protected and Secure layers preserve external CFG call targets") {
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy {};
		if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &ControlFlowGuardPolicy, sizeof(ControlFlowGuardPolicy))) {
			MESSAGE("Control Flow Guard policy queries are unavailable: " << GetLastError());
			return;
		}

		if (!ControlFlowGuardPolicy.EnableControlFlowGuard) {
			MESSAGE("Control Flow Guard is not active for this test executable.");
			return;
		}

		if (!ResolveSetProcessValidCallTargets()) {
			MESSAGE("Selective Control Flow Guard call-target updates are unavailable.");
			return;
		}

		DWORD unExitCode = 0;
		REQUIRE(RunWindowsTestChild(_T("External CFG target is rejected while Protected and Secure layers are active"), &unExitCode) == true);
		CHECK(unExitCode == kControlFlowGuardViolationExitCode);

		unExitCode = 0;
		REQUIRE(RunWindowsTestChild(_T("External CFG target is rejected after Protected and Secure layers are released"), &unExitCode) == true);
		CHECK(unExitCode == kControlFlowGuardViolationExitCode);
	}

	TEST_CASE("Protected and Secure layers share one hidden shadow page") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		Detours::Memory::ProtectedPage ProtectedPage(pPageAddress, unPageCapacity);
		REQUIRE(ProtectedPage.GetPageAddress() == pPageAddress);

		std::vector<TestMemoryRange> vecAfterProtected;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterProtected) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(vecBefore, vecAfterProtected, pPageAddress, unPageCapacity, unPageCapacity, &vecNewPages) == true);
		REQUIRE(vecNewPages.size() == 1);
		void* const pShadowAddress = vecNewPages.front();
		CHECK(IsTestMemoryAddressNoAccess(vecAfterProtected, pPageAddress) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterProtected, pShadowAddress) == true);

		Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
		REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
		std::vector<TestMemoryRange> vecAfterSecure;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterSecure) == true);
		vecNewPages.clear();
		REQUIRE(CollectNewNoAccessTestPages(vecAfterProtected, vecAfterSecure, pPageAddress, unPageCapacity, unPageCapacity, &vecNewPages) == true);
		CHECK(vecNewPages.empty());
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecure, pShadowAddress) == true);

		REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		volatile std::uint64_t* const pValue =
			static_cast<volatile std::uint64_t*>(SecurePage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pValue) != nullptr);
		*pValue = 0x1020304050607080;

		std::vector<unsigned char> vecFirstCiphertext;
		REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecFirstCiphertext) == true);
		REQUIRE(SecurePage.Release() == true);
		std::vector<TestMemoryRange> vecAfterSecureRelease;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterSecureRelease) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecureRelease, pPageAddress) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecureRelease, pShadowAddress) == true);

		Detours::Memory::SecurePage ReplacementSecurePage(pPageAddress, unPageCapacity);
		REQUIRE(ReplacementSecurePage.GetPageAddress() == pPageAddress);
		REQUIRE(ReplacementSecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		std::vector<unsigned char> vecSecondCiphertext;
		REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecSecondCiphertext) == true);
		CHECK(vecFirstCiphertext != vecSecondCiphertext);
		REQUIRE(ReplacementSecurePage.Release() == true);
		REQUIRE(ProtectedPage.Release() == true);

		std::vector<TestMemoryRange> vecAfterRelease;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterRelease) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterRelease, pPageAddress) == false);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterRelease, pShadowAddress) == false);
	}


	TEST_CASE("Protected and Secure pages use exactly one system page") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);

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
		if (!pMultiPageAddress) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMultiPageAddress]() {
			VirtualFree(pMultiPageAddress, 0, MEM_RELEASE);
		});
		{
			Detours::Memory::ProtectedPage InvalidProtectedPage(pMultiPageAddress, unPageSize * 2);
			Detours::Memory::SecurePage InvalidSecurePage(pMultiPageAddress, unPageSize * 2);
			CHECK(InvalidProtectedPage.GetPageAddress() == nullptr);
			CHECK(InvalidSecurePage.GetPageAddress() == nullptr);
		}

		bool const bMultiPageFreed = VirtualFree(pMultiPageAddress, 0, MEM_RELEASE) != FALSE;
		CHECK(bMultiPageFreed == true);
		if (bMultiPageFreed) {
			MemoryCleanup.Release();
		}
	}

	TEST_CASE("ProtectedRange and ProtectedStorage") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unRangeSize = static_cast<std::size_t>(SystemInfo.dwPageSize) + 64;
		Detours::Memory::ProtectedRange ProtectedRange(unRangeSize);
		void* const pRangeAddress = ProtectedRange.GetRangeAddress();
		REQUIRE(pRangeAddress != nullptr);
		CHECK(ProtectedRange.GetRangeSize() == unRangeSize);
		CHECK(ProtectedRange.IsProtected() == true);
		volatile unsigned long long* const pLastValue = reinterpret_cast<volatile unsigned long long*>(static_cast<unsigned char*>(pRangeAddress) + unRangeSize - sizeof(unsigned long long));
		unsigned long long const unValue = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pRangeAddress);
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
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize > 1);

		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pMemory != nullptr);
		if (!pMemory) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMemory]() {
			FreeScannerTestMemory(pMemory);
		});

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
		bool const bFreed = FreeScannerTestMemory(pMemory);
		CHECK(bFreed == true);
		if (bFreed) {
			MemoryCleanup.Release();
		}
	}

	TEST_CASE("Failed external SecurePage hook installation preserves memory") {
		Detours::Memory::Page Page;
		unsigned char* const pPageAddress = static_cast<unsigned char*>(Page.GetPageAddress());
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		DWORD unOriginalProtection = 0;
		REQUIRE(Page.GetProtection(&unOriginalProtection) == true);
		std::vector<unsigned char> vecExpected(unPageCapacity);
		for (std::size_t unIndex = 0; unIndex < unPageCapacity; ++unIndex) {
			vecExpected[unIndex] = static_cast<unsigned char>((unIndex * 37) ^ 0xA5);
		}

		std::memcpy(pPageAddress, vecExpected.data(), vecExpected.size());

		REQUIRE(Detours::Hook::HookMemory(ProtectedMemoryRollbackHook, pPageAddress, unPageCapacity) == true);
		auto HookCleanup = MakeScopeExit([pPageAddress]() {
			Detours::Hook::UnHookMemory(ProtectedMemoryRollbackHook, pPageAddress);
		});
		{
			Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
			CHECK(SecurePage.GetPageAddress() == nullptr);
			CHECK(SecurePage.GetPageCapacity() == 0);
			CHECK(SecurePage.IsSecured() == false);
		}

		bool const bUnHooked = Detours::Hook::UnHookMemory(ProtectedMemoryRollbackHook, pPageAddress);
		REQUIRE(bUnHooked == true);
		HookCleanup.Release();

		DWORD unRestoredProtection = 0;
		REQUIRE(Page.GetProtection(&unRestoredProtection) == true);
		CHECK((unRestoredProtection & 0xFF) == (unOriginalProtection & 0xFF));
		CHECK(std::memcmp(pPageAddress, vecExpected.data(), vecExpected.size()) == 0);
	}

	TEST_CASE("ProtectedPage detects bypass tampering") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);

		Detours::Memory::ProtectedPage ProtectedPage(pPageAddress, Page.GetPageCapacity());
		volatile unsigned long long* const pData = static_cast<volatile unsigned long long*>(ProtectedPage.Alloc(sizeof(unsigned long long)));
		REQUIRE(const_cast<unsigned long long*>(pData) != nullptr);
		*pData = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pData);
		CHECK(ProtectedPage.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(const_cast<unsigned long long*>(pData), sizeof(*pData)) == true);
		CHECK(ProtectedPage.IsCompromised() == true);
		CHECK(ProtectedPage.Release() == true);
	}

	TEST_CASE("SecurePage cannot hide a ProtectedPage compromise") {
		Detours::Memory::Page Page;
		Detours::Memory::ProtectedPage ProtectedPage(Page.GetPageAddress(), Page.GetPageCapacity());
		void* const pData = ProtectedPage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pData);
		REQUIRE(TamperProtectedTestMemory(Page.GetPageAddress(), Page.GetPageCapacity()) == true);
		REQUIRE(ProtectedPage.IsCompromised() == true);

		Detours::Memory::SecurePage SecurePage(ProtectedPage.GetPageAddress(), ProtectedPage.GetPageCapacity());
		if (SecurePage.GetPageAddress()) {
			CHECK(ProtectedPage.IsCompromised() == true);
			CHECK(SecurePage.IsCompromised() == true);
		} else {
			CHECK(SecurePage.IsSecured() == false);
		}
	}

	TEST_CASE("Secure and Protected exact-range composition") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);

		void* pValueAddress = nullptr;
		unsigned long long const unValue = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pPageAddress);
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
			unsigned char const* const pValueBytes = reinterpret_cast<unsigned char const*>(&unValue);
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
		std::size_t const unRangeSize = static_cast<std::size_t>(SystemInfo.dwPageSize) + 64;

		Detours::Memory::SecureRange SecureRange(unRangeSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		REQUIRE(SecureRange.IsSecured() == true);

		Detours::Memory::ProtectedRange ProtectedRange(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize());
		REQUIRE(ProtectedRange.GetRangeAddress() == SecureRange.GetRangeAddress());
		REQUIRE(ProtectedRange.IsProtected() == true);

		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(ProtectedRange.Alloc(unRangeSize));
		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
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
		REQUIRE(const_cast<unsigned long long*>(pFirstValue) != nullptr);
		REQUIRE(const_cast<unsigned long long*>(pSecondValue) != nullptr);
		unsigned long long const unValue = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pFirstAddress);
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

		for (std::size_t unIndex = 0; unIndex < 8; ++unIndex) {
			unsigned long long const unCurrentValue = unValue + unIndex;
			*pFirstValue = unCurrentValue;
			CHECK(*pFirstValue == unCurrentValue);
			CHECK(FirstSecurePage.IsCompromised() == false);
		}

		CHECK(SecondSecurePage.IsCompromised() == false);
	}

	TEST_CASE("SecurePage only reports decrypted hash mismatches") {
		Detours::Memory::SecurePage SecurePage;
		void* const pAddress = SecurePage.GetPageAddress();
		std::size_t const unCapacity = SecurePage.GetPageCapacity();
		REQUIRE(pAddress != nullptr);
		REQUIRE(unCapacity != 0);

		volatile unsigned long long* const pValue = static_cast<volatile unsigned long long*>(SecurePage.Alloc(sizeof(unsigned long long)));
		REQUIRE(const_cast<unsigned long long*>(pValue) != nullptr);
		*pValue = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pValue);
		CHECK(SecurePage.IsCompromised() == false);

		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pAddress, unCapacity, PAGE_READONLY, &unOldProtection) != FALSE);
		auto ProtectionCleanup = MakeScopeExit([pAddress, unCapacity, unOldProtection]() {
			DWORD unTemporaryProtection = 0;
			VirtualProtect(pAddress, unCapacity, unOldProtection, &unTemporaryProtection);
		});
		CHECK(SecurePage.IsCompromised() == false);
		CHECK(SecurePage.IsSecured() == false);

		DWORD unTemporaryProtection = 0;
		bool const bRestored = VirtualProtect(pAddress, unCapacity, unOldProtection, &unTemporaryProtection) != FALSE;
		CHECK(bRestored == true);
		if (bRestored) {
			ProtectionCleanup.Release();
		}
	}

	TEST_CASE("SecurePage detects encrypted payload tampering") {
		Detours::Memory::Page Page;
		Detours::Memory::SecurePage SecurePage(Page.GetPageAddress(), Page.GetPageCapacity());
		void* const pData = SecurePage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pData);
		CHECK(SecurePage.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(Page.GetPageAddress(), Page.GetPageCapacity()) == true);
		CHECK(SecurePage.IsCompromised() == true);

		Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
		CHECK(ProtectedPage.IsCompromised() == true);
		CHECK(ProtectedPage.Release() == true);
		CHECK(SecurePage.Release() == true);
		CHECK(*static_cast<unsigned long long*>(pData) == 0);
	}

	TEST_CASE("SecurePage detects ciphertext tampering after metadata protection bypass") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
		REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
		volatile unsigned long long* const pData = static_cast<volatile unsigned long long*>(SecurePage.Alloc(sizeof(unsigned long long)));
		REQUIRE(const_cast<unsigned long long*>(pData) != nullptr);
		*pData = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pData);
		REQUIRE(SecurePage.IsCompromised() == false);

		std::vector<TestMemoryRange> vecAfter;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfter) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(vecBefore, vecAfter, pPageAddress, unPageCapacity, unPageCapacity, &vecNewPages) == true);
		REQUIRE(vecNewPages.size() == 1);
		void* const pMetadataAddress = vecNewPages.front();

		DWORD unOldPageProtection = 0;
		REQUIRE(VirtualProtect(pPageAddress, unPageCapacity, PAGE_EXECUTE_READWRITE, &unOldPageProtection) != FALSE);
		auto PageProtectionCleanup = MakeScopeExit([pPageAddress, unPageCapacity, unOldPageProtection]() {
			DWORD unTemporaryProtection = 0;
			VirtualProtect(pPageAddress, unPageCapacity, unOldPageProtection, &unTemporaryProtection);
		});
		REQUIRE((unOldPageProtection & 0xFF) == PAGE_NOACCESS);

		DWORD unOldMetadataProtection = 0;
		REQUIRE(VirtualProtect(pMetadataAddress, unPageCapacity, PAGE_EXECUTE_READWRITE, &unOldMetadataProtection) != FALSE);
		auto MetadataProtectionCleanup = MakeScopeExit([pMetadataAddress, unPageCapacity, unOldMetadataProtection]() {
			DWORD unTemporaryProtection = 0;
			VirtualProtect(pMetadataAddress, unPageCapacity, unOldMetadataProtection, &unTemporaryProtection);
		});
		REQUIRE((unOldMetadataProtection & 0xFF) == PAGE_NOACCESS);

		unsigned char* const pCiphertext = static_cast<unsigned char*>(pPageAddress);
		pCiphertext[0] = static_cast<unsigned char>(pCiphertext[0] ^ 1);
		CHECK(SecurePage.IsCompromised() == true);
		CHECK(SecurePage.IsSecured() == false);

		std::vector<TestMemoryRange> vecRestored;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecRestored) == true);
		bool const bPageHidden = IsTestMemoryAddressNoAccess(vecRestored, pPageAddress);
		bool const bMetadataHidden = IsTestMemoryAddressNoAccess(vecRestored, pMetadataAddress);
		CHECK(bPageHidden == true);
		CHECK(bMetadataHidden == true);
		if (bPageHidden) {
			PageProtectionCleanup.Release();
		}

		if (bMetadataHidden) {
			MetadataProtectionCleanup.Release();
		}
	}

	TEST_CASE("SecurePage teardown completes after ciphertext tampering") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		DWORD unOriginalProtection = 0;
		REQUIRE(Page.GetProtection(&unOriginalProtection) == true);

		Detours::Memory::SecurePage SecurePage(pPageAddress, Page.GetPageCapacity());
		void* const pData = SecurePage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = 0x1020304050607080;
		REQUIRE(TamperProtectedTestMemory(pPageAddress, Page.GetPageCapacity()) == true);
		CHECK(SecurePage.IsCompromised() == true);
		REQUIRE(SecurePage.Release() == true);
		CHECK(SecurePage.GetPageAddress() == nullptr);

		DWORD unRestoredProtection = 0;
		REQUIRE(Page.GetProtection(&unRestoredProtection) == true);
		REQUIRE((unRestoredProtection & 0xFF) == (unOriginalProtection & 0xFF));
		volatile unsigned int* const pDirectValue = static_cast<volatile unsigned int*>(pPageAddress);
		*pDirectValue = 0x5A5AA5A5;
		CHECK(*pDirectValue == 0x5A5AA5A5);
	}

	TEST_CASE("ProtectedPage preserves SecurePage compromise state") {
		Detours::Memory::Page Page;
		Detours::Memory::SecurePage SecurePage(Page.GetPageAddress(), Page.GetPageCapacity());
		Detours::Memory::ProtectedPage ProtectedPage(SecurePage.GetPageAddress(), SecurePage.GetPageCapacity());
		void* const pData = ProtectedPage.Alloc(sizeof(unsigned long long));
		REQUIRE(pData != nullptr);
		*static_cast<volatile unsigned long long*>(pData) = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pData);
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
		CHECK((reinterpret_cast<std::uintptr_t>(pAddress) % SecurePage.GetPageCapacity()) == 0);
		CHECK(SecurePage.IsSecured() == true);

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pAddress, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK(MemoryInfo.State == MEM_COMMIT);
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		unsigned long long const unNeedle = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pAddress);
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
		std::size_t const unRangeSize = static_cast<std::size_t>(SystemInfo.dwPageSize) + 64;
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

		unsigned long long const unNeedle = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pAddress);
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
		REQUIRE(VirtualQuery(const_cast<unsigned long long const*>(pLastValue), &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		CHECK(SecureRange.Release() == true);
		CHECK(SecureRange.GetRangeAddress() == nullptr);
		CHECK(SecureRange.GetRangeSize() == 0);
		CHECK(SecureRange.IsSecured() == false);
		CHECK(SecureRange.Release() == false);
	}

	TEST_CASE("SecureRange authenticates partial logical tail") {
		constexpr std::size_t kRangeSize = 31;
		Detours::Memory::SecureRange SecureRange(kRangeSize);
		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(SecureRange.Alloc(kRangeSize));
		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
		CHECK(SecureRange.GetRangeSize() == kRangeSize);
		CHECK(SecureRange.IsSecured() == true);

		unsigned char arrPlaintext[kRangeSize] {};
		for (std::size_t unIndex = 0; unIndex < kRangeSize; ++unIndex) {
			arrPlaintext[unIndex] = static_cast<unsigned char>(unIndex + 1);
			pData[unIndex] = arrPlaintext[unIndex];
		}

		volatile unsigned char* const pTail = pData + (kRangeSize - 1);
		CHECK(*pTail == arrPlaintext[kRangeSize - 1]);
		std::vector<unsigned char> vecCiphertext;
		REQUIRE(CopyProtectedTestMemory(const_cast<unsigned char*>(pData), kRangeSize, &vecCiphertext) == true);
		CHECK(std::equal(arrPlaintext + 16, arrPlaintext + kRangeSize, vecCiphertext.begin() + 16) == false);
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
		CHECK(SecureStorage.Alloc(std::numeric_limits<std::size_t>::max()) == nullptr);
		CHECK(SecureStorage.GetDataSize() == 128);

		unsigned long long const unNeedle = __rdtsc() ^ reinterpret_cast<std::uintptr_t>(pFirst);
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
		REQUIRE(const_cast<unsigned long long*>(pPageData) != nullptr);
		*pPageData = 0x123456789ABCDEF0;
		CHECK(*pPageData == 0x123456789ABCDEF0);

		Detours::Memory::ProtectedStorage* const pStorage = Manager.CreateStorage(64);
		REQUIRE(pStorage != nullptr);
		volatile unsigned long long* const pStorageData = static_cast<volatile unsigned long long*>(pStorage->Alloc(64));
		REQUIRE(const_cast<unsigned long long*>(pStorageData) != nullptr);
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
		REQUIRE(const_cast<unsigned long long*>(pPageData) != nullptr);
		*pPageData = 0x123456789ABCDEF0;
		CHECK(*pPageData == 0x123456789ABCDEF0);

		Detours::Memory::SecureStorage* const pStorage = Manager.CreateStorage(64);
		REQUIRE(pStorage != nullptr);
		volatile unsigned long long* const pStorageData = static_cast<volatile unsigned long long*>(pStorage->Alloc(64));
		REQUIRE(const_cast<unsigned long long*>(pStorageData) != nullptr);
		*pStorageData = 0x0FEDCBA987654321;
		CHECK(*pStorageData == 0x0FEDCBA987654321);
		CHECK(pStorage->IsSecured() == true);

		CHECK(Manager.DestroyStorage(pStorage) == true);
		CHECK(Manager.DestroyPage(pPage) == true);
	}
} // TEST_SUITE("Detours::Memory")

TEST_SUITE("Detours::Exception") {
	constexpr DWORD kExceptionListenerLifecycleCode = 0xE0424242;
	constexpr DWORD kDeadOwnerExceptionCode = 0xE0424243;
	constexpr DWORD kDeadOwnerExceptionExitCode = 0x42;
	constexpr std::size_t kWindowsThreadStateChurnCount = 544;
	std::atomic<unsigned int> g_unConfiguredExceptionCallBackCalls = 0;
	std::atomic<unsigned int> g_unDestroyedExceptionCallBackCalls = 0;
	std::atomic<unsigned int> g_unFirstExceptionOrderCallBackCalls = 0;
	std::atomic<unsigned int> g_unSecondExceptionOrderCallBackCalls = 0;
	std::atomic<unsigned int> g_unNestedExceptionCallBackCalls = 0;
	std::atomic<unsigned int> g_unNestedExceptionFallbackCalls = 0;
	std::atomic<bool> g_bBlockingExceptionCallBackEntered = false;
	std::atomic<bool> g_bReleaseBlockingExceptionCallBack = false;
	std::atomic<bool> g_bBlockNextExceptionOrderDispatch = false;
	std::atomic<bool> g_bExceptionOrderDispatchBlocked = false;
	std::atomic<bool> g_bReleaseExceptionOrderDispatch = false;
	std::atomic<bool> g_bCycleExceptionOrderCallBack = false;
	std::atomic<bool> g_bExceptionOrderCycleSucceeded = false;
	std::atomic<bool> g_bNestedExceptionRemovalSucceeded = false;
	Detours::Exception::ExceptionListener* g_pExceptionOrderListener = nullptr;
	Detours::Exception::ExceptionListener* g_pNestedExceptionListener = nullptr;

	bool DeadOwnerExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kDeadOwnerExceptionCode) {
			return false;
		}

		ExitThread(kDeadOwnerExceptionExitCode);
	}

	DWORD WINAPI RaiseDeadOwnerException(void*) {
		RaiseException(kDeadOwnerExceptionCode, 0, 0, nullptr);
		return 1;
	}

	bool ThreadErrorStateExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const pCTX) {
		if ((Exception.ExceptionCode != EXCEPTION_BREAKPOINT) || !pCTX) {
			return false;
		}

#if defined(DETOURS_ARCH_X64)
		++pCTX->Rip;
#elif defined(DETOURS_ARCH_X86)
		++pCTX->Eip;
#endif
		errno = EOVERFLOW;
		SetLastError(ERROR_ACCESS_DENIED);
		return true;
	}


	TEST_CASE("Vectored exception dispatch preserves thread error state") {
		Detours::Exception::ExceptionListener Listener;
		REQUIRE(Listener.AddCallBack(ThreadErrorStateExceptionCallBack) == true);
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});

		errno = EDOM;
		SetLastError(ERROR_BAD_LENGTH);
		__debugbreak();
		DWORD const unObservedLastError = GetLastError();
		int const nObservedError = errno;
		CHECK(unObservedLastError == ERROR_BAD_LENGTH);
		CHECK(nObservedError == EDOM);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	bool ConfiguredExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_unConfiguredExceptionCallBackCalls.fetch_add(1, std::memory_order_relaxed);
		return true;
	}

	bool DestroyedExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_unDestroyedExceptionCallBackCalls.fetch_add(1, std::memory_order_relaxed);
		return true;
	}

	bool ExceptionCallBackFallback(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		return Exception.ExceptionCode == kExceptionListenerLifecycleCode;
	}

	bool DestroyedExceptionCallBackFallback(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		return Exception.ExceptionCode == kExceptionListenerLifecycleCode;
	}

	bool FirstExceptionOrderCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_unFirstExceptionOrderCallBackCalls.fetch_add(1, std::memory_order_relaxed);
		if (g_bCycleExceptionOrderCallBack.exchange(false, std::memory_order_acq_rel)) {
			Detours::Exception::ExceptionListener* const pListener = g_pExceptionOrderListener;
			bool const bSucceeded = pListener &&
									pListener->RemoveCallBack(FirstExceptionOrderCallBack) &&
									pListener->AddCallBack(FirstExceptionOrderCallBack) &&
									pListener->RemoveCallBack(FirstExceptionOrderCallBack) &&
									pListener->AddCallBack(FirstExceptionOrderCallBack);
			g_bExceptionOrderCycleSucceeded.store(bSucceeded, std::memory_order_release);
		}

		return true;
	}

	bool SecondExceptionOrderCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_unSecondExceptionOrderCallBackCalls.fetch_add(1, std::memory_order_relaxed);
		return false;
	}

	bool BlockingExceptionOrderCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if ((Exception.ExceptionCode != kExceptionListenerLifecycleCode) ||
			!g_bBlockNextExceptionOrderDispatch.exchange(false, std::memory_order_acq_rel)) {
			return false;
		}

		g_bExceptionOrderDispatchBlocked.store(true, std::memory_order_release);
		while (!g_bReleaseExceptionOrderDispatch.load(std::memory_order_acquire)) {
			std::atomic_signal_fence(std::memory_order_seq_cst);
		}

		return false;
	}

	bool BlockingExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_bBlockingExceptionCallBackEntered.store(true, std::memory_order_release);
		while (!g_bReleaseBlockingExceptionCallBack.load(std::memory_order_acquire)) {
			std::atomic_signal_fence(std::memory_order_seq_cst);
		}

		return true;
	}

	bool NestedExceptionCallBack(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		unsigned int const unCalls = g_unNestedExceptionCallBackCalls.fetch_add(1, std::memory_order_relaxed) + 1;
		if (unCalls == 1) {
			RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		} else if ((unCalls == 2) && g_pNestedExceptionListener) {
			g_bNestedExceptionRemovalSucceeded.store(
				g_pNestedExceptionListener->RemoveCallBack(NestedExceptionCallBack), std::memory_order_release);
		}

		return true;
	}

	bool NestedExceptionFallback(EXCEPTION_RECORD const& Exception, CONTEXT* const) {
		if (Exception.ExceptionCode != kExceptionListenerLifecycleCode) {
			return false;
		}

		g_unNestedExceptionFallbackCalls.fetch_add(1, std::memory_order_relaxed);
		return true;
	}

	bool OnException(EXCEPTION_RECORD const& Exception, PCONTEXT const pCTX) {
		if (Exception.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
			return false;
		}

		ULONG_PTR const unAccessType = Exception.ExceptionInformation[0];
		if (unAccessType != 0) {
			return false;
		}

		void const* const pAccessAddress = reinterpret_cast<void*>(Exception.ExceptionInformation[1]);
		void const* const pInvalidAddress = reinterpret_cast<void*>(std::numeric_limits<std::uintptr_t>::max());
		if (pAccessAddress != pInvalidAddress) {
			return false;
		}

		unsigned char* pCode = reinterpret_cast<unsigned char*>(Exception.ExceptionAddress);
		if (pCode[0] != 0xCD) {
			return false;
		}

		unsigned char const unInterrupt = pCode[1];

		_tprintf_s(_T("[OnException] Called `int 0x%02X`\n"), unInterrupt);
#if defined(_M_X64)
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
#elif defined(_M_IX86)
		_tprintf_s(_T("  -> EAX = 0x%08X\n"), pCTX->Eax);
		_tprintf_s(_T("  -> ECX = 0x%08X\n"), pCTX->Ecx);
		_tprintf_s(_T("  -> EDX = 0x%08X\n"), pCTX->Edx);
		_tprintf_s(_T("  -> EBX = 0x%08X\n"), pCTX->Ebx);
		_tprintf_s(_T("  -> EBP = 0x%08X\n"), pCTX->Ebp);
		_tprintf_s(_T("  -> ESI = 0x%08X\n"), pCTX->Esi);
		_tprintf_s(_T("  -> EDI = 0x%08X\n"), pCTX->Edi);
#endif

#if defined(_M_X64)
		pCTX->Rip += 2;
		pCTX->Rax = 0xDEEDBEEF;
#elif defined(_M_IX86)
		pCTX->Eip += 2;
		pCTX->Eax = 0xDEEDBEEF;
#endif

		return true;
	}

#if defined(_M_X64)
	TEST_CASE("CallInterrupt has unwind metadata") {
		DWORD64 unFunctionAddress = reinterpret_cast<DWORD64>(&CallInterrupt);
		unsigned char const* const pFunctionCode = reinterpret_cast<unsigned char const*>(unFunctionAddress);
		if (pFunctionCode[0] == 0xE9) {
			signed int nRelativeOffset = 0;
			std::memcpy(&nRelativeOffset, pFunctionCode + 1, sizeof(nRelativeOffset));
			unFunctionAddress = static_cast<DWORD64>(static_cast<std::intptr_t>(unFunctionAddress) + 5 + static_cast<std::intptr_t>(nRelativeOffset));
		}

		DWORD64 unImageBase = 0;
		PRUNTIME_FUNCTION const pRuntimeFunction = RtlLookupFunctionEntry(unFunctionAddress, &unImageBase, nullptr);
		CHECK(pRuntimeFunction != nullptr);
		CHECK(unImageBase != 0);
		if (pRuntimeFunction && unImageBase) {
			CHECK(unFunctionAddress >= (unImageBase + pRuntimeFunction->BeginAddress));
			CHECK(unFunctionAddress < (unImageBase + pRuntimeFunction->EndAddress));
		}
	}
#endif

	TEST_CASE("g_ExceptionListener") {
		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(OnException) == true);
		auto CallBackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(OnException);
		});
#if defined(_M_X64)
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 0xDEEDBEEF);
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 0xDEEDBEEF);
#elif defined(_M_IX86)
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7) == 0xDEEDBEEF);
		CHECK(CallInterrupt(1, 2, 3, 4, 5, 6, 7) == 0xDEEDBEEF);
#endif
		bool const bRemoved = Detours::Exception::g_ExceptionListener.RemoveCallBack(OnException);
		CHECK(bRemoved == true);
		if (bRemoved) {
			CallBackCleanup.Release();
		}
	}

	TEST_CASE("ExceptionListener publishes callbacks only while enabled") {
		g_unConfiguredExceptionCallBackCalls.store(0, std::memory_order_relaxed);
		g_unDestroyedExceptionCallBackCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Exception::g_ExceptionListener.EnableHandler() == true);

		Detours::Exception::ExceptionListener Listener;
		REQUIRE(Listener.AddCallBack(ConfiguredExceptionCallBack) == true);
		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(ExceptionCallBackFallback) == true);
		auto NeverEnabledFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(ExceptionCallBackFallback);
		});
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unConfiguredExceptionCallBackCalls.load(std::memory_order_relaxed) == 0);
		REQUIRE(Detours::Exception::g_ExceptionListener.RemoveCallBack(ExceptionCallBackFallback) == true);
		NeverEnabledFallbackCleanup.Release();

		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unConfiguredExceptionCallBackCalls.load(std::memory_order_relaxed) == 1);
		REQUIRE(Listener.DisableHandler() == true);
		ListenerCleanup.Release();

		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(ExceptionCallBackFallback) == true);
		auto DisabledFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(ExceptionCallBackFallback);
		});
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unConfiguredExceptionCallBackCalls.load(std::memory_order_relaxed) == 1);
		REQUIRE(Detours::Exception::g_ExceptionListener.RemoveCallBack(ExceptionCallBackFallback) == true);
		DisabledFallbackCleanup.Release();

		REQUIRE(Listener.EnableHandler() == true);
		auto ReenabledListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unConfiguredExceptionCallBackCalls.load(std::memory_order_relaxed) == 2);
		REQUIRE(Listener.DisableHandler() == true);
		ReenabledListenerCleanup.Release();

		{
			Detours::Exception::ExceptionListener DestroyedListener;
			REQUIRE(DestroyedListener.AddCallBack(DestroyedExceptionCallBack) == true);
			REQUIRE(DestroyedListener.EnableHandler() == true);
			RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
			CHECK(g_unDestroyedExceptionCallBackCalls.load(std::memory_order_relaxed) == 1);
		}

		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(DestroyedExceptionCallBackFallback) == true);
		auto DestroyedFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(DestroyedExceptionCallBackFallback);
		});
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unDestroyedExceptionCallBackCalls.load(std::memory_order_relaxed) == 1);
		bool const bFallbackRemoved = Detours::Exception::g_ExceptionListener.RemoveCallBack(DestroyedExceptionCallBackFallback);
		CHECK(bFallbackRemoved == true);
		if (bFallbackRemoved) {
			DestroyedFallbackCleanup.Release();
		}
	}




	TEST_CASE("ExceptionListener supports nested self-removal") {
		g_unNestedExceptionCallBackCalls.store(0, std::memory_order_relaxed);
		g_unNestedExceptionFallbackCalls.store(0, std::memory_order_relaxed);
		g_bNestedExceptionRemovalSucceeded.store(false, std::memory_order_relaxed);

		Detours::Exception::ExceptionListener Listener;
		g_pNestedExceptionListener = &Listener;
		auto ListenerPointerCleanup = MakeScopeExit([]() {
			g_pNestedExceptionListener = nullptr;
		});
		REQUIRE(Listener.AddCallBack(NestedExceptionCallBack) == true);
		REQUIRE(Listener.AddCallBack(NestedExceptionFallback) == true);
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});

		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unNestedExceptionCallBackCalls.load(std::memory_order_relaxed) == 2);
		CHECK(g_bNestedExceptionRemovalSucceeded.load(std::memory_order_acquire) == true);
		CHECK(g_unNestedExceptionFallbackCalls.load(std::memory_order_relaxed) == 0);

		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unNestedExceptionFallbackCalls.load(std::memory_order_relaxed) == 1);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	TEST_CASE("ExceptionListener appends a re-added callback to dispatch order") {
		g_unFirstExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		g_unSecondExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		Detours::Exception::ExceptionListener Listener;
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.RemoveCallBack(FirstExceptionOrderCallBack);
			Listener.RemoveCallBack(SecondExceptionOrderCallBack);
			Listener.DisableHandler();
		});

		REQUIRE(Listener.AddCallBack(FirstExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(SecondExceptionOrderCallBack) == true);
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unFirstExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 0);

		REQUIRE(Listener.RemoveCallBack(FirstExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(FirstExceptionOrderCallBack) == true);
		g_unFirstExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		g_unSecondExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		CHECK(g_unFirstExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 1);

		CHECK(Listener.RemoveCallBack(SecondExceptionOrderCallBack) == true);
		CHECK(Listener.RemoveCallBack(FirstExceptionOrderCallBack) == true);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	TEST_CASE("ExceptionListener rejects stale snapshots after repeated callback reactivation") {
		g_unFirstExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		g_unSecondExceptionOrderCallBackCalls.store(0, std::memory_order_relaxed);
		g_bBlockNextExceptionOrderDispatch.store(false, std::memory_order_relaxed);
		g_bExceptionOrderDispatchBlocked.store(false, std::memory_order_relaxed);
		g_bReleaseExceptionOrderDispatch.store(false, std::memory_order_relaxed);
		g_bCycleExceptionOrderCallBack.store(false, std::memory_order_relaxed);
		g_bExceptionOrderCycleSucceeded.store(false, std::memory_order_relaxed);

		Detours::Exception::ExceptionListener Listener;
		std::thread DispatchThread;
		g_pExceptionOrderListener = &Listener;
		auto Cleanup = MakeScopeExit([&Listener, &DispatchThread]() {
			g_bReleaseExceptionOrderDispatch.store(true, std::memory_order_release);
			if (DispatchThread.joinable()) {
				DispatchThread.join();
			}

			g_pExceptionOrderListener = nullptr;
			Listener.RemoveCallBack(BlockingExceptionOrderCallBack);
			Listener.RemoveCallBack(FirstExceptionOrderCallBack);
			Listener.RemoveCallBack(SecondExceptionOrderCallBack);
			Listener.RemoveCallBack(ExceptionCallBackFallback);
			Listener.DisableHandler();
		});

		REQUIRE(Listener.AddCallBack(BlockingExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(FirstExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(SecondExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(ExceptionCallBackFallback) == true);
		REQUIRE(Listener.EnableHandler() == true);

		g_bBlockNextExceptionOrderDispatch.store(true, std::memory_order_release);
		DispatchThread = std::thread([]() {
			RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		});
		REQUIRE(WaitForTestCondition(
			[]() {
				return g_bExceptionOrderDispatchBlocked.load(std::memory_order_acquire);
			},
			kParallelThreadWaitMilliseconds));

		g_bCycleExceptionOrderCallBack.store(true, std::memory_order_release);
		RaiseException(kExceptionListenerLifecycleCode, 0, 0, nullptr);
		REQUIRE(g_bExceptionOrderCycleSucceeded.load(std::memory_order_acquire) == true);
		g_bReleaseExceptionOrderDispatch.store(true, std::memory_order_release);
		DispatchThread.join();

		CHECK(g_unFirstExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondExceptionOrderCallBackCalls.load(std::memory_order_relaxed) == 1);
		g_pExceptionOrderListener = nullptr;
		CHECK(Listener.RemoveCallBack(BlockingExceptionOrderCallBack) == true);
		CHECK(Listener.RemoveCallBack(FirstExceptionOrderCallBack) == true);
		CHECK(Listener.RemoveCallBack(SecondExceptionOrderCallBack) == true);
		CHECK(Listener.RemoveCallBack(ExceptionCallBackFallback) == true);
		CHECK(Listener.DisableHandler() == true);
		Cleanup.Release();
	}


} // TEST_SUITE("Detours::Exception")

TEST_SUITE("Detours::rddisasm") {
	TEST_CASE("RdDecode") {
		Detours::rddisasm::INSTRUCTION ins;
		unsigned char pCode[3] = { 0xB0, 0x01 }; // mov al, 1
#if defined(_M_X64)
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pCode), RD_DATA_64, RD_DATA_64)) == true);
#elif _M_IX86
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pCode), RD_DATA_32, RD_DATA_32)) == true);
#endif

		CHECK(ins.Length == 2);
		CHECK(ins.Instruction == Detours::rddisasm::RD_INS_CLASS::RD_INS_MOV);
	}
}

TEST_SUITE("Detours::Hook") {
	constexpr std::size_t kNestedMemoryHookEventCapacity = 8;
	constexpr unsigned int kFirstRawCapacityOffset = 0x11;
	constexpr unsigned int kSecondRawCapacityOffset = 0x22;
	constexpr unsigned int kRawCETOriginalValue = 0x10203040;
	constexpr unsigned int kRawCETRedirectValue = 0x50607080;
	constexpr unsigned int kRawCETFailSafeValue = 0x90A0B0C0;
	constexpr unsigned int kRawCETReservedStackSize = sizeof(void*) * 2;
	constexpr DWORD kRawStackValidationFailureExitCode = 0x4C;
	constexpr unsigned int kRawHookUnwindExceptionValue = 0x6A17C0DE;
	constexpr unsigned int kRawStackProbeOriginalValue = 0x13572468;
	constexpr unsigned int kRawStackProbeHookValue = 0x24681357;
	constexpr unsigned int kRawStackProbeReservedStackSize = 128 * 1024;
	constexpr std::size_t kRawStackProbeFiberReserveSize = 1024 * 1024;
	constexpr DWORD kRawCETChildWaitMilliseconds = 60'000;
	constexpr std::size_t kRawCETExecutablePathCapacity = 32'768;
	constexpr unsigned int kThreadAccessorLoopCount = 100;
	constexpr unsigned int kThreadAccessorPauseCount = 1'000'000;
	constexpr DWORD kDeadOwnerMemoryHookExitCode = 0x43;
	constexpr DWORD kProtectedMemoryDeadOwnerExitCode = 0x44;
	constexpr DWORD kDeadOwnerManualMemoryHookExitCode = 0x45;
	constexpr DWORD kDeadOwnerManualMemoryHookProtectionFailureExitCode = 0x46;
	constexpr DWORD kDeadOwnerInterruptHookExitCode = 0x47;
	constexpr DWORD kDeadOwnerHardwareHookExitCode = 0x48;
	constexpr DWORD kWindowsReaperControlOwnerExitCode = 0xE0000101;
	constexpr unsigned int kWindowsReaperControlExitPhaseHandlePublished = 2;
	constexpr unsigned int kWindowsReaperControlExitPhaseStopping = 3;
	constexpr std::size_t kWindowsMemoryHookThreadStateChurnCount = 544;
	constexpr std::size_t kWindowsDeadOwnerInterruptHookChurnCount = 272;
	constexpr std::size_t kWindowsDeadOwnerHardwareHookShardCount = 52;
	constexpr std::size_t kWindowsDeadOwnerHardwareHookProcessCount = 5;
	constexpr std::size_t kInlineWrapperSelfUnHookIterationCount = 8;
	constexpr std::size_t kInlineWrapperSelfUnHookDepth = 128;
	constexpr std::size_t kThreadRangeAccessorValueCapacity = 2;
	constexpr std::size_t kInlineProtectionCodeSize = 6;
	constexpr std::size_t kInlineProtectionFailingTargetOffset = 64;
	constexpr std::size_t kInlineProtectionMinimumPageSize = 256;
	constexpr unsigned int kInlineProtectionOriginalValue = 11;
	constexpr unsigned int kInlineProtectionHookValue = 37;
	constexpr DWORD kDebugRegisterTrapFlagMask = static_cast<DWORD>(1) << 8;
	constexpr DWORD_PTR kDebugRegisterZeroSlotMask = 0xF0003;
	constexpr unsigned int kInterruptHookReturnValue = 0xDEEDBEEF;

	typedef enum _NESTED_MEMORY_HOOK_EVENT {
		NestedOuterPreBegin = 0,
		NestedInnerPre,
		NestedInnerPost,
		NestedOuterPreEnd,
		NestedOuterPost
	} NESTED_MEMORY_HOOK_EVENT;

	typedef struct _WINDOWS_DEBUG_CONTEXT_REQUEST {
		_WINDOWS_DEBUG_CONTEXT_REQUEST() noexcept;

		HANDLE m_hThread;
		CONTEXT m_Context;
		bool m_bSuspendSucceeded;
		bool m_bGetContextSucceeded;
		bool m_bResumeSucceeded;
	} WINDOWS_DEBUG_CONTEXT_REQUEST, *PWINDOWS_DEBUG_CONTEXT_REQUEST;

	typedef struct _WINDOWS_REAPER_PAUSE_TEST_DATA {
		_WINDOWS_REAPER_PAUSE_TEST_DATA() noexcept;

		std::atomic<unsigned int> m_unAcquiredCount;
		std::atomic<unsigned int> m_unFailureCount;
		std::atomic<bool> m_bStart;
		std::atomic<bool> m_bRelease;
		bool m_bExitWithoutResume;
	} WINDOWS_REAPER_PAUSE_TEST_DATA, *PWINDOWS_REAPER_PAUSE_TEST_DATA;

	struct ThreadRangeAccessorLoopData {
		ThreadRangeAccessorLoopData() noexcept;

		unsigned int* m_pAddress;
		std::size_t m_unValueCount;
		unsigned int m_arrValues[kThreadRangeAccessorValueCapacity];
	};

	using fnRawStackProbeTarget = unsigned int(__cdecl*)();

	typedef struct _RAW_STACK_PROBE_FIBER_DATA {
		_RAW_STACK_PROBE_FIBER_DATA() noexcept;

		void* m_pMainFiber;
		fnRawStackProbeTarget m_pTarget;
		unsigned int m_unResult;
		bool m_bCompleted;
	} RAW_STACK_PROBE_FIBER_DATA, *PRAW_STACK_PROBE_FIBER_DATA;

#if defined(_M_IX86)
	typedef struct _STANDALONE_RAW_CALL_CONTEXT {
		Detours::Hook::RAW_CONTEXT m_Context;
		void* m_arrCanary[2];
	} STANDALONE_RAW_CALL_CONTEXT;
#endif

	_WINDOWS_DEBUG_CONTEXT_REQUEST::_WINDOWS_DEBUG_CONTEXT_REQUEST() noexcept :
		m_hThread(nullptr),
		m_Context {},
		m_bSuspendSucceeded(false),
		m_bGetContextSucceeded(false),
		m_bResumeSucceeded(false)
	{
	}

	_WINDOWS_REAPER_PAUSE_TEST_DATA::_WINDOWS_REAPER_PAUSE_TEST_DATA() noexcept :
		m_unAcquiredCount(0),
		m_unFailureCount(0),
		m_bStart(false),
		m_bRelease(false),
		m_bExitWithoutResume(false)
	{
	}

	ThreadRangeAccessorLoopData::ThreadRangeAccessorLoopData() noexcept :
		m_arrValues {}
	{
		m_pAddress = nullptr;
		m_unValueCount = 0;
	}

	_RAW_STACK_PROBE_FIBER_DATA::_RAW_STACK_PROBE_FIBER_DATA() noexcept :
		m_pMainFiber(nullptr),
		m_pTarget(nullptr),
		m_unResult(0),
		m_bCompleted(false)
	{
	}

	static_assert(kInlineProtectionCodeSize == (sizeof(unsigned int) + 2), "Inline protection fixture must contain an immediate move and return");
	static_assert(
		(kInlineProtectionFailingTargetOffset + 2) <= kInlineProtectionMinimumPageSize,
		"Inline protection fixture offsets must fit in the minimum page");
	static_assert(std::atomic<LONG>::is_always_lock_free, "Windows exception callbacks require lock-free LONG atomics");
	static_assert(
		(kWindowsDeadOwnerHardwareHookShardCount * kWindowsDeadOwnerHardwareHookProcessCount) > 256,
		"Aggregate hardware dead-owner churn coverage must exceed 256 callbacks");
#if defined(_M_IX86)
	static_assert(
		offsetof(STANDALONE_RAW_CALL_CONTEXT, m_arrCanary) == sizeof(Detours::Hook::RAW_CONTEXT),
		"The standalone raw-call canary must immediately follow RAW_CONTEXT");
#endif

	Detours::Hook::VTableFunctionHook g_FooHook;
	Detours::Hook::VTableFunctionHook g_BooHook;
	Detours::Hook::VTableHook g_TestingRTTIVTableHook;
	bool g_bInlineSleepHookCalled = false;
	Detours::Hook::InlineWrapperHook g_InlineSleepHook;
	bool g_bRawSleepHookCalled = false;
	Detours::Hook::RawHook g_RawSleepHook;
	std::atomic<unsigned int> g_unRawSleepConcurrentCalls = 0;
	Detours::Hook::RawHook g_RawSleepConcurrentHook;
	Detours::Hook::RAW_CONTEXT_M128 g_LastXMM7;
	Detours::Hook::RawHook g_RawCallConventionHook;
	Detours::Hook::RawHook g_RawCPUIDHook;
	Detours::Hook::RawHook g_FirstCapacityRawHook;
	Detours::Hook::RawHook g_SecondCapacityRawHook;
	Detours::Hook::InlineWrapperHook g_WaitForSingleObjectHook;
	Detours::Hook::InlineWrapperHook g_SetEventHook;
	Detours::Hook::InlineWrapperHook g_GetCurrentThreadIDHook;
	Detours::Hook::InlineWrapperHook g_BackgroundSleepHook;
	Detours::Hook::InlineWrapperHook g_InlineWrapperSelfUnHook;
	Detours::Hook::InlineWrapperHook g_InlineWrapperAPISelfUnHook;
	std::atomic<unsigned int> g_unFirstCapacityRawHookCalls = 0;
	std::atomic<unsigned int> g_unSecondCapacityRawHookCalls = 0;
	std::atomic<unsigned int> g_unRawCETRedirectCalls = 0;
#if defined(_M_X64)
	void* g_pRawHookUnwindReturnAddress = nullptr;
	std::array<void*, 16> g_arrRawHookUnwindCallStack {};
	std::size_t g_unRawHookUnwindCallStackSize = 0;
#endif
	std::atomic<LONG> g_nNestedMemoryHookEventCount = 0;
	std::atomic<LONG> g_nNestedMemoryHookInvalidCalls = 0;
	NESTED_MEMORY_HOOK_EVENT g_arrNestedMemoryHookEvents[kNestedMemoryHookEventCapacity] {};
	volatile unsigned char* g_pNestedOuterMemoryHookAddress = nullptr;
	volatile unsigned char* g_pNestedInnerMemoryHookAddress = nullptr;
	volatile unsigned char g_unNestedMemoryHookReadValue = 0;
	std::atomic<LONG> g_nVirtualBatchPreCalls = 0;
	std::atomic<LONG> g_nVirtualBatchPostCalls = 0;
	std::atomic<LONG> g_nTransactionalMemoryHookPreCalls = 0;
	std::atomic<LONG> g_nTransactionalMemoryHookPostCalls = 0;
	std::atomic<LONG> g_nDeadOwnerManualMemoryHookPostCalls = 0;
	std::atomic<unsigned int> g_unMemoryHookPreCalls = 0;
	std::atomic<unsigned int> g_unMemoryHookPostCalls = 0;
	std::atomic<LONG> g_nZeroInterruptCalls = 0;
	std::atomic<unsigned int> g_unCurrentThreadHardwareHookCalls = 0;
	std::atomic<unsigned int> g_unHardwareHookCalls = 0;
	std::atomic<unsigned int> g_unFirstThreadHardwareHookCalls = 0;
	std::atomic<unsigned int> g_unSecondThreadHardwareHookCalls = 0;
	std::atomic<unsigned int> g_unWaitForSingleObjectHookCalls = 0;
	std::atomic<unsigned int> g_unSetEventHookCalls = 0;
	std::atomic<unsigned int> g_unGetCurrentThreadIDHookCalls = 0;
	std::atomic<unsigned int> g_unBackgroundSleepHookCalls = 0;
	std::atomic<unsigned int> g_unInlineWrapperSelfUnHookCalls = 0;
	std::atomic<bool> g_bInlineWrapperSelfUnHookSucceeded = false;
	std::atomic<unsigned int> g_unInlineWrapperAPISelfUnHookCalls = 0;
	std::atomic<bool> g_bInlineWrapperAPISelfUnHookSucceeded = false;
	std::atomic<unsigned int> g_unHardwareSelfUnHookCalls = 0;
	std::atomic<unsigned int> g_unHardwareTrapFlagClearingHookCalls = 0;
	std::atomic<unsigned int> g_unMemoryHookModifyCalls = 0;
	std::atomic<unsigned int> g_unPersistentPreviousMemoryHookCalls = 0;
	std::atomic<unsigned int> g_unPersistentCurrentMemoryHookCalls = 0;
	std::atomic<unsigned int> g_unMemorySelfUnHookCalls = 0;
	std::atomic<unsigned int> g_unSecondaryMemorySelfUnHookCalls = 0;
	std::atomic<bool> g_bHardwareSelfUnHookSucceeded = false;
	std::atomic<bool> g_bMemoryHookModifyUnHookSucceeded = false;
	std::atomic<bool> g_bMemorySelfUnHookSucceeded = false;
	std::atomic<bool> g_bSecondaryMemorySelfUnHookSucceeded = false;
	void const* g_pPersistentPreviousMemoryHookAddress = nullptr;
	void const* g_pPersistentCurrentMemoryHookAddress = nullptr;

	void RecordNestedMemoryHookEvent(NESTED_MEMORY_HOOK_EVENT Event) {
		LONG const nEventIndex = g_nNestedMemoryHookEventCount.fetch_add(1, std::memory_order_relaxed);
		if ((nEventIndex >= 0) && (static_cast<std::size_t>(nEventIndex) < kNestedMemoryHookEventCapacity)) {
			g_arrNestedMemoryHookEvents[nEventIndex] = Event;
		}
	}

	void NestedMemoryHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		if (!pCTX || !pExceptionAddress || !pHookAddress || !pAccessAddress || (unOperation != Detours::Hook::MEMORY_READ)) {
			g_nNestedMemoryHookInvalidCalls.fetch_add(1, std::memory_order_relaxed);
		}

		if (pHookAddress == const_cast<unsigned char const*>(g_pNestedOuterMemoryHookAddress)) {
			RecordNestedMemoryHookEvent(NestedOuterPreBegin);
			g_unNestedMemoryHookReadValue = *g_pNestedInnerMemoryHookAddress;
			RecordNestedMemoryHookEvent(NestedOuterPreEnd);
		} else if (pHookAddress == const_cast<unsigned char const*>(g_pNestedInnerMemoryHookAddress)) {
			RecordNestedMemoryHookEvent(NestedInnerPre);
		} else {
			g_nNestedMemoryHookInvalidCalls.fetch_add(1, std::memory_order_relaxed);
		}
	}

	void NestedPostMemoryHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		if (!pCTX || !pExceptionAddress || !pHookAddress || !pAccessAddress || (unOperation != Detours::Hook::MEMORY_READ)) {
			g_nNestedMemoryHookInvalidCalls.fetch_add(1, std::memory_order_relaxed);
		}

		if (pHookAddress == const_cast<unsigned char const*>(g_pNestedOuterMemoryHookAddress)) {
			RecordNestedMemoryHookEvent(NestedOuterPost);
		} else if (pHookAddress == const_cast<unsigned char const*>(g_pNestedInnerMemoryHookAddress)) {
			RecordNestedMemoryHookEvent(NestedInnerPost);
		} else {
			g_nNestedMemoryHookInvalidCalls.fetch_add(1, std::memory_order_relaxed);
		}
	}

	void VirtualBatchMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		g_nVirtualBatchPreCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void VirtualBatchPostMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		g_nVirtualBatchPostCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void TransactionalMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		g_nTransactionalMemoryHookPreCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void TransactionalPostMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		g_nTransactionalMemoryHookPostCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void DeadOwnerMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		ExitThread(kDeadOwnerMemoryHookExitCode);
	}

	void DeadOwnerManualMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const* pHookAddress, void const*) {
		DWORD unPreviousProtection = 0;
		if (!VirtualProtect(const_cast<void*>(pHookAddress), 1, PAGE_READWRITE, &unPreviousProtection)) {
			ExitThread(kDeadOwnerManualMemoryHookProtectionFailureExitCode);
		}

		ExitThread(kDeadOwnerManualMemoryHookExitCode);
	}

	void DeadOwnerManualPostMemoryHook(PCONTEXT const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
		g_nDeadOwnerManualMemoryHookPostCalls.fetch_add(1, std::memory_order_relaxed);
	}

	DWORD WINAPI ReadDeadOwnerMemory(void* const pData) {
		volatile unsigned char const* const pValue = static_cast<volatile unsigned char const*>(pData);
		if (pValue) {
			*pValue;
		}

		return 1;
	}

	__declspec(noinline) bool TryReadTransactionalMemory(volatile unsigned char const* const pAddress, unsigned char* const pValue) noexcept {
		if (!pAddress || !pValue) {
			return false;
		}

		__try {
			*pValue = *pAddress;
			return true;
		} __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			return false;
		}
	}

	bool ZeroInterruptHook(PCONTEXT const pCTX, unsigned char const unInterrupt) {
		if (!pCTX || unInterrupt) {
			return false;
		}

		g_nZeroInterruptCalls.fetch_add(1, std::memory_order_relaxed);
		return true;
	}

	bool DeadOwnerInterruptHook(PCONTEXT const, unsigned char const unInterrupt) {
		if (unInterrupt != 0x7E) {
			return false;
		}

		ExitThread(kDeadOwnerInterruptHookExitCode);
	}

	bool RetireInterruptSnapshotHook(PCONTEXT const, unsigned char const) {
		return false;
	}

	DWORD WINAPI InvokeDeadOwnerInterrupt(void*) {
#if defined(_M_X64)
		CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#elif defined(_M_IX86)
		CallInterrupt(1, 2, 3, 4, 5, 6, 7);
#endif
		return 1;
	}

	int __cdecl VTableRollbackOriginal() {
		return 17;
	}

	int __cdecl VTableRollbackReplacement() {
		return 29;
	}

	int __cdecl InlineProtectionReplacement() {
		return static_cast<int>(kInlineProtectionHookValue);
	}

	__declspec(noinline) unsigned int __cdecl FirstRawCapacityTarget(unsigned int unValue) {
		volatile unsigned int unResult = unValue + kFirstRawCapacityOffset;
		return unResult;
	}

	__declspec(noinline) unsigned int __cdecl SecondRawCapacityTarget(unsigned int unValue) {
		volatile unsigned int unResult = unValue + kSecondRawCapacityOffset;
		return unResult;
	}

#if defined(_M_X64)
	bool __fastcall FirstRawCapacityHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl FirstRawCapacityHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_unFirstCapacityRawHookCalls.fetch_add(1, std::memory_order_relaxed);
		g_FirstCapacityRawHook.CallTrampoline(pCTX);
		return true;
	}

#if defined(_M_X64)
	bool __fastcall SecondRawCapacityHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl SecondRawCapacityHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_unSecondCapacityRawHookCalls.fetch_add(1, std::memory_order_relaxed);
		g_SecondCapacityRawHook.CallTrampoline(pCTX);
		return true;
	}

	__declspec(noinline) unsigned int __cdecl RawCETTransitionTarget() {
		volatile unsigned int unResult = kRawCETOriginalValue;
		return unResult;
	}

	__declspec(noinline) unsigned int __cdecl RawCETRedirectTarget() {
		g_unRawCETRedirectCalls.fetch_add(1, std::memory_order_relaxed);
		volatile unsigned int unResult = kRawCETRedirectValue;
		return unResult;
	}

#if defined(_M_X64)
	bool __fastcall RawCETSingleRedirectHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl RawCETSingleRedirectHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		if (!pCTX) {
			return false;
		}

		pCTX->m_Stack.Push(RawCETRedirectTarget);
		return true;
	}

#if defined(_M_X64)
	bool __fastcall RawCETUnsupportedRedirectHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl RawCETUnsupportedRedirectHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		if (!pCTX) {
			return false;
		}

#if defined(_M_X64)
		pCTX->m_unRAX = kRawCETFailSafeValue;
#elif defined(_M_IX86)
		pCTX->m_unEAX = kRawCETFailSafeValue;
#endif
		pCTX->m_Stack.Push(RawCETRedirectTarget);
		pCTX->m_Stack.Push(RawCETRedirectTarget);
		return true;
	}

#if defined(_M_X64)
	__declspec(noinline) bool __fastcall ThrowingRawHook(Detours::Hook::PRAW_CONTEXT) {
		g_pRawHookUnwindReturnAddress = _ReturnAddress();
		std::vector<void*> const vecCallStack = Detours::CallStack::GetCallStack(GetCurrentThread(), 16);
		g_unRawHookUnwindCallStackSize = std::min(vecCallStack.size(), g_arrRawHookUnwindCallStack.size());
		std::copy_n(vecCallStack.begin(), g_unRawHookUnwindCallStackSize, g_arrRawHookUnwindCallStack.begin());
		throw kRawHookUnwindExceptionValue;
	}
#endif

	__declspec(noinline) unsigned int __cdecl RawStackProbeTarget() {
		volatile unsigned int unResult = kRawStackProbeOriginalValue;
		return unResult;
	}

#if defined(_M_X64)
	bool __fastcall RawStackProbeHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl RawStackProbeHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		if (!pCTX) {
			return false;
		}

#if defined(_M_X64)
		pCTX->m_unRAX = kRawStackProbeHookValue;
#elif defined(_M_IX86)
		pCTX->m_unEAX = kRawStackProbeHookValue;
#endif
		return true;
	}

	[[noreturn]] static VOID WINAPI RawStackProbeFiber(void* const pParameter) noexcept {
		PRAW_STACK_PROBE_FIBER_DATA const pData = static_cast<PRAW_STACK_PROBE_FIBER_DATA>(pParameter);
		if (!pData || !pData->m_pMainFiber || !pData->m_pTarget) {
			ExitProcess(EXIT_FAILURE);
		}

		pData->m_unResult = pData->m_pTarget();
		pData->m_bCompleted = true;
		SwitchToFiber(pData->m_pMainFiber);
		ExitProcess(EXIT_FAILURE);
	}

	static bool RunWindowsRawStackProbeFiberScenario() noexcept {
		Detours::Hook::RawHook Hook;
		if (!Hook.Set(reinterpret_cast<void*>(RawStackProbeTarget))) {
			return false;
		}

		auto HookCleanup = MakeScopeExit([&Hook]() {
			Hook.UnHook();
			Hook.Release();
		});
		if (!Hook.Hook(RawStackProbeHook, true, kRawStackProbeReservedStackSize, false)) {
			return false;
		}

		void* const pMainFiber = ConvertThreadToFiber(nullptr);
		if (!pMainFiber) {
			return false;
		}

		bool bMainFiberActive = true;
		auto MainFiberCleanup = MakeScopeExit([&bMainFiberActive]() {
			if (bMainFiberActive) {
				ConvertFiberToThread();
			}
		});

		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		if (!SystemInfo.dwPageSize) {
			return false;
		}

		RAW_STACK_PROBE_FIBER_DATA FiberData {};
		FiberData.m_pMainFiber = pMainFiber;
		FiberData.m_pTarget = RawStackProbeTarget;
		void* pProbeFiber = CreateFiberEx(static_cast<SIZE_T>(SystemInfo.dwPageSize), static_cast<SIZE_T>(kRawStackProbeFiberReserveSize), 0, RawStackProbeFiber, &FiberData);
		if (!pProbeFiber) {
			return false;
		}

		auto ProbeFiberCleanup = MakeScopeExit([&pProbeFiber]() {
			if (pProbeFiber) {
				DeleteFiber(pProbeFiber);
				pProbeFiber = nullptr;
			}
		});

		SwitchToFiber(pProbeFiber);
		bool const bFiberSucceeded =
			FiberData.m_bCompleted &&
			(FiberData.m_unResult == kRawStackProbeHookValue);
		DeleteFiber(pProbeFiber);
		pProbeFiber = nullptr;
		ProbeFiberCleanup.Release();

		bool const bConvertedToThread = ConvertFiberToThread() != FALSE;
		if (bConvertedToThread) {
			bMainFiberActive = false;
			MainFiberCleanup.Release();
		}

		bool const bUnHooked = Hook.UnHook();
		bool const bReleased = Hook.Release();
		if (bReleased) {
			HookCleanup.Release();
		}

		return bFiberSucceeded && bConvertedToThread && bUnHooked && bReleased;
	}

	__declspec(noinline) unsigned int __cdecl RawStackValidationTarget(std::uintptr_t, std::uintptr_t) {
		volatile unsigned int unResult = kRawCETOriginalValue;
		return unResult;
	}

	[[noreturn]] static void RawStackValidationFailureTarget() noexcept {
		ExitProcess(kRawStackValidationFailureExitCode);
	}

	static void SetRawStackValidationResult(Detours::Hook::PRAW_CONTEXT pCTX) noexcept {
#if defined(_M_X64)
		pCTX->m_unRAX = kRawCETFailSafeValue;
#elif defined(_M_IX86)
		pCTX->m_unEAX = kRawCETFailSafeValue;
#endif
	}

#if defined(_M_X64)
	bool __fastcall RawStackGapBelowEntryHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl RawStackGapBelowEntryHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		if (!pCTX || !pCTX->m_Stack.GetAddress()) {
			return false;
		}

		void* pReturnAddress = nullptr;
		std::memcpy(&pReturnAddress, pCTX->m_Stack.GetAddress(), sizeof(pReturnAddress));
		SetRawStackValidationResult(pCTX);
		pCTX->m_Stack.Push(pReturnAddress);
		pCTX->m_Stack.Push(RawStackValidationFailureTarget);
		return true;
	}

#if defined(_M_X64)
	bool __fastcall RawStackAboveEntryHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl RawStackAboveEntryHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		if (!pCTX || !pCTX->m_Stack.GetAddress()) {
			return false;
		}

		static_assert(
			sizeof(&RawStackValidationFailureTarget) == sizeof(void*),
			"RawHook stack fixtures require code and data pointers with equal size");
		unsigned char* const pEntryStack = static_cast<unsigned char*>(pCTX->m_Stack.GetAddress());
		void* pReturnAddress = nullptr;
		decltype(&RawStackValidationFailureTarget) pFailureTarget = &RawStackValidationFailureTarget;
		std::memcpy(&pReturnAddress, pEntryStack, sizeof(pReturnAddress));
		std::memcpy(pEntryStack + sizeof(void*), &pFailureTarget, sizeof(pFailureTarget));
		std::memcpy(pEntryStack + (sizeof(void*) * 2), &pReturnAddress, sizeof(pReturnAddress));
		SetRawStackValidationResult(pCTX);
		pCTX->m_Stack.SetAddress(pEntryStack + sizeof(void*));
		return true;
	}

	static bool RunWindowsRawStackValidationScenario(Detours::Hook::fnRawHookCallBack pCallBack) noexcept {
		if (!pCallBack) {
			return false;
		}

		Detours::Hook::RawHook Hook;
		if (!Hook.Set(reinterpret_cast<void*>(RawStackValidationTarget))) {
			return false;
		}

		auto HookCleanup = MakeScopeExit([&Hook]() {
			Hook.UnHook();
			Hook.Release();
		});
		if (!Hook.Hook(pCallBack, false, kRawCETReservedStackSize, true)) {
			return false;
		}

		using fnRawStackValidationTarget = unsigned int(__cdecl*)(std::uintptr_t, std::uintptr_t);
		fnRawStackValidationTarget volatile pTarget = RawStackValidationTarget;
		if (pTarget(1, 2) != kRawCETFailSafeValue) {
			return false;
		}

		if (!Hook.UnHook() || !Hook.Release()) {
			return false;
		}

		HookCleanup.Release();
		return true;
	}

	DWORD WINAPI CaptureWindowsDebugContextThread(LPVOID pParameter) noexcept {
		PWINDOWS_DEBUG_CONTEXT_REQUEST const pRequest = static_cast<PWINDOWS_DEBUG_CONTEXT_REQUEST>(pParameter);
		if (!pRequest || !pRequest->m_hThread || (pRequest->m_hThread == INVALID_HANDLE_VALUE)) {
			return ERROR_INVALID_PARAMETER;
		}

		if (SuspendThread(pRequest->m_hThread) == static_cast<DWORD>(-1)) {
			return GetLastError();
		}

		pRequest->m_bSuspendSucceeded = true;

		pRequest->m_Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		pRequest->m_bGetContextSucceeded = GetThreadContext(pRequest->m_hThread, &pRequest->m_Context) != FALSE;
		pRequest->m_bResumeSucceeded = RetryTestCleanup([pRequest]() {
			return ResumeThread(pRequest->m_hThread) != static_cast<DWORD>(-1);
		});
		if (!pRequest->m_bResumeSucceeded) {
			std::abort();
		}

		return (pRequest->m_bGetContextSucceeded && pRequest->m_bResumeSucceeded) ? ERROR_SUCCESS : ERROR_FUNCTION_FAILED;
	}

	bool CaptureCurrentWindowsDebugContext(CONTEXT* const pCTX) noexcept {
		if (!pCTX) {
			return false;
		}

		WINDOWS_DEBUG_CONTEXT_REQUEST Request {};
		Request.m_hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, GetCurrentThreadId());
		if (!Request.m_hThread || (Request.m_hThread == INVALID_HANDLE_VALUE)) {
			return false;
		}

		HANDLE hHelperThread = CreateThread(nullptr, 0, CaptureWindowsDebugContextThread, &Request, 0, nullptr);
		if (!hHelperThread || (hHelperThread == INVALID_HANDLE_VALUE)) {
			CloseHandle(Request.m_hThread);
			return false;
		}

		bool const bHelperCompleted = WaitForSingleObject(hHelperThread, INFINITE) == WAIT_OBJECT_0;
		CloseHandle(hHelperThread);
		CloseHandle(Request.m_hThread);
		if (!bHelperCompleted || !Request.m_bSuspendSucceeded ||
			!Request.m_bGetContextSucceeded || !Request.m_bResumeSucceeded) {
			return false;
		}

		*pCTX = Request.m_Context;
		return true;
	}

	void CountCurrentThreadHardwareHook(PCONTEXT const pCTX) noexcept {
		UNREFERENCED_PARAMETER(pCTX);

		g_unCurrentThreadHardwareHookCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void ClearHardwareHookTrapFlag(PCONTEXT const pCTX) noexcept {
		if (pCTX) {
			pCTX->EFlags &= ~kDebugRegisterTrapFlagMask;
		}

		g_unHardwareTrapFlagClearingHookCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void HardwareHook(PCONTEXT const pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		g_unHardwareHookCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[HardwareHook] Mem access! TID=%lu\n"), GetCurrentThreadId());
	}

	void FirstThreadHardwareHook(PCONTEXT const pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		g_unFirstThreadHardwareHookCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void SecondThreadHardwareHook(PCONTEXT const pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		g_unSecondThreadHardwareHookCalls.fetch_add(1, std::memory_order_relaxed);
	}

	void DeadOwnerHardwareHook(PCONTEXT const) {
		ExitThread(kDeadOwnerHardwareHookExitCode);
	}

	void HardwareSelfUnHook(PCONTEXT const pCTX) {
		UNREFERENCED_PARAMETER(pCTX);

		g_unHardwareSelfUnHookCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[HardwareSelfUnHook] Mem access! TID=%lu\n"), GetCurrentThreadId());

		g_bHardwareSelfUnHookSucceeded.store(
			Detours::Hook::UnHookHardware(GetCurrentThreadId(), Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0),
			std::memory_order_relaxed);
	}

	DWORD WINAPI ThreadAccessor(LPVOID pParameter) {
		static_cast<unsigned int*>(pParameter)[0] = 4;
		return 0;
	}

	DWORD WINAPI AccessDeadOwnerHardwareMemory(void* const pData) {
		volatile unsigned char* const pValue = static_cast<volatile unsigned char*>(pData);
		if (pValue) {
			*pValue = static_cast<unsigned char>(*pValue + 1);
		}

		return 1;
	}

	DWORD WINAPI AtomicThreadAccessorLoop(LPVOID pParameter) {
		static_assert(std::atomic<unsigned int>::is_always_lock_free, "Hardware hook test requires lock-free atomic access");
		static_assert(sizeof(std::atomic<unsigned int>) == sizeof(unsigned int), "Hardware hook test requires a 32-bit atomic value");

		std::atomic<unsigned int>* const pValue = static_cast<std::atomic<unsigned int>*>(pParameter);
		if (!pValue) {
			return 1;
		}

		for (std::size_t unAccess = 0; unAccess < kThreadAccessorLoopCount; ++unAccess) {
			for (std::size_t unIteration = 0; unIteration < kThreadAccessorPauseCount; ++unIteration) {
				_mm_pause();
			}

			pValue->store(4, std::memory_order_relaxed);
		}

		return 0;
	}

	DWORD WINAPI ThreadRangeAccessor(LPVOID pParameter) {
		static_cast<unsigned int*>(pParameter)[0] = 0xDEEDBEEF;
		static_cast<unsigned int*>(pParameter)[1] = 0xDEEDFACE;
		static_cast<unsigned int*>(pParameter)[2] = 0xFACE;
		return 0;
	}

	DWORD WINAPI ThreadRangeAccessorLoop(LPVOID pParameter) {
		ThreadRangeAccessorLoopData* const pData = static_cast<ThreadRangeAccessorLoopData*>(pParameter);
		if (!pData || !pData->m_pAddress || !pData->m_unValueCount ||
			(pData->m_unValueCount > kThreadRangeAccessorValueCapacity)) {
			return 1;
		}

		for (std::size_t unAccess = 0; unAccess < kThreadAccessorLoopCount; ++unAccess) {
			for (std::size_t unIteration = 0; unIteration < kThreadAccessorPauseCount; ++unIteration) {
				_mm_pause();
			}

			for (std::size_t unIndex = 0; unIndex < pData->m_unValueCount; ++unIndex) {
				pData->m_pAddress[unIndex] = pData->m_arrValues[unIndex];
			}
		}

		return 0;
	}

	void MemoryHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);

		g_unMemoryHookPreCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[MemoryHook] Mem access! TID=%lu Addr=%p\n"), GetCurrentThreadId(), pAccessAddress);
	}

	void PostMemoryHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pHookAddress);

		g_unMemoryHookPostCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[PostMemoryHook] Mem access! TID=%lu Addr=%p\n"), GetCurrentThreadId(), pAccessAddress);
	}

	void MemoryHookSelfUnHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pAccessAddress);

		g_unMemorySelfUnHookCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[MemoryHookSelfUnHook] Mem access! TID=%lu\n"), GetCurrentThreadId());

		g_bMemorySelfUnHookSucceeded.store(
			Detours::Hook::UnHookMemory(MemoryHookSelfUnHook, const_cast<void*>(pHookAddress)),
			std::memory_order_relaxed);
	}

	void SecondaryMemoryHookSelfUnHook(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pCTX);
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pAccessAddress);

		g_unSecondaryMemorySelfUnHookCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[SecondaryMemoryHookSelfUnHook] Mem access! TID=%lu\n"), GetCurrentThreadId());

		g_bSecondaryMemorySelfUnHookSucceeded.store(
			Detours::Hook::UnHookMemory(SecondaryMemoryHookSelfUnHook, const_cast<void*>(pHookAddress)),
			std::memory_order_relaxed);
	}

	void MemoryHookModify(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pAccessAddress);

		g_unMemoryHookModifyCalls.fetch_add(1, std::memory_order_relaxed);
		_tprintf_s(_T("[MemoryHookModify] Mem access! TID=%lu\n"), GetCurrentThreadId());

		static int s_nDummy = 0;

#if defined(_M_X64)
		pCTX->Rax = reinterpret_cast<DWORD64>(&s_nDummy);
#elif defined(_M_IX86)
		pCTX->Eax = reinterpret_cast<DWORD>(&s_nDummy);
#endif

		g_bMemoryHookModifyUnHookSucceeded.store(
			Detours::Hook::UnHookMemory(MemoryHookModify, const_cast<void*>(pHookAddress)),
			std::memory_order_relaxed);
	}

	void PersistentMemoryHookModify(PCONTEXT const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pHookAddress, void const* pAccessAddress) {
		UNREFERENCED_PARAMETER(pExceptionAddress);
		UNREFERENCED_PARAMETER(unOperation);
		UNREFERENCED_PARAMETER(pAccessAddress);

		if (pHookAddress == g_pPersistentPreviousMemoryHookAddress) {
			g_unPersistentPreviousMemoryHookCalls.fetch_add(1, std::memory_order_relaxed);
		} else if (pHookAddress == g_pPersistentCurrentMemoryHookAddress) {
			g_unPersistentCurrentMemoryHookCalls.fetch_add(1, std::memory_order_relaxed);
		}

		_tprintf_s(_T("[PersistentMemoryHookModify] Mem access! TID=%lu\n"), GetCurrentThreadId());

		static int s_nDummy = 0;

#if defined(_M_X64)
		pCTX->Rax = reinterpret_cast<DWORD64>(&s_nDummy);
#elif defined(_M_IX86)
		pCTX->Eax = reinterpret_cast<DWORD>(&s_nDummy);
#endif
	}

	bool InterruptHook(PCONTEXT const pCTX, unsigned char const unInterrupt) {
		_tprintf_s(_T("[InterruptHook] Called `int 0x%02X`\n"), unInterrupt);
#if defined(_M_X64)
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
#elif defined(_M_IX86)
		_tprintf_s(_T("  -> EAX = 0x%08X\n"), pCTX->Eax);
		_tprintf_s(_T("  -> ECX = 0x%08X\n"), pCTX->Ecx);
		_tprintf_s(_T("  -> EDX = 0x%08X\n"), pCTX->Edx);
		_tprintf_s(_T("  -> EBX = 0x%08X\n"), pCTX->Ebx);
		_tprintf_s(_T("  -> EBP = 0x%08X\n"), pCTX->Ebp);
		_tprintf_s(_T("  -> ESI = 0x%08X\n"), pCTX->Esi);
		_tprintf_s(_T("  -> EDI = 0x%08X\n"), pCTX->Edi);
#endif

#if defined(_M_X64)
		pCTX->Rax = kInterruptHookReturnValue;
#elif defined(_M_IX86)
		pCTX->Eax = kInterruptHookReturnValue;
#endif

		return true;
	}

	bool __fastcall FooHook(void* pThis, void* /* unused */) {
		using fnFoo = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnFoo>(g_FooHook.GetOriginal())(pThis, nullptr);
	}

	bool __fastcall BooHook(void* pThis, void* /* unused */) {
		using fnBoo = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnBoo>(g_BooHook.GetOriginal())(pThis, nullptr);
	}

	bool __fastcall VTableBooHook(void* pThis, void* /* unused */) {
		using fnBoo = bool(__fastcall*)(void*, void*);
		return !reinterpret_cast<fnBoo>(g_TestingRTTIVTableHook.GetHookingFunctions()[1]->GetOriginal())(pThis, nullptr);
	}

	void WINAPI SleepHook(DWORD unMilliseconds) {
		g_bInlineSleepHookCalled = true;
		using fnSleep = void(WINAPI*)(DWORD);
		return reinterpret_cast<fnSleep>(g_InlineSleepHook.GetTrampoline())(unMilliseconds);
	}

	DWORD WINAPI WaitForSingleObjectHook(HANDLE hObject, DWORD unMilliseconds) {
		g_unWaitForSingleObjectHookCalls.fetch_add(1, std::memory_order_relaxed);
		using fnWaitForSingleObject = DWORD(WINAPI*)(HANDLE, DWORD);
		return reinterpret_cast<fnWaitForSingleObject>(g_WaitForSingleObjectHook.GetTrampoline())(hObject, unMilliseconds);
	}

	BOOL WINAPI SetEventHook(HANDLE hEvent) {
		g_unSetEventHookCalls.fetch_add(1, std::memory_order_relaxed);
		using fnSetEvent = BOOL(WINAPI*)(HANDLE);
		return reinterpret_cast<fnSetEvent>(g_SetEventHook.GetTrampoline())(hEvent);
	}

	DWORD WINAPI GetCurrentThreadIDHook() {
		g_unGetCurrentThreadIDHookCalls.fetch_add(1, std::memory_order_relaxed);
		using fnGetCurrentThreadID = DWORD(WINAPI*)();
		return reinterpret_cast<fnGetCurrentThreadID>(g_GetCurrentThreadIDHook.GetTrampoline())();
	}

	void WINAPI BackgroundSleepHook(DWORD unMilliseconds) {
		g_unBackgroundSleepHookCalls.fetch_add(1, std::memory_order_relaxed);
		using fnSleep = void(WINAPI*)(DWORD);
		return reinterpret_cast<fnSleep>(g_BackgroundSleepHook.GetTrampoline())(unMilliseconds);
	}

	__declspec(noinline) double __cdecl InlineWrapperSelfUnHookTarget(unsigned int unFirst, unsigned int unSecond, unsigned int unThird, unsigned int unFourth, unsigned int unFifth, unsigned int unSixth, double flFirst, double flSecond) {
		return static_cast<double>(
			unFirst + unSecond + unThird + unFourth + unFifth + unSixth) +
			flFirst + flSecond;
	}

	__declspec(noinline) bool AttemptInlineWrapperSelfUnHook(std::size_t const unDepth) {
		volatile std::size_t unStackMarker = unDepth + 1;
		bool const bResult = unDepth ? AttemptInlineWrapperSelfUnHook(unDepth - 1) : g_InlineWrapperSelfUnHook.UnHook();
		unStackMarker ^= 1;
		return bResult && (unStackMarker != 0);
	}

	__declspec(noinline) double __cdecl InlineWrapperSelfUnHook(unsigned int unFirst, unsigned int unSecond, unsigned int unThird, unsigned int unFourth, unsigned int unFifth, unsigned int unSixth, double flFirst, double flSecond) {
		g_unInlineWrapperSelfUnHookCalls.fetch_add(1, std::memory_order_relaxed);
		g_bInlineWrapperSelfUnHookSucceeded.store(AttemptInlineWrapperSelfUnHook(kInlineWrapperSelfUnHookDepth), std::memory_order_release);

		using fnTarget = double(__cdecl*)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, double, double);
		fnTarget const pTrampoline = reinterpret_cast<fnTarget>(g_InlineWrapperSelfUnHook.GetTrampoline());
		if (!pTrampoline) {
			return 0.0;
		}

		return pTrampoline(unFirst, unSecond, unThird, unFourth, unFifth, unSixth, flFirst, flSecond) + 1.0;
	}

	BOOL WINAPI InlineWrapperAPISelfUnHook(HANDLE hProcess, LPCVOID pBaseAddress, LPVOID pBuffer, SIZE_T unSize, SIZE_T* pBytesRead) {
		g_unInlineWrapperAPISelfUnHookCalls.fetch_add(1, std::memory_order_relaxed);
		g_bInlineWrapperAPISelfUnHookSucceeded.store(g_InlineWrapperAPISelfUnHook.UnHook(), std::memory_order_release);

		using fnReadProcessMemory = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
		fnReadProcessMemory const pTrampoline = reinterpret_cast<fnReadProcessMemory>(g_InlineWrapperAPISelfUnHook.GetTrampoline());
		return pTrampoline && pTrampoline(hProcess, pBaseAddress, pBuffer, unSize, pBytesRead);
	}

#if defined(_M_X64)
	bool __fastcall SleepRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl SleepRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_bRawSleepHookCalled = true;
		g_RawSleepHook.CallTrampoline(pCTX);
		return true;
	}

#if defined(_M_X64)
	bool __fastcall SleepRawHookConcurrent(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl SleepRawHookConcurrent(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_unRawSleepConcurrentCalls.fetch_add(1, std::memory_order_relaxed);
		g_RawSleepConcurrentHook.CallTrampoline(pCTX);
		return true;
	}

#if defined(_M_X64)
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
#elif defined(_M_IX86)
	__declspec(noinline) unsigned int __fastcall CallAddressStandaloneTarget(unsigned int unValue) {
		return unValue + 0x1234;
	}

	__declspec(noinline) unsigned int __stdcall CallAddressStandaloneStackTarget(unsigned int unValue) {
		return unValue + 0x2345;
	}
#endif

#if defined(_M_X64)
	bool __fastcall SleepRawHookModified(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl SleepRawHookModified(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif
		g_bRawSleepHookCalled = true;

		g_LastXMM7 = pCTX->m_XMM7;
		pCTX->m_XMM7.m_un64[0] = 0x1122334455667788;
		pCTX->m_XMM7.m_un64[1] = 0x1122334455667788;

		g_RawSleepHook.CallAddress(g_RawSleepHook.GetTrampoline(), pCTX);
		return true;
	}

#if defined(_M_X64)
	bool __fastcall NewFoo(void* pThis) {
#elif defined(_M_IX86)
	bool __fastcall NewFoo(void* pThis) {
#endif

#if defined(_M_X64)
		_tprintf_s(_T("[NewFoo] pThis = 0x%016llX\n"), reinterpret_cast<unsigned long long>(pThis));
#elif defined(_M_IX86)
		_tprintf_s(_T("[NewFoo] pThis = 0x%08X\n"), reinterpret_cast<unsigned int>(pThis));
#endif

		return false;
	}

#if defined(_M_X64)
	bool __fastcall CallConventionRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl CallConventionRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif

		// Convert __thiscall to __fastcall and redirect it.

		pCTX->m_Stack.Push(NewFoo);

		return true;
	}

#if defined(_M_X64)
	bool __fastcall CPUIDRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#elif defined(_M_IX86)
	bool __cdecl CPUIDRawHook(Detours::Hook::PRAW_CONTEXT pCTX) {
#endif

		pCTX->m_unEAX = 0x00000001;
		pCTX->m_unEBX = 0x11223344;
		pCTX->m_unECX = 0x00000003;
		pCTX->m_unEDX = 0x00000004;
		pCTX->m_Stack.Push(reinterpret_cast<char*>(g_RawCPUIDHook.GetTrampoline()) + g_RawCPUIDHook.GetFirstInstructionSize());

		return true;
	}

	TEST_CASE("HardwareHook updates and restores the current thread debug register") {
		alignas(sizeof(unsigned int)) volatile unsigned int unWatchedValue = 0;
		CONTEXT ContextBefore {};
		REQUIRE(CaptureCurrentWindowsDebugContext(&ContextBefore));
		REQUIRE((ContextBefore.Dr7 & kDebugRegisterZeroSlotMask) == 0);

		DWORD const unCurrentTID = GetCurrentThreadId();
		g_unCurrentThreadHardwareHookCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, CountCurrentThreadHardwareHook, const_cast<unsigned int*>(&unWatchedValue), Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_WRITE, sizeof(unWatchedValue)) == true);
		auto HookCleanup = MakeScopeExit([unCurrentTID]() {
			Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		unWatchedValue = 0x12345678;
		CHECK(g_unCurrentThreadHardwareHookCalls.load(std::memory_order_relaxed) == 1);

		REQUIRE(Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0) == true);
		HookCleanup.Release();

		CONTEXT ContextAfter {};
		REQUIRE(CaptureCurrentWindowsDebugContext(&ContextAfter));
		CHECK(ContextAfter.Dr0 == ContextBefore.Dr0);
		CHECK((ContextAfter.Dr7 & kDebugRegisterZeroSlotMask) == (ContextBefore.Dr7 & kDebugRegisterZeroSlotMask));

		unsigned int const unCallCount = g_unCurrentThreadHardwareHookCalls.load(std::memory_order_relaxed);
		unWatchedValue = 0x87654321;
		CHECK(g_unCurrentThreadHardwareHookCalls.load(std::memory_order_relaxed) == unCallCount);
		CHECK(unWatchedValue == 0x87654321);
	}

	TEST_CASE("HardwareHook preserves its internal trap flag after the callback") {
		alignas(sizeof(unsigned int)) volatile unsigned int unWatchedValue = 0;
		DWORD const unCurrentTID = GetCurrentThreadId();
		g_unHardwareTrapFlagClearingHookCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, ClearHardwareHookTrapFlag, const_cast<unsigned int*>(&unWatchedValue), Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_WRITE, sizeof(unWatchedValue)) == true);
		auto HookCleanup = MakeScopeExit([unCurrentTID]() {
			Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		unWatchedValue = 1;
		CHECK(g_unHardwareTrapFlagClearingHookCalls.load(std::memory_order_relaxed) == 1);
		Sleep(0);
		unWatchedValue = 2;
		CHECK(g_unHardwareTrapFlagClearingHookCalls.load(std::memory_order_relaxed) == 2);

		bool const bUnHooked = Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("HardwareHook 1") {
		static unsigned int s_arrHardwareHookValues[] = {
			1, 2, 3, 4, 5
		};

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);

		g_unHardwareHookCalls.store(0, std::memory_order_relaxed);
		DWORD const unCurrentTID = GetCurrentThreadId();
		DWORD unTID = 0;
		ScopedThread Thread(CreateThread(nullptr, 0, ThreadAccessor, &s_arrHardwareHookValues[3], CREATE_SUSPENDED, &unTID));
		REQUIRE(Thread.IsValid());

		REQUIRE(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &s_arrHardwareHookValues[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(s_arrHardwareHookValues[3]))) == true);
		auto CurrentHookCleanup = MakeScopeExit([unCurrentTID]() {
			Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		REQUIRE(Detours::Hook::HookHardware(unTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &s_arrHardwareHookValues[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(s_arrHardwareHookValues[3]))) == true);
		auto ThreadHookCleanup = MakeScopeExit([unTID]() {
			Detours::Hook::UnHookHardware(unTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);

		unsigned int const unCallsBeforeThreadAccess = g_unHardwareHookCalls.load(std::memory_order_relaxed);
		REQUIRE(Thread.Resume());
		REQUIRE(Thread.Wait());
		CHECK(Thread.Close() == true);
		CHECK(g_unHardwareHookCalls.load(std::memory_order_relaxed) > unCallsBeforeThreadAccess);

		bool const bThreadUnHooked = Detours::Hook::UnHookHardware(unTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bThreadUnHooked == true);
		if (bThreadUnHooked) {
			ThreadHookCleanup.Release();
		}

		bool const bCurrentThreadUnHooked = Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bCurrentThreadUnHooked == true);
		if (bCurrentThreadUnHooked) {
			CurrentHookCleanup.Release();
		}

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);
	}

	TEST_CASE("HardwareHook 2") {
		std::atomic<unsigned int> unHardwareHookValue { 4 };
		printf("unHardwareHookValue = %u\n", unHardwareHookValue.load(std::memory_order_relaxed));

		g_unHardwareHookCalls.store(0, std::memory_order_relaxed);
		g_unFirstThreadHardwareHookCalls.store(0, std::memory_order_relaxed);
		g_unSecondThreadHardwareHookCalls.store(0, std::memory_order_relaxed);
		DWORD const unCurrentTID = GetCurrentThreadId();
		DWORD unTID1 = 0;
		ScopedThread Thread1(CreateThread(nullptr, 0, AtomicThreadAccessorLoop, &unHardwareHookValue, CREATE_SUSPENDED, &unTID1));
		REQUIRE(Thread1.IsValid());

		DWORD unTID2 = 0;
		ScopedThread Thread2(CreateThread(nullptr, 0, AtomicThreadAccessorLoop, &unHardwareHookValue, CREATE_SUSPENDED, &unTID2));
		REQUIRE(Thread2.IsValid());

		REQUIRE(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareHook, &unHardwareHookValue, Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(unsigned int))) == true);
		auto CurrentHookCleanup = MakeScopeExit([unCurrentTID]() {
			Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		REQUIRE(Detours::Hook::HookHardware(unTID1, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, FirstThreadHardwareHook, &unHardwareHookValue, Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(unsigned int))) == true);
		auto Thread1HookCleanup = MakeScopeExit([unTID1]() {
			Detours::Hook::UnHookHardware(unTID1, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		REQUIRE(Detours::Hook::HookHardware(unTID2, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, SecondThreadHardwareHook, &unHardwareHookValue, Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(unsigned int))) == true);
		auto Thread2HookCleanup = MakeScopeExit([unTID2]() {
			Detours::Hook::UnHookHardware(unTID2, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		printf("unHardwareHookValue = %u\n", unHardwareHookValue.load(std::memory_order_relaxed));
		CHECK(g_unHardwareHookCalls.load(std::memory_order_relaxed) > 0);

		REQUIRE(Thread1.Resume());
		REQUIRE(Thread2.Resume());
		REQUIRE(Thread1.Wait());
		REQUIRE(Thread2.Wait());
		CHECK(Thread1.Close() == true);
		CHECK(Thread2.Close() == true);
		CHECK(g_unFirstThreadHardwareHookCalls.load(std::memory_order_relaxed) > 0);
		CHECK(g_unSecondThreadHardwareHookCalls.load(std::memory_order_relaxed) > 0);

		bool const bThread2UnHooked = Detours::Hook::UnHookHardware(unTID2, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bThread2UnHooked == true);
		if (bThread2UnHooked) {
			Thread2HookCleanup.Release();
		}

		bool const bThread1UnHooked = Detours::Hook::UnHookHardware(unTID1, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bThread1UnHooked == true);
		if (bThread1UnHooked) {
			Thread1HookCleanup.Release();
		}

		bool const bCurrentThreadUnHooked = Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		CHECK(bCurrentThreadUnHooked == true);
		if (bCurrentThreadUnHooked) {
			CurrentHookCleanup.Release();
		}

		printf("unHardwareHookValue = %u\n", unHardwareHookValue.load(std::memory_order_relaxed));
	}

	TEST_CASE("HardwareHook 3") {
		static unsigned int s_arrHardwareHookValues[] = {
			1, 2, 3, 4, 5
		};

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);

		g_unHardwareSelfUnHookCalls.store(0, std::memory_order_relaxed);
		g_bHardwareSelfUnHookSucceeded.store(false, std::memory_order_relaxed);
		DWORD const unCurrentTID = GetCurrentThreadId();
		REQUIRE(Detours::Hook::HookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0, HardwareSelfUnHook, &s_arrHardwareHookValues[3], Detours::Hook::HARDWARE_HOOK_TYPE::TYPE_ACCESS, static_cast<unsigned char>(sizeof(s_arrHardwareHookValues[3]))) == true);
		auto HookCleanup = MakeScopeExit([unCurrentTID]() {
			Detours::Hook::UnHookHardware(unCurrentTID, Detours::Hook::HARDWARE_HOOK_REGISTER::REGISTER_DR0);
		});

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);

		printf("arrHardwareHookValues[2] = %u\n", s_arrHardwareHookValues[2]);
		printf("arrHardwareHookValues[3] = %u\n", s_arrHardwareHookValues[3]);
		printf("arrHardwareHookValues[4] = %u\n", s_arrHardwareHookValues[4]);

		CHECK(g_unHardwareSelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		bool const bSelfUnHooked = g_bHardwareSelfUnHookSucceeded.load(std::memory_order_relaxed);
		CHECK(bSelfUnHooked == true);
		if (bSelfUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 1") {
		Detours::Memory::Page Page(nullptr);
		REQUIRE(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(unsigned int) * 3);
		REQUIRE(pAddress != nullptr);

		unsigned int* pArray = static_cast<unsigned int*>(pAddress);

		ScopedThread Thread(CreateThread(nullptr, 0, ThreadRangeAccessor, pArray, CREATE_SUSPENDED, nullptr));
		REQUIRE(Thread.IsValid());

		g_unMemoryHookPreCalls.store(0, std::memory_order_relaxed);
		g_unMemoryHookPostCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(unsigned int) * 3, PostMemoryHook) == true);
		auto HookCleanup = MakeScopeExit([pArray]() {
			Detours::Hook::UnHookMemory(MemoryHook, pArray);
		});
		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(unsigned int) * 3) == false);

		pArray[0] = 0xDEEDBEEF;
		pArray[1] = 0xDEEDFACE;
		pArray[2] = 0xFACE;

		REQUIRE(Thread.Resume());
		REQUIRE(Thread.Wait());
		CHECK(Thread.Close() == true);

		CHECK(pArray[0] == 0xDEEDBEEF);
		CHECK(pArray[1] == 0xDEEDFACE);
		CHECK(pArray[2] == 0xFACE);
		unsigned int const unPreCalls = g_unMemoryHookPreCalls.load(std::memory_order_relaxed);
		unsigned int const unPostCalls = g_unMemoryHookPostCalls.load(std::memory_order_relaxed);
		CHECK(unPreCalls > 0);
		CHECK(unPostCalls == unPreCalls);

		bool const bUnHooked = Detours::Hook::UnHookMemory(MemoryHook, pArray);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 2") {
		Detours::Memory::Page Page(nullptr);
		REQUIRE(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(unsigned int) * 3);
		REQUIRE(pAddress != nullptr);

		unsigned int* pArray = static_cast<unsigned int*>(pAddress);
		ThreadRangeAccessorLoopData FirstThreadData {};
		FirstThreadData.m_pAddress = pArray;
		FirstThreadData.m_unValueCount = 1;
		FirstThreadData.m_arrValues[0] = 0xDEEDBEEF;
		FirstThreadData.m_arrValues[1] = 0;
		ThreadRangeAccessorLoopData SecondThreadData {};
		SecondThreadData.m_pAddress = pArray + 1;
		SecondThreadData.m_unValueCount = 2;
		SecondThreadData.m_arrValues[0] = 0xDEEDFACE;
		SecondThreadData.m_arrValues[1] = 0xFACE;

		ScopedThread Thread1(CreateThread(nullptr, 0, ThreadRangeAccessorLoop, &FirstThreadData, CREATE_SUSPENDED, nullptr));
		REQUIRE(Thread1.IsValid());
		ScopedThread Thread2(CreateThread(nullptr, 0, ThreadRangeAccessorLoop, &SecondThreadData, CREATE_SUSPENDED, nullptr));
		REQUIRE(Thread2.IsValid());

		g_unMemoryHookPreCalls.store(0, std::memory_order_relaxed);
		g_unMemoryHookPostCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(unsigned int) * 3, PostMemoryHook) == true);
		auto HookCleanup = MakeScopeExit([pArray]() {
			Detours::Hook::UnHookMemory(MemoryHook, pArray);
		});
		CHECK(Detours::Hook::HookMemory(MemoryHook, pArray, sizeof(unsigned int) * 3) == false);

		pArray[0] = 0xDEEDBEEF;
		pArray[1] = 0xDEEDFACE;
		pArray[2] = 0xFACE;

		REQUIRE(Thread1.Resume());
		REQUIRE(Thread2.Resume());
		REQUIRE(Thread1.Wait());
		REQUIRE(Thread2.Wait());
		CHECK(Thread1.Close() == true);
		CHECK(Thread2.Close() == true);

		CHECK(pArray[0] == 0xDEEDBEEF);
		CHECK(pArray[1] == 0xDEEDFACE);
		CHECK(pArray[2] == 0xFACE);
		unsigned int const unPreCalls = g_unMemoryHookPreCalls.load(std::memory_order_relaxed);
		unsigned int const unPostCalls = g_unMemoryHookPostCalls.load(std::memory_order_relaxed);
		CHECK(unPreCalls > 0);
		CHECK(unPostCalls == unPreCalls);

		bool const bUnHooked = Detours::Hook::UnHookMemory(MemoryHook, pArray);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 3") {
		Detours::Memory::Page Page(nullptr);
		REQUIRE(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 5);
		REQUIRE(pAddress != nullptr);

		int* const pArray = static_cast<int*>(pAddress);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		g_unMemorySelfUnHookCalls.store(0, std::memory_order_relaxed);
		g_bMemorySelfUnHookSucceeded.store(false, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == true);
		auto HookCleanup = MakeScopeExit([pArray]() {
			Detours::Hook::UnHookMemory(MemoryHookSelfUnHook, pArray);
		});
		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == false);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		printf("pArray[2] = %i\n", pArray[2]);
		printf("pArray[3] = %i\n", pArray[3]);
		printf("pArray[4] = %i\n", pArray[4]);

		CHECK(g_unMemorySelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		bool const bSelfUnHooked = g_bMemorySelfUnHookSucceeded.load(std::memory_order_relaxed);
		CHECK(bSelfUnHooked == true);
		if (bSelfUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook [benchmark]" * doctest::skip(true)) {
		Detours::Memory::Region Region(nullptr, static_cast<std::size_t>(0x800000));
		REQUIRE(Region.GetRegionAddress() != nullptr);
		void* pAddress = Region.Alloc(1);
		REQUIRE(pAddress != nullptr);
		srand(time(nullptr) & 0xffffffff);
		ULONG unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 1'000'000; ++unIteration) {
			reinterpret_cast<unsigned char*>(pAddress)[0] = 1;
		}

		MESSAGE("Benchmark with 1 000 000 iterations (without hook): ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		REQUIRE(Detours::Hook::HookMemory(MemoryHook, Region.GetRegionAddress(), Region.GetRegionCapacity(), PostMemoryHook) == true);
		auto HookCleanup = MakeScopeExit([&Region]() {
			Detours::Hook::UnHookMemory(MemoryHook, Region.GetRegionAddress());
		});
		unBegin = Detours::g_KUserSharedData.SystemTime.LowPart;
		for (std::size_t unIteration = 0; unIteration < 1'000'000; ++unIteration) {
			reinterpret_cast<unsigned char*>(pAddress)[0] = 2;
		}

		MESSAGE("Benchmark with 1 000 000 iterations (with hook): ", (Detours::g_KUserSharedData.SystemTime.LowPart - unBegin) / 10000, " ms");
		bool const bUnHooked = Detours::Hook::UnHookMemory(MemoryHook, Region.GetRegionAddress());
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 4") {
		Detours::Memory::Page Page(nullptr);
		REQUIRE(Page.GetPageAddress() != nullptr);
		void* pAddress = Page.Alloc(sizeof(int) * 6);
		REQUIRE(pAddress != nullptr);

		int* const pArray = static_cast<int*>(pAddress);

		CHECK(TryRead(&pArray[0]) == 0);
		CHECK(TryRead(&pArray[3]) == 0);

		g_unMemorySelfUnHookCalls.store(0, std::memory_order_relaxed);
		g_unSecondaryMemorySelfUnHookCalls.store(0, std::memory_order_relaxed);
		g_bMemorySelfUnHookSucceeded.store(false, std::memory_order_relaxed);
		g_bSecondaryMemorySelfUnHookSucceeded.store(false, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray, sizeof(int) * 3) == true);
		auto HookCleanup = MakeScopeExit([pArray]() {
			Detours::Hook::UnHookMemory(SecondaryMemoryHookSelfUnHook, pArray + 3);
			Detours::Hook::UnHookMemory(MemoryHookSelfUnHook, pArray);
		});
		REQUIRE(Detours::Hook::HookMemory(SecondaryMemoryHookSelfUnHook, pArray + 3, sizeof(int) * 3) == true);
		CHECK(Detours::Hook::HookMemory(MemoryHookSelfUnHook, pArray + 3, sizeof(int) * 3) == false);

		CHECK(TryRead(&pArray[0]) == 0);
		CHECK(TryRead(&pArray[3]) == 0);
		CHECK(g_unMemorySelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondaryMemorySelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		bool const bFirstSelfUnHooked = g_bMemorySelfUnHookSucceeded.load(std::memory_order_relaxed);
		bool const bSecondSelfUnHooked = g_bSecondaryMemorySelfUnHookSucceeded.load(std::memory_order_relaxed);
		CHECK(bFirstSelfUnHooked == true);
		CHECK(bSecondSelfUnHooked == true);

		CHECK(TryRead(&pArray[0]) == 0);
		CHECK(TryRead(&pArray[3]) == 0);
		CHECK(g_unMemorySelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondaryMemorySelfUnHookCalls.load(std::memory_order_relaxed) == 1);
		if (bFirstSelfUnHooked && bSecondSelfUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 5") {
		void* pHookAddress = VirtualAlloc(nullptr, sizeof(int), MEM_RESERVE, PAGE_NOACCESS);
		REQUIRE(pHookAddress != nullptr);
		auto RegionCleanup = MakeScopeExit([pHookAddress]() {
			VirtualFree(pHookAddress, 0, MEM_RELEASE);
		});

		g_unMemoryHookModifyCalls.store(0, std::memory_order_relaxed);
		g_bMemoryHookModifyUnHookSucceeded.store(false, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(MemoryHookModify, pHookAddress, sizeof(int), nullptr, true) == true);
		auto HookCleanup = MakeScopeExit([pHookAddress]() {
			Detours::Hook::UnHookMemory(MemoryHookModify, pHookAddress);
		});

		CHECK(TryRead(pHookAddress) == 0);
		CHECK(g_unMemoryHookModifyCalls.load(std::memory_order_relaxed) == 1);
		bool const bSelfUnHooked = g_bMemoryHookModifyUnHookSucceeded.load(std::memory_order_relaxed);
		CHECK(bSelfUnHooked == true);
		if (bSelfUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook 6") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = SystemInfo.dwPageSize;

		Detours::Memory::Page Page(nullptr);
		REQUIRE(Page.GetPageAddress() != nullptr);

		int* pArray = reinterpret_cast<int*>(Page.GetPageAddress());

		MEMORY_BASIC_INFORMATION CurrentMemoryInfo {};
		MEMORY_BASIC_INFORMATION PreviousMemoryInfo {};
		REQUIRE(VirtualQuery(pArray, &CurrentMemoryInfo, sizeof(CurrentMemoryInfo)) == sizeof(CurrentMemoryInfo));
		REQUIRE(CurrentMemoryInfo.State == MEM_COMMIT);

		void* pPreviousByte = reinterpret_cast<BYTE*>(pArray) - 1;
		REQUIRE(VirtualQuery(pPreviousByte, &PreviousMemoryInfo, sizeof(PreviousMemoryInfo)) == sizeof(PreviousMemoryInfo));

		void* pRegion = nullptr;
		auto RegionCleanup = MakeScopeExit([&pRegion]() {
			if (pRegion) {
				VirtualFree(pRegion, 0, MEM_RELEASE);
			}
		});

		if (PreviousMemoryInfo.State == MEM_COMMIT) {
			pRegion = VirtualAlloc(nullptr, 2 * unPageSize, MEM_RESERVE, PAGE_READWRITE);
			REQUIRE(pRegion != nullptr);

			void* pCommit = VirtualAlloc(static_cast<BYTE*>(pRegion) + unPageSize, unPageSize, MEM_COMMIT, PAGE_READWRITE);
			REQUIRE(pCommit != nullptr);

			pArray = static_cast<int*>(pCommit);

			REQUIRE(VirtualQuery(pArray, &CurrentMemoryInfo, sizeof(CurrentMemoryInfo)) == sizeof(CurrentMemoryInfo));
			REQUIRE(CurrentMemoryInfo.State == MEM_COMMIT);

			pPreviousByte = static_cast<BYTE*>(pCommit) - 1;
			REQUIRE(VirtualQuery(pPreviousByte, &PreviousMemoryInfo, sizeof(PreviousMemoryInfo)) == sizeof(PreviousMemoryInfo));
			REQUIRE(PreviousMemoryInfo.State != MEM_COMMIT);
		} else {
			REQUIRE(PreviousMemoryInfo.State != MEM_COMMIT);
		}

		void* pPreviousHookAddress = reinterpret_cast<BYTE*>(pArray) - sizeof(int);
		g_unPersistentPreviousMemoryHookCalls.store(0, std::memory_order_relaxed);
		g_unPersistentCurrentMemoryHookCalls.store(0, std::memory_order_relaxed);
		g_pPersistentPreviousMemoryHookAddress = pPreviousHookAddress;
		g_pPersistentCurrentMemoryHookAddress = pArray;
		auto HookStateCleanup = MakeScopeExit([]() {
			g_pPersistentPreviousMemoryHookAddress = nullptr;
			g_pPersistentCurrentMemoryHookAddress = nullptr;
		});
		REQUIRE(Detours::Hook::HookMemory(PersistentMemoryHookModify, pPreviousHookAddress, sizeof(int), nullptr, true) == true);
		auto PreviousHookCleanup = MakeScopeExit([pPreviousHookAddress]() {
			Detours::Hook::UnHookMemory(PersistentMemoryHookModify, pPreviousHookAddress);
		});

		REQUIRE(Detours::Hook::HookMemory(PersistentMemoryHookModify, pArray, sizeof(int), nullptr, false) == true);
		auto CurrentHookCleanup = MakeScopeExit([pArray]() {
			Detours::Hook::UnHookMemory(PersistentMemoryHookModify, pArray);
		});

		CHECK(TryRead(pPreviousHookAddress) == 0);
		CHECK(TryRead(pArray) == 0);
		CHECK(g_unPersistentPreviousMemoryHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unPersistentCurrentMemoryHookCalls.load(std::memory_order_relaxed) == 1);

		bool const bCurrentUnHooked = Detours::Hook::UnHookMemory(PersistentMemoryHookModify, pArray);
		CHECK(bCurrentUnHooked == true);
		if (bCurrentUnHooked) {
			CurrentHookCleanup.Release();
		}

		bool const bPreviousUnHooked = Detours::Hook::UnHookMemory(PersistentMemoryHookModify, pPreviousHookAddress);
		CHECK(bPreviousUnHooked == true);
		if (bPreviousUnHooked) {
			PreviousHookCleanup.Release();
		}

		if (pRegion) {
			bool const bRegionReleased = VirtualFree(pRegion, 0, MEM_RELEASE) != FALSE;
			CHECK(bRegionReleased == true);
			if (bRegionReleased) {
				pRegion = nullptr;
				RegionCleanup.Release();
			}
		} else {
			RegionCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook preserves nested frames and post ordering") {
		Detours::Memory::Page OuterPage;
		Detours::Memory::Page InnerPage;
		volatile unsigned char* const pOuterValue = static_cast<volatile unsigned char*>(OuterPage.Alloc(1));
		volatile unsigned char* const pInnerValue = static_cast<volatile unsigned char*>(InnerPage.Alloc(1));
		REQUIRE(const_cast<unsigned char*>(pOuterValue) != nullptr);
		REQUIRE(const_cast<unsigned char*>(pInnerValue) != nullptr);
		*pOuterValue = 0x5A;
		*pInnerValue = 0xA5;

		g_pNestedOuterMemoryHookAddress = pOuterValue;
		g_pNestedInnerMemoryHookAddress = pInnerValue;
		g_unNestedMemoryHookReadValue = 0;
		g_nNestedMemoryHookEventCount.store(0, std::memory_order_relaxed);
		g_nNestedMemoryHookInvalidCalls.store(0, std::memory_order_relaxed);
		std::memset(g_arrNestedMemoryHookEvents, 0, sizeof(g_arrNestedMemoryHookEvents));

		REQUIRE(Detours::Hook::HookMemory(NestedMemoryHook, const_cast<unsigned char*>(pOuterValue), 1, NestedPostMemoryHook) == true);
		auto HookCleanup = MakeScopeExit([pOuterValue, pInnerValue]() {
			Detours::Hook::UnHookMemory(NestedMemoryHook, const_cast<unsigned char*>(pInnerValue));
			Detours::Hook::UnHookMemory(NestedMemoryHook, const_cast<unsigned char*>(pOuterValue));
		});
		REQUIRE(Detours::Hook::HookMemory(NestedMemoryHook, const_cast<unsigned char*>(pInnerValue), 1, NestedPostMemoryHook) == true);

		unsigned char const unOuterValue = *pOuterValue;
		CHECK(unOuterValue == 0x5A);
		CHECK(g_unNestedMemoryHookReadValue == 0xA5);
		CHECK(g_nNestedMemoryHookInvalidCalls.load(std::memory_order_relaxed) == 0);
		REQUIRE(g_nNestedMemoryHookEventCount.load(std::memory_order_relaxed) == 5);
		CHECK(g_arrNestedMemoryHookEvents[0] == NestedOuterPreBegin);
		CHECK(g_arrNestedMemoryHookEvents[1] == NestedInnerPre);
		CHECK(g_arrNestedMemoryHookEvents[2] == NestedInnerPost);
		CHECK(g_arrNestedMemoryHookEvents[3] == NestedOuterPreEnd);
		CHECK(g_arrNestedMemoryHookEvents[4] == NestedOuterPost);

		MEMORY_BASIC_INFORMATION OuterMemoryInfo {};
		MEMORY_BASIC_INFORMATION InnerMemoryInfo {};
		REQUIRE(VirtualQuery(const_cast<unsigned char*>(pOuterValue), &OuterMemoryInfo, sizeof(OuterMemoryInfo)) == sizeof(OuterMemoryInfo));
		REQUIRE(VirtualQuery(const_cast<unsigned char*>(pInnerValue), &InnerMemoryInfo, sizeof(InnerMemoryInfo)) == sizeof(InnerMemoryInfo));
		CHECK((OuterMemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);
		CHECK((InnerMemoryInfo.Protect & 0xFF) == PAGE_NOACCESS);

		bool const bInnerUnHooked = Detours::Hook::UnHookMemory(NestedMemoryHook, const_cast<unsigned char*>(pInnerValue));
		bool const bOuterUnHooked = Detours::Hook::UnHookMemory(NestedMemoryHook, const_cast<unsigned char*>(pOuterValue));
		CHECK(bInnerUnHooked == true);
		CHECK(bOuterUnHooked == true);
		if (bInnerUnHooked && bOuterUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("MemoryHook unhooks every segment from one allowVirtual installation") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 3));

		unsigned char* const pBatchAddress = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize * 3, MEM_RESERVE, PAGE_NOACCESS));
		REQUIRE(pBatchAddress != nullptr);
		if (!pBatchAddress) {
			return;
		}

		auto BatchCleanup = MakeScopeExit([pBatchAddress]() {
			VirtualFree(pBatchAddress, 0, MEM_RELEASE);
		});

		unsigned char* const pFirstPage = static_cast<unsigned char*>(VirtualAlloc(pBatchAddress, unPageSize, MEM_COMMIT, PAGE_READWRITE));
		unsigned char* const pThirdPage = static_cast<unsigned char*>(VirtualAlloc(pBatchAddress + (unPageSize * 2), unPageSize, MEM_COMMIT, PAGE_READWRITE));
		REQUIRE(pFirstPage == pBatchAddress);
		REQUIRE(pThirdPage == (pBatchAddress + (unPageSize * 2)));
		if (!pFirstPage || !pThirdPage) {
			return;
		}

		pFirstPage[0] = 0x11;
		pThirdPage[0] = 0x33;

		Detours::Memory::Page StandalonePage;
		volatile unsigned char* const pStandaloneValue = static_cast<volatile unsigned char*>(StandalonePage.Alloc(1));
		REQUIRE(const_cast<unsigned char*>(pStandaloneValue) != nullptr);
		*pStandaloneValue = 0x44;

		g_nVirtualBatchPreCalls.store(0, std::memory_order_relaxed);
		g_nVirtualBatchPostCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(VirtualBatchMemoryHook, pBatchAddress, unPageSize * 3, VirtualBatchPostMemoryHook, true) == true);
		auto HookCleanup = MakeScopeExit([pBatchAddress, pThirdPage, pStandaloneValue, unPageSize]() {
			Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, pBatchAddress);
			Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, pBatchAddress + unPageSize);
			Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, pThirdPage);
			Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, const_cast<unsigned char*>(pStandaloneValue));
		});
		REQUIRE(Detours::Hook::HookMemory(VirtualBatchMemoryHook, const_cast<unsigned char*>(pStandaloneValue), 1, VirtualBatchPostMemoryHook) == true);

		volatile unsigned char unSink = pFirstPage[0];
		unSink = static_cast<unsigned char>(unSink ^ pThirdPage[0]);
		unSink = static_cast<unsigned char>(unSink ^ *pStandaloneValue);
		CHECK(unSink == static_cast<unsigned char>(0x11 ^ 0x33 ^ 0x44));
		CHECK(g_nVirtualBatchPreCalls.load(std::memory_order_relaxed) >= 3);
		CHECK(g_nVirtualBatchPostCalls.load(std::memory_order_relaxed) == g_nVirtualBatchPreCalls.load(std::memory_order_relaxed));

		REQUIRE(Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, pBatchAddress) == true);

		MEMORY_BASIC_INFORMATION FirstMemoryInfo {};
		MEMORY_BASIC_INFORMATION MiddleMemoryInfo {};
		MEMORY_BASIC_INFORMATION ThirdMemoryInfo {};
		REQUIRE(VirtualQuery(pFirstPage, &FirstMemoryInfo, sizeof(FirstMemoryInfo)) == sizeof(FirstMemoryInfo));
		REQUIRE(VirtualQuery(pBatchAddress + unPageSize, &MiddleMemoryInfo, sizeof(MiddleMemoryInfo)) == sizeof(MiddleMemoryInfo));
		REQUIRE(VirtualQuery(pThirdPage, &ThirdMemoryInfo, sizeof(ThirdMemoryInfo)) == sizeof(ThirdMemoryInfo));
		CHECK(FirstMemoryInfo.State == MEM_COMMIT);
		CHECK((FirstMemoryInfo.Protect & 0xFF) == PAGE_READWRITE);
		CHECK(MiddleMemoryInfo.State == MEM_RESERVE);
		CHECK(ThirdMemoryInfo.State == MEM_COMMIT);
		CHECK((ThirdMemoryInfo.Protect & 0xFF) == PAGE_READWRITE);

		LONG const nBatchPreCalls = g_nVirtualBatchPreCalls.load(std::memory_order_relaxed);
		LONG const nBatchPostCalls = g_nVirtualBatchPostCalls.load(std::memory_order_relaxed);
		unSink = pFirstPage[0];
		unSink = static_cast<unsigned char>(unSink ^ pThirdPage[0]);
		CHECK(g_nVirtualBatchPreCalls.load(std::memory_order_relaxed) == nBatchPreCalls);
		CHECK(g_nVirtualBatchPostCalls.load(std::memory_order_relaxed) == nBatchPostCalls);
		unSink = static_cast<unsigned char>(unSink ^ *pStandaloneValue);
		CHECK(unSink == static_cast<unsigned char>(0x11 ^ 0x33 ^ 0x44));
		CHECK(g_nVirtualBatchPreCalls.load(std::memory_order_relaxed) == (nBatchPreCalls + 1));
		CHECK(g_nVirtualBatchPostCalls.load(std::memory_order_relaxed) == (nBatchPostCalls + 1));
		CHECK(Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, pThirdPage) == false);
		REQUIRE(Detours::Hook::UnHookMemory(VirtualBatchMemoryHook, const_cast<unsigned char*>(pStandaloneValue)) == true);
		HookCleanup.Release();
	}














	TEST_CASE("InterruptHook") {
		REQUIRE(Detours::Hook::HookInterrupt(InterruptHook, 0x7E) == true);
		auto HookCleanup = MakeScopeExit([]() {
			Detours::Hook::UnHookInterrupt(InterruptHook);
		});
#if defined(_M_X64)
		unsigned long long const unRAX = CallInterrupt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		CHECK(unRAX == kInterruptHookReturnValue);
		CHECK(CallInterrupt(unRAX, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == kInterruptHookReturnValue);
#elif defined(_M_IX86)
		unsigned int const unEAX = CallInterrupt(1, 2, 3, 4, 5, 6, 7);
		CHECK(unEAX == kInterruptHookReturnValue);
		CHECK(CallInterrupt(unEAX, 2, 3, 4, 5, 6, 7) == kInterruptHookReturnValue);
#endif
		bool const bUnHooked = Detours::Hook::UnHookInterrupt(InterruptHook);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("InterruptHook handles vector zero") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize >= 8);
		if (unPageSize < 8) {
			return;
		}

		unsigned char* const pCode = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		REQUIRE(pCode != nullptr);
		if (!pCode) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pCode]() {
			VirtualFree(pCode, 0, MEM_RELEASE);
		});

		unsigned char const arrCode[] = { 0xCD, 0x00, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
		std::memcpy(pCode, arrCode, sizeof(arrCode));
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pCode, unPageSize, PAGE_EXECUTE_READ, &unOldProtection) != FALSE);
		REQUIRE(FlushInstructionCache(GetCurrentProcess(), pCode, sizeof(arrCode)) != FALSE);

		g_nZeroInterruptCalls.store(0, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookInterrupt(ZeroInterruptHook, 0) == true);
		auto HookCleanup = MakeScopeExit([]() {
			Detours::Hook::UnHookInterrupt(ZeroInterruptHook);
		});

		using fnZeroInterrupt = int(__cdecl*)();
		CHECK(reinterpret_cast<fnZeroInterrupt>(pCode)() == 42);
		CHECK(g_nZeroInterruptCalls.load(std::memory_order_relaxed) == 1);
		bool const bUnHooked = Detours::Hook::UnHookInterrupt(ZeroInterruptHook);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

#pragma optimize("", off)

	TEST_CASE("VTableFunctionHook") {
		ScopedTestingRTTIObjects TestingObjects(g_pBaseTestingRTTI, g_pTestingRTTI);

		std::unique_ptr<Detours::RTTI::Object> pObject =
			Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		REQUIRE(pObject != nullptr);
		void** pVTable = pObject->GetVTable();
		REQUIRE(pVTable != nullptr);
		using fnFoo = bool(__fastcall*)(void* pThis, void*);
		using fnBoo = bool(__fastcall*)(void* pThis, void*);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);

		Detours::Hook::VTableFunctionHook SelfHook(pVTable, 0);
		CHECK(SelfHook.Hook(pVTable[0]) == false);
		CHECK(SelfHook.IsHooked() == false);
		CHECK(SelfHook.Release() == true);

		REQUIRE(g_FooHook.Set(pVTable, 0) == true);
		auto FooHookCleanup = MakeScopeExit([]() {
			g_FooHook.UnHook();
			g_FooHook.Release();
		});
		REQUIRE(g_FooHook.Hook(FooHook) == true);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == false);
		CHECK(g_FooHook.UnHook() == true);
		bool const bFooHookReleased = g_FooHook.Release();
		CHECK(bFooHookReleased == true);
		if (bFooHookReleased) {
			FooHookCleanup.Release();
		}

		REQUIRE(g_BooHook.Set(pVTable, 1) == true);
		auto BooHookCleanup = MakeScopeExit([]() {
			g_BooHook.UnHook();
			g_BooHook.Release();
		});
		REQUIRE(g_BooHook.Hook(BooHook) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == true);
		CHECK(g_BooHook.UnHook() == true);
		bool const bBooHookReleased = g_BooHook.Release();
		CHECK(bBooHookReleased == true);
		if (bBooHookReleased) {
			BooHookCleanup.Release();
		}
	}

	TEST_CASE("VTableHook") {
		ScopedTestingRTTIObjects TestingObjects(g_pBaseTestingRTTI, g_pTestingRTTI);

		std::unique_ptr<Detours::RTTI::Object> pObject =
			Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		REQUIRE(pObject != nullptr);
		void** pVTable = pObject->GetVTable();
		REQUIRE(pVTable != nullptr);
		using fnFoo = bool(__fastcall*)(void* pThis, void*);
		using fnBoo = bool(__fastcall*)(void* pThis, void*);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == false);

		constexpr std::size_t kVTableFunctionCount = 2;
		void* arrNewVTable[kVTableFunctionCount] = {
			nullptr, // Will be skipped
			reinterpret_cast<void*>(VTableBooHook)
		};

		REQUIRE(g_TestingRTTIVTableHook.Set(pVTable, kVTableFunctionCount) == true);
		auto VTableHookCleanup = MakeScopeExit([]() {
			g_TestingRTTIVTableHook.UnHook();
			g_TestingRTTIVTableHook.Release();
		});
		REQUIRE(g_TestingRTTIVTableHook.Hook(arrNewVTable) == true);

		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == true);
		CHECK(reinterpret_cast<fnBoo>(pVTable[1])(g_pTestingRTTI, nullptr) == true);

		CHECK(g_TestingRTTIVTableHook.UnHook() == true);
		bool const bVTableHookReleased = g_TestingRTTIVTableHook.Release();
		CHECK(bVTableHookReleased == true);
		if (bVTableHookReleased) {
			VTableHookCleanup.Release();
		}
	}

	TEST_CASE("VTableHook rolls back earlier entries when a later entry fails") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInfo.dwPageSize);
		REQUIRE(unPageSize >= sizeof(void*));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		unsigned char* const pReservation = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE, PAGE_NOACCESS));
		REQUIRE(pReservation != nullptr);
		if (!pReservation) {
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pReservation]() {
			VirtualFree(pReservation, 0, MEM_RELEASE);
		});
		REQUIRE(VirtualAlloc(pReservation, unPageSize, MEM_COMMIT, PAGE_READWRITE) == pReservation);

		void** const pVTable = reinterpret_cast<void**>(pReservation + unPageSize - sizeof(void*));
		pVTable[0] = reinterpret_cast<void*>(VTableRollbackOriginal);
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pReservation, unPageSize, PAGE_READONLY, &unOldProtection) != FALSE);

		void* arrHookVTable[] = {
			reinterpret_cast<void*>(VTableRollbackReplacement),
			reinterpret_cast<void*>(VTableRollbackReplacement)
		};
		Detours::Hook::VTableHook VTableHook;
		REQUIRE(VTableHook.Set(pVTable, 2) == true);
		CHECK(VTableHook.Hook(arrHookVTable) == false);
		CHECK(pVTable[0] == reinterpret_cast<void*>(VTableRollbackOriginal));
		using fnVTableRollback = int(__cdecl*)();
		CHECK(reinterpret_cast<fnVTableRollback>(pVTable[0])() == 17);
		CHECK(VTableHook.GetHookingFunctions().empty());

		MEMORY_BASIC_INFORMATION MemoryInfo {};
		REQUIRE(VirtualQuery(pVTable, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo));
		CHECK(MemoryInfo.State == MEM_COMMIT);
		CHECK((MemoryInfo.Protect & 0xFF) == PAGE_READONLY);
		CHECK(VTableHook.Release() == true);
	}

#pragma optimize("", on)



	TEST_CASE("InlineWrapper callback rejects self-unhook in child" * doctest::skip()) {
		using fnTarget = double(__cdecl*)(
			unsigned int,
			unsigned int,
			unsigned int,
			unsigned int,
			unsigned int,
			unsigned int,
			double,
			double);
		fnTarget const pTarget = InlineWrapperSelfUnHookTarget;

		for (std::size_t unIteration = 0;
			 unIteration < kInlineWrapperSelfUnHookIterationCount;
			 ++unIteration) {
			g_unInlineWrapperSelfUnHookCalls.store(0, std::memory_order_relaxed);
			g_bInlineWrapperSelfUnHookSucceeded.store(false, std::memory_order_relaxed);
			REQUIRE(g_InlineWrapperSelfUnHook.Set(
				reinterpret_cast<void*>(pTarget)) == true);
			auto HookCleanup = MakeScopeExit([]() {
				g_InlineWrapperSelfUnHook.UnHook();
				g_InlineWrapperSelfUnHook.Release();
			});
			REQUIRE(g_InlineWrapperSelfUnHook.Hook(
				reinterpret_cast<void*>(InlineWrapperSelfUnHook), true) == true);
			CHECK(pTarget(1, 2, 3, 4, 5, 6, 1.25, 2.5) == doctest::Approx(25.75));
			CHECK(g_unInlineWrapperSelfUnHookCalls.load(std::memory_order_relaxed) == 1);
			CHECK(g_bInlineWrapperSelfUnHookSucceeded.load(std::memory_order_acquire) == false);
			REQUIRE(g_InlineWrapperSelfUnHook.UnHook() == true);
			REQUIRE(g_InlineWrapperSelfUnHook.Release() == true);
			HookCleanup.Release();
		}
	}


	TEST_CASE("InlineWrapper API callback rejects hook-independent self-unhook in child" * doctest::skip()) {
		HMODULE const hKernel32 = GetModuleHandleW(L"kernel32.dll");
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* const pReadProcessMemory = reinterpret_cast<void*>(
			GetProcAddress(hKernel32, "ReadProcessMemory"));
		REQUIRE(pReadProcessMemory != nullptr);

		g_unInlineWrapperAPISelfUnHookCalls.store(0, std::memory_order_relaxed);
		g_bInlineWrapperAPISelfUnHookSucceeded.store(false, std::memory_order_relaxed);
		REQUIRE(g_InlineWrapperAPISelfUnHook.Set(pReadProcessMemory) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_InlineWrapperAPISelfUnHook.UnHook();
			g_InlineWrapperAPISelfUnHook.Release();
		});
		REQUIRE(g_InlineWrapperAPISelfUnHook.Hook(
			reinterpret_cast<void*>(InlineWrapperAPISelfUnHook), true) == true);

		unsigned int const unSource = 0x12345678;
		unsigned int unDestination = 0;
		SIZE_T unBytesRead = 0;
		CHECK(ReadProcessMemory(
				  GetCurrentProcess(),
				  &unSource,
				  &unDestination,
				  sizeof(unDestination),
				  &unBytesRead) != FALSE);
		CHECK(unBytesRead == sizeof(unDestination));
		CHECK(unDestination == unSource);
		CHECK(g_unInlineWrapperAPISelfUnHookCalls.load(std::memory_order_relaxed) >= 1);
		CHECK(g_bInlineWrapperAPISelfUnHookSucceeded.load(std::memory_order_acquire) == false);
		REQUIRE(g_InlineWrapperAPISelfUnHook.UnHook() == true);
		REQUIRE(g_InlineWrapperAPISelfUnHook.Release() == true);
		HookCleanup.Release();
	}

	TEST_CASE("Inline hooks reject their target as the replacement") {
		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* const pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		Detours::Hook::InlineHook InlineHook(pSleep);
		CHECK(InlineHook.Hook(pSleep, false) == false);
		CHECK(InlineHook.GetTrampoline() == nullptr);
		CHECK(InlineHook.Release() == true);

		Detours::Hook::InlineWrapperHook WrapperHook(pSleep);
		CHECK(WrapperHook.Hook(pSleep, false) == false);
		CHECK(WrapperHook.GetTrampoline() == nullptr);
		CHECK(WrapperHook.Release() == true);
	}

	TEST_CASE("InlineWrapperHook") {
		g_bInlineSleepHookCalled = false;

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		REQUIRE(g_InlineSleepHook.Set(pSleep) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_InlineSleepHook.UnHook();
			g_InlineSleepHook.Release();
		});
		REQUIRE(g_InlineSleepHook.Hook(reinterpret_cast<void*>(SleepHook), true) == true);
		CHECK(g_bInlineSleepHookCalled == false);
		Sleep(1000);
		CHECK(g_bInlineSleepHookCalled == true);
		CHECK(g_InlineSleepHook.UnHook() == true);
		bool const bReleased = g_InlineSleepHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("GetCurrentContext and CallAddress") {
		Detours::Hook::RAW_CONTEXT Context {};
		Detours::Hook::GetCurrentContext(&Context);
#ifdef _M_IX86
		unsigned int unCurrentStackAddress = 0;
		__asm {
			mov unCurrentStackAddress, esp
		}
#endif
		REQUIRE(Context.m_Stack.GetAddress() != nullptr);
#if defined(_M_X64)
		CHECK(Context.m_unRFLAGS != 0);
		CHECK((reinterpret_cast<std::uintptr_t>(Context.m_Stack.GetAddress()) & 0xF) == 0x8);
		Context.m_unRCX = 0x300;
#elif defined(_M_IX86)
		CHECK(Context.m_unEFLAGS != 0);
		// MSVC may retain the cdecl outgoing argument slot or reclaim it
		// immediately after GetCurrentContext returns.
		bool const bOutgoingStackSlotRetained = Context.m_unESP == unCurrentStackAddress;
		bool const bOutgoingStackSlotReleased = (Context.m_unESP + sizeof(void*)) == unCurrentStackAddress;
		CHECK((bOutgoingStackSlotRetained || bOutgoingStackSlotReleased));
		Context.m_unECX = 0x300;
#endif

		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#if defined(_M_X64)
		CHECK(Context.m_unRAX == 0x1534);
#elif defined(_M_IX86)
		CHECK(Context.m_unEAX == 0x1534);
#endif
	}

	TEST_CASE("CallAddress standalone RAW_CONTEXT") {
		Detours::Hook::RAW_CONTEXT Context {};
		Context.m_unEFLAGS = 0x202;
		Context.m_unMXCSR = 0x1F80;
		Context.m_FPU.m_unControlWord = 0x037F;
		Context.m_FPU.m_unTagWord = 0xFFFF;
#if defined(_M_X64)
		Context.m_unRCX = 0x100;
#elif defined(_M_IX86)
		Context.m_unECX = 0x100;
#endif

		CHECK(Context.m_Stack.GetAddress() == nullptr);
		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
		CHECK(Context.m_Stack.GetAddress() == nullptr);
#if defined(_M_X64)
		CHECK(Context.m_unRAX == 0x1334);
#elif defined(_M_IX86)
		CHECK(Context.m_unEAX == 0x1334);
#endif
	}

	TEST_CASE("CallAddress standalone custom stack") {
		constexpr std::size_t kStackSize = 0x10000;
		void* pStack = VirtualAlloc(nullptr, kStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		REQUIRE(pStack != nullptr);
		auto StackCleanup = MakeScopeExit([&pStack]() {
			if (pStack) {
				VirtualFree(pStack, 0, MEM_RELEASE);
			}
		});

		Detours::Hook::RAW_CONTEXT Context {};
		Context.m_unEFLAGS = 0x202;
		Context.m_unMXCSR = 0x1F80;
		Context.m_FPU.m_unControlWord = 0x037F;
		Context.m_FPU.m_unTagWord = 0xFFFF;
#if defined(_M_X64)
		Context.m_unRCX = 0x200;
		std::uintptr_t unStackAddress = (reinterpret_cast<std::uintptr_t>(pStack) + kStackSize - 0x100) & ~static_cast<std::uintptr_t>(0xF);
		unStackAddress -= 8;
#elif defined(_M_IX86)
		Context.m_unECX = 0x200;
		std::uintptr_t unStackAddress = (reinterpret_cast<std::uintptr_t>(pStack) + kStackSize - 0x100) & ~static_cast<std::uintptr_t>(0xF);
		unStackAddress -= 4;
#endif
		Context.m_Stack.SetAddress(reinterpret_cast<void*>(unStackAddress));
		*reinterpret_cast<std::size_t*>(Context.m_Stack.GetAddress()) = 0;

		Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#if defined(_M_X64)
		CHECK(Context.m_unRAX == 0x1434);
#elif defined(_M_IX86)
		CHECK(Context.m_unEAX == 0x1434);
#endif
		CHECK(reinterpret_cast<std::uintptr_t>(Context.m_Stack.GetAddress()) >= reinterpret_cast<std::uintptr_t>(pStack));
		CHECK(reinterpret_cast<std::uintptr_t>(Context.m_Stack.GetAddress()) < (reinterpret_cast<std::uintptr_t>(pStack) + kStackSize));
#pragma warning(suppress: 6001) // Custom stack transfer obscures pStack lifetime from code analysis.
		bool const bStackReleased = VirtualFree(pStack, 0, MEM_RELEASE) != FALSE;
		CHECK(bStackReleased == true);
		if (bStackReleased) {
			pStack = nullptr;
			StackCleanup.Release();
		}
	}

#if defined(_M_IX86)
	TEST_CASE("CallAddress standalone does not mutate adjacent RawHook state") {
		SYSTEM_INFO SystemInfo {};
		GetSystemInfo(&SystemInfo);
		REQUIRE(SystemInfo.dwPageSize >= 0x200);

		void* const pStack = VirtualAlloc(
			nullptr, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		REQUIRE(pStack != nullptr);
		auto StackCleanup = MakeScopeExit([pStack]() {
			VirtualFree(pStack, 0, MEM_RELEASE);
		});

		STANDALONE_RAW_CALL_CONTEXT StandaloneContext {};
		StandaloneContext.m_Context.m_unEFLAGS = 0x202;
		StandaloneContext.m_Context.m_unMXCSR = 0x1F80;
		StandaloneContext.m_Context.m_FPU.m_unControlWord = 0x037F;
		StandaloneContext.m_Context.m_FPU.m_unTagWord = 0xFFFF;

		std::uintptr_t const unStackAddress =
			(reinterpret_cast<std::uintptr_t>(pStack) + SystemInfo.dwPageSize - 0x100) &
			~static_cast<std::uintptr_t>(0xF);
		void* const pStackAddress = reinterpret_cast<void*>(unStackAddress);
		void* const pReturnAddress = reinterpret_cast<void*>(0x13572468);
		unsigned int* const pStackValues = reinterpret_cast<unsigned int*>(pStackAddress);
		pStackValues[0] = reinterpret_cast<unsigned int>(pReturnAddress);
		pStackValues[1] = 0x200;
		StandaloneContext.m_Context.m_Stack.SetAddress(pStackAddress);
		StandaloneContext.m_arrCanary[0] = pStackAddress;
		StandaloneContext.m_arrCanary[1] = pReturnAddress;

		Detours::Hook::CallAddress(
			reinterpret_cast<void*>(CallAddressStandaloneStackTarget),
			&StandaloneContext.m_Context);

		CHECK(StandaloneContext.m_Context.m_unEAX == 0x2545);
		CHECK(StandaloneContext.m_Context.m_Stack.GetAddress() ==
			reinterpret_cast<unsigned char*>(pStackAddress) + sizeof(void*));
		CHECK(StandaloneContext.m_arrCanary[0] == pStackAddress);
		CHECK(StandaloneContext.m_arrCanary[1] == pReturnAddress);
	}
#endif

	TEST_CASE("CallAddress concurrent contexts") {
		constexpr std::size_t kThreadCount = 8;
		static constexpr std::size_t kIterations = 128;
		std::atomic<std::size_t> unFailures = 0;
		std::vector<std::thread> vecThreads;
		vecThreads.reserve(kThreadCount);
		auto ThreadsCleanup = MakeScopeExit([&vecThreads]() {
			for (auto& Thread : vecThreads) {
				if (Thread.joinable()) {
					Thread.join();
				}
			}
		});

		for (std::size_t unThread = 0; unThread < kThreadCount; ++unThread) {
			vecThreads.emplace_back([unThread, &unFailures]() {
				for (std::size_t unIteration = 0; unIteration < kIterations; ++unIteration) {
#if defined(_M_X64)
					unsigned long long const unInput = (static_cast<unsigned long long>(unThread) << 32) | unIteration;
#elif defined(_M_IX86)
					unsigned int const unInput = (unThread << 16) | unIteration;
#endif
					Detours::Hook::RAW_CONTEXT Context {};
#if defined(_M_X64)
					Context.m_unRFLAGS = 0x202;
#elif defined(_M_IX86)
					Context.m_unEFLAGS = 0x202;
#endif
					Context.m_unMXCSR = 0x1F80;
					Context.m_FPU.m_unControlWord = 0x037F;
					Context.m_FPU.m_unTagWord = 0xFFFF;
#if defined(_M_X64)
					Context.m_unRCX = unInput;
#elif defined(_M_IX86)
					Context.m_unECX = unInput;
#endif

					Detours::Hook::CallAddress(reinterpret_cast<void*>(CallAddressStandaloneTarget), &Context);
#if defined(_M_X64)
					if (Context.m_Stack.GetAddress() || (Context.m_unRAX != (unInput + 0x1234))) {
#elif defined(_M_IX86)
					if (Context.m_Stack.GetAddress() || (Context.m_unEAX != (unInput + 0x1234))) {
#endif
						unFailures.fetch_add(1, std::memory_order_relaxed);
					}
				}
			});
		}

		for (auto& Thread : vecThreads) {
			Thread.join();
		}

		ThreadsCleanup.Release();

		CHECK(unFailures.load(std::memory_order_relaxed) == 0);
	}

	TEST_CASE("RawHook") {
		g_bRawSleepHookCalled = false;

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* const pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		REQUIRE(g_RawSleepHook.Set(pSleep) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_RawSleepHook.UnHook();
			g_RawSleepHook.Release();
		});
		REQUIRE(g_RawSleepHook.Hook(SleepRawHook, false, 0x16, true) == true);
		CHECK(g_bRawSleepHookCalled == false);

		Sleep(1000);

		CHECK(g_bRawSleepHookCalled == true);
		CHECK(g_RawSleepHook.UnHook() == true);
		bool const bReleased = g_RawSleepHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

#if defined(_M_X64)
	TEST_CASE("RawHook registers callback unwind information") {
		g_pRawHookUnwindReturnAddress = nullptr;
		g_arrRawHookUnwindCallStack.fill(nullptr);
		g_unRawHookUnwindCallStackSize = 0;

		Detours::Hook::RawHook Hook;
		REQUIRE(Hook.Set(reinterpret_cast<void*>(RawCETTransitionTarget)) == true);
		auto HookCleanup = MakeScopeExit([&Hook]() {
			Hook.UnHook();
			Hook.Release();
		});
		REQUIRE(Hook.Hook(
			ThrowingRawHook,
			true,
			kRawCETReservedStackSize,
			false) == true);

		bool bCaught = false;
		using fnRawHookUnwindTarget = unsigned int(__cdecl*)();
		fnRawHookUnwindTarget volatile pTarget = RawCETTransitionTarget;
		try {
			pTarget();
		} catch (unsigned int const unValue) {
			bCaught = unValue == kRawHookUnwindExceptionValue;
		}

		REQUIRE(bCaught == true);
		REQUIRE(g_pRawHookUnwindReturnAddress != nullptr);
		auto itWrapperFrame = std::find(
			g_arrRawHookUnwindCallStack.begin(),
			g_arrRawHookUnwindCallStack.begin() +
				g_unRawHookUnwindCallStackSize,
			g_pRawHookUnwindReturnAddress);
		REQUIRE(itWrapperFrame !=
			(g_arrRawHookUnwindCallStack.begin() +
			 g_unRawHookUnwindCallStackSize));
		REQUIRE((itWrapperFrame + 1) !=
			(g_arrRawHookUnwindCallStack.begin() +
			 g_unRawHookUnwindCallStackSize));

		DWORD64 unImageBase = 0;
		REQUIRE(RtlLookupFunctionEntry(
			reinterpret_cast<DWORD64>(g_pRawHookUnwindReturnAddress),
			&unImageBase,
			nullptr) != nullptr);
		REQUIRE(Hook.UnHook() == true);

		unImageBase = 0;
		CHECK(RtlLookupFunctionEntry(
			reinterpret_cast<DWORD64>(g_pRawHookUnwindReturnAddress),
			&unImageBase,
			nullptr) == nullptr);
		bool const bReleased = Hook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}
#endif

	TEST_CASE("RawHook rejects oversized reserved stack") {
		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		REQUIRE(hKernel32 != INVALID_HANDLE_VALUE);
		if (!hKernel32 || (hKernel32 == INVALID_HANDLE_VALUE)) {
			return;
		}

		void* const pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		Detours::Hook::RawHook OversizedRawHook;
		REQUIRE(OversizedRawHook.Set(pSleep) == true);
		auto HookCleanup = MakeScopeExit([&OversizedRawHook]() {
			OversizedRawHook.UnHook();
			OversizedRawHook.Release();
		});
		CHECK(OversizedRawHook.Hook(SleepRawHook, true, std::numeric_limits<unsigned int>::max(), true) == false);
		bool const bReleased = OversizedRawHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("Inline hooks reject an instruction truncated by a guard page") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!pMemory) {
			FAIL("Failed to allocate the guarded hook target.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMemory]() {
			VirtualFree(pMemory, 0, MEM_RELEASE);
		});
		pMemory[unPageSize - 1] = 0x0F;
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pMemory, unPageSize, PAGE_EXECUTE_READ, &unOldProtection) != FALSE);
		REQUIRE(VirtualProtect(pMemory + unPageSize, unPageSize, PAGE_NOACCESS, &unOldProtection) != FALSE);
		void* const pTruncatedInstruction = pMemory + unPageSize - 1;

		Detours::Hook::InlineHook InlineHook(pTruncatedInstruction);
		CHECK(InlineHook.Hook(reinterpret_cast<void*>(SleepHook), false) == false);
		CHECK(InlineHook.Release() == true);

		Detours::Hook::InlineWrapperHook WrapperHook(pTruncatedInstruction);
		CHECK(WrapperHook.Hook(reinterpret_cast<void*>(SleepHook), false) == false);
		CHECK(WrapperHook.Release() == true);
	}

	TEST_CASE("Failed inline relocation preserves shared trampoline execution") {
		SYSTEM_INFO SystemInformation {};
		GetSystemInfo(&SystemInformation);
		std::size_t const unPageSize = static_cast<std::size_t>(SystemInformation.dwPageSize);
		if (unPageSize < kInlineProtectionMinimumPageSize) {
			FAIL("The system page size is too small for the inline relocation fixture.");
			return;
		}

		unsigned char* const pMemory = static_cast<unsigned char*>(VirtualAlloc(nullptr, unPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!pMemory) {
			FAIL("Failed to allocate inline relocation test memory.");
			return;
		}

		auto MemoryCleanup = MakeScopeExit([pMemory]() {
			VirtualFree(pMemory, 0, MEM_RELEASE);
		});
		std::memset(pMemory, 0x90, unPageSize);

		unsigned char* const pWorkingTarget = pMemory;
		pWorkingTarget[0] = 0xB8;
		unsigned int const unOriginalValue = kInlineProtectionOriginalValue;
		std::memcpy(pWorkingTarget + 1, &unOriginalValue, sizeof(unOriginalValue));
		pWorkingTarget[kInlineProtectionCodeSize - 1] = 0xC3;
		unsigned char* const pFailingTarget = pMemory + kInlineProtectionFailingTargetOffset;
		pFailingTarget[0] = 0xEB;
		pFailingTarget[1] = 0x7E;
		DWORD unOldProtection = 0;
		REQUIRE(VirtualProtect(pMemory, unPageSize, PAGE_EXECUTE_READ, &unOldProtection) != FALSE);

		using fnInlineProtectionTarget = int(__cdecl*)();
		Detours::Hook::InlineHook WorkingHook(pWorkingTarget);
		REQUIRE(WorkingHook.Hook(reinterpret_cast<void*>(InlineProtectionReplacement), false) == true);
		auto WorkingHookCleanup = MakeScopeExit([&WorkingHook]() {
			if (!WorkingHook.Release()) {
				std::abort();
			}
		});
		void* const pTrampolineAddress = WorkingHook.GetTrampoline();
		REQUIRE(pTrampolineAddress != nullptr);

		Detours::Hook::InlineHook FailingHook(pFailingTarget);
		CHECK(FailingHook.Hook(reinterpret_cast<void*>(InlineProtectionReplacement), false) == false);
		CHECK(FailingHook.Release() == true);

		MEMORY_BASIC_INFORMATION TrampolineInfo {};
		REQUIRE(VirtualQuery(pTrampolineAddress, &TrampolineInfo, sizeof(TrampolineInfo)) == sizeof(TrampolineInfo));
		REQUIRE((TrampolineInfo.Protect & 0xFF) == PAGE_EXECUTE_READ);
		CHECK(reinterpret_cast<fnInlineProtectionTarget>(pWorkingTarget)() == static_cast<int>(kInlineProtectionHookValue));
		CHECK(reinterpret_cast<fnInlineProtectionTarget>(pTrampolineAddress)() == static_cast<int>(kInlineProtectionOriginalValue));
		bool const bWorkingHookUnHooked = WorkingHook.UnHook();
		CHECK(bWorkingHookUnHooked == true);
		bool const bWorkingHookReleased = WorkingHook.Release();
		CHECK(bWorkingHookReleased == true);
		if (bWorkingHookReleased) {
			WorkingHookCleanup.Release();
		}
	}

	TEST_CASE("RawHook CET stack transitions") {
		g_unRawCETRedirectCalls.store(0, std::memory_order_relaxed);

		using fnRawCETTransitionTarget = unsigned int(__cdecl*)();
		fnRawCETTransitionTarget const pTarget = RawCETTransitionTarget;
		CHECK(pTarget() == kRawCETOriginalValue);

		Detours::Hook::RawHook TransitionHook;
		REQUIRE(TransitionHook.Set(reinterpret_cast<void*>(RawCETTransitionTarget)) == true);
		auto HookCleanup = MakeScopeExit([&TransitionHook]() {
			TransitionHook.UnHook();
			TransitionHook.Release();
		});

		SUBCASE("one synthetic redirect frame is executed") {
			REQUIRE(TransitionHook.Hook(RawCETSingleRedirectHook, false, kRawCETReservedStackSize, true) == true);
			CHECK(pTarget() == kRawCETRedirectValue);
			CHECK(g_unRawCETRedirectCalls.load(std::memory_order_relaxed) == 1);
		}

		SUBCASE("two synthetic redirect frames restore the original return path") {
			REQUIRE(TransitionHook.Hook(RawCETUnsupportedRedirectHook, false, kRawCETReservedStackSize, true) == true);
			CHECK(pTarget() == kRawCETFailSafeValue);
			CHECK(g_unRawCETRedirectCalls.load(std::memory_order_relaxed) == 0);
		}

		CHECK(TransitionHook.UnHook() == true);
		CHECK(pTarget() == kRawCETOriginalValue);
		bool const bReleased = TransitionHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("RawHook probes a large reserved stack on a minimally committed fiber in child" * doctest::skip()) {
		CHECK(RunWindowsRawStackProbeFiberScenario() == true);
	}

	TEST_CASE("RawHook grows Windows fiber stacks page by page") {
		DWORD unExitCode = 0;
		REQUIRE(RunWindowsTestChild(
			_T("RawHook probes a large reserved stack on a minimally committed fiber in child"),
			&unExitCode) == true);
		CHECK(unExitCode == 0);
	}

	TEST_CASE("RawHook rejects a return stack gap below entry in child" * doctest::skip()) {
		CHECK(RunWindowsRawStackValidationScenario(RawStackGapBelowEntryHook) == true);
	}

	TEST_CASE("RawHook rejects a return stack pointer above entry in child" * doctest::skip()) {
		CHECK(RunWindowsRawStackValidationScenario(RawStackAboveEntryHook) == true);
	}

	TEST_CASE("RawHook accepts only documented return stack shapes") {
		TCHAR const* const arrChildTests[] = {
			_T("RawHook rejects a return stack gap below entry in child"),
			_T("RawHook rejects a return stack pointer above entry in child")
		};
		for (auto const szChildTest : arrChildTests) {
			DWORD unExitCode = 0;
			REQUIRE(RunWindowsTestChild(szChildTest, &unExitCode) == true);
			CHECK(unExitCode == 0);
		}
	}

#if defined(_M_X64) && defined(PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON)
	TEST_CASE("RawHook hardware-enforced shadow-stack subprocess") {
		std::vector<TCHAR> vecExecutablePath(kRawCETExecutablePathCapacity);
		DWORD const unExecutablePathLength = GetModuleFileName(nullptr, vecExecutablePath.data(), static_cast<DWORD>(vecExecutablePath.size()));
		REQUIRE(unExecutablePathLength != 0);
		REQUIRE(unExecutablePathLength < vecExecutablePath.size());

		SIZE_T unAttributeListSize = 0;
		InitializeProcThreadAttributeList(nullptr, 1, 0, &unAttributeListSize);
		DWORD const unAttributeProbeError = GetLastError();
		if (!unAttributeListSize && ((unAttributeProbeError == ERROR_NOT_SUPPORTED) || (unAttributeProbeError == ERROR_INVALID_PARAMETER))) {
			MESSAGE("Hardware-enforced shadow-stack process attributes are unavailable: " << unAttributeProbeError);
			return;
		}

		REQUIRE(unAttributeListSize != 0);

		std::vector<unsigned char> vecAttributeList(unAttributeListSize);
		LPPROC_THREAD_ATTRIBUTE_LIST const pAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(vecAttributeList.data());
		if (!pAttributeList) {
			FAIL("Failed to allocate the process thread attribute list.");
			return;
		}

		REQUIRE(InitializeProcThreadAttributeList(pAttributeList, 1, 0, &unAttributeListSize) == TRUE);
		auto AttributeListCleanup = MakeScopeExit([pAttributeList]() {
			DeleteProcThreadAttributeList(pAttributeList);
		});

		DWORD64 arrMitigationPolicy[2] {
			0,
			PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON
		};
		if (!UpdateProcThreadAttribute(
				pAttributeList,
				0,
				PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
				arrMitigationPolicy,
				sizeof(arrMitigationPolicy),
				nullptr,
				nullptr)) {
			DWORD const unAttributeError = GetLastError();
			if ((unAttributeError == ERROR_NOT_SUPPORTED) || (unAttributeError == ERROR_INVALID_PARAMETER)) {
				MESSAGE("Hardware-enforced shadow-stack mitigation is unavailable: " << unAttributeError);
				return;
			}

			FAIL("Failed to configure hardware-enforced shadow-stack mitigation: " << unAttributeError);
		}

		std::basic_string<TCHAR> strCommandLine = _T("\"");
		strCommandLine += vecExecutablePath.data();
		strCommandLine += _T("\" --test-case=\"RawHook CET stack transitions\" --no-skip=true");
		std::vector<TCHAR> vecCommandLine(strCommandLine.cbegin(), strCommandLine.cend());
		vecCommandLine.push_back(_T('\0'));

		STARTUPINFOEX StartupInfoEx {};
		StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);
		StartupInfoEx.lpAttributeList = pAttributeList;
		PROCESS_INFORMATION ProcessInformation {};
		DWORD const unCreationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
		if (!CreateProcess(
				vecExecutablePath.data(),
				vecCommandLine.data(),
				nullptr,
				nullptr,
				FALSE,
				unCreationFlags,
				nullptr,
				nullptr,
				&StartupInfoEx.StartupInfo,
				&ProcessInformation)) {
			DWORD const unCreationError = GetLastError();
			if ((unCreationError == ERROR_NOT_SUPPORTED) || (unCreationError == ERROR_INVALID_PARAMETER)) {
				MESSAGE("Hardware-enforced shadow-stack subprocess is unavailable: " << unCreationError);
				return;
			}

			FAIL("Failed to create hardware-enforced shadow-stack subprocess: " << unCreationError);
		}

		bool bChildRunning = true;
		auto ProcessCleanup = MakeScopeExit([&ProcessInformation, &bChildRunning]() {
			if (bChildRunning) {
				TerminateProcess(ProcessInformation.hProcess, 1);
				WaitForSingleObject(ProcessInformation.hProcess, kRawCETChildWaitMilliseconds);
			}

			CloseHandle(ProcessInformation.hThread);
			CloseHandle(ProcessInformation.hProcess);
		});

		PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY ShadowStackPolicy {};
		if (!GetProcessMitigationPolicy(
				ProcessInformation.hProcess,
				ProcessUserShadowStackPolicy,
				&ShadowStackPolicy,
				sizeof(ShadowStackPolicy))) {
			DWORD const unPolicyError = GetLastError();
			if ((unPolicyError == ERROR_NOT_SUPPORTED) || (unPolicyError == ERROR_INVALID_PARAMETER)) {
				MESSAGE("Hardware-enforced shadow-stack policy query is unavailable: " << unPolicyError);
				return;
			}

			FAIL("Failed to query hardware-enforced shadow-stack policy: " << unPolicyError);
		}

		if (!ShadowStackPolicy.EnableUserShadowStack) {
			MESSAGE("Hardware-enforced shadow stacks are not active on this environment");
			return;
		}

		REQUIRE(ResumeThread(ProcessInformation.hThread) != static_cast<DWORD>(-1));
		REQUIRE(WaitForSingleObject(ProcessInformation.hProcess, kRawCETChildWaitMilliseconds) == WAIT_OBJECT_0);
		bChildRunning = false;

		DWORD unExitCode = 0;
		REQUIRE(GetExitCodeProcess(ProcessInformation.hProcess, &unExitCode) == TRUE);
		CHECK(unExitCode == 0);
	}
#endif

	TEST_CASE("Two RawHooks coexist within hook storage capacity") {
		g_unFirstCapacityRawHookCalls.store(0, std::memory_order_relaxed);
		g_unSecondCapacityRawHookCalls.store(0, std::memory_order_relaxed);

		REQUIRE(g_FirstCapacityRawHook.Set(reinterpret_cast<void*>(FirstRawCapacityTarget)) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_SecondCapacityRawHook.UnHook();
			g_SecondCapacityRawHook.Release();
			g_FirstCapacityRawHook.UnHook();
			g_FirstCapacityRawHook.Release();
		});
		REQUIRE(g_SecondCapacityRawHook.Set(reinterpret_cast<void*>(SecondRawCapacityTarget)) == true);

		REQUIRE(g_FirstCapacityRawHook.Hook(FirstRawCapacityHook, false, 0x16, true) == true);
		REQUIRE(g_SecondCapacityRawHook.Hook(SecondRawCapacityHook, false, 0x16, true) == true);

		using fnRawCapacityTarget = unsigned int(__cdecl*)(unsigned int);
		fnRawCapacityTarget const pFirstTarget = FirstRawCapacityTarget;
		fnRawCapacityTarget const pSecondTarget = SecondRawCapacityTarget;
		CHECK(pFirstTarget(7) == (7 + kFirstRawCapacityOffset));
		CHECK(pSecondTarget(9) == (9 + kSecondRawCapacityOffset));
		CHECK(g_unFirstCapacityRawHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unSecondCapacityRawHookCalls.load(std::memory_order_relaxed) == 1);

		bool const bSecondUnHooked = g_SecondCapacityRawHook.UnHook();
		bool const bSecondReleased = g_SecondCapacityRawHook.Release();
		bool const bFirstUnHooked = g_FirstCapacityRawHook.UnHook();
		bool const bFirstReleased = g_FirstCapacityRawHook.Release();
		CHECK(bSecondUnHooked == true);
		CHECK(bSecondReleased == true);
		CHECK(bFirstUnHooked == true);
		CHECK(bFirstReleased == true);
		if (bSecondUnHooked && bSecondReleased && bFirstUnHooked && bFirstReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("RawHook 2") {
		g_bRawSleepHookCalled = false;
		g_LastXMM7 = {};

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* const pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);

		REQUIRE(g_RawSleepHook.Set(pSleep) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_RawSleepHook.UnHook();
			g_RawSleepHook.Release();
		});
		REQUIRE(g_RawSleepHook.Hook(SleepRawHookModified, false, 0x16, true) == true);
		CHECK(g_bRawSleepHookCalled == false);
		CHECK(g_LastXMM7.m_un64[0] == 0);
		CHECK(g_LastXMM7.m_un64[1] == 0);
		Sleep(1000); // Will record last XMM7 value and change it
		Sleep(1000); // Will record last XMM7 value and change it
		CHECK(g_LastXMM7.m_un64[0] == 0x1122334455667788);
		CHECK(g_LastXMM7.m_un64[1] == 0x1122334455667788);
		CHECK(g_bRawSleepHookCalled == true);
		CHECK(g_RawSleepHook.UnHook() == true);
		bool const bReleased = g_RawSleepHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("RawHook CallTrampoline concurrent") {
		g_unRawSleepConcurrentCalls.store(0, std::memory_order_relaxed);

		HMODULE const hKernel32 = GetModuleHandle(_T("kernel32.dll"));
		REQUIRE(hKernel32 != nullptr);
		if (!hKernel32) {
			return;
		}

		void* const pSleep = reinterpret_cast<void*>(GetProcAddress(hKernel32, "Sleep"));
		REQUIRE(pSleep != nullptr);
		REQUIRE(g_RawSleepConcurrentHook.Set(pSleep) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_RawSleepConcurrentHook.UnHook();
			g_RawSleepConcurrentHook.Release();
		});
		REQUIRE(g_RawSleepConcurrentHook.Hook(SleepRawHookConcurrent, false, 0x16, true) == true);

		constexpr std::size_t kThreadCount = 8;
		static constexpr std::size_t kIterations = 64;
		std::vector<std::thread> vecThreads;
		vecThreads.reserve(kThreadCount);
		auto ThreadsCleanup = MakeScopeExit([&vecThreads]() {
			for (auto& Thread : vecThreads) {
				if (Thread.joinable()) {
					Thread.join();
				}
			}
		});
		for (std::size_t unThread = 0; unThread < kThreadCount; ++unThread) {
			vecThreads.emplace_back([]() {
				for (std::size_t unIteration = 0; unIteration < kIterations; ++unIteration) {
					Sleep(0);
				}
			});
		}

		for (auto& Thread : vecThreads) {
			Thread.join();
		}

		ThreadsCleanup.Release();

		CHECK(g_unRawSleepConcurrentCalls.load(std::memory_order_relaxed) == (kThreadCount * kIterations));
		CHECK(g_RawSleepConcurrentHook.UnHook() == true);
		bool const bReleased = g_RawSleepConcurrentHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

#pragma optimize("", off)

	TEST_CASE("RawHook 3") {
		ScopedTestingRTTIObjects TestingObjects(g_pBaseTestingRTTI, g_pTestingRTTI);

		std::unique_ptr<Detours::RTTI::Object> pObject =
			Detours::RTTI::FindObject(GetModuleHandle(nullptr), ".?AVTestingRTTI@@");
		REQUIRE(pObject != nullptr);

		void** pVTable = pObject->GetVTable();
		REQUIRE(pVTable != nullptr);
		using fnFoo = bool(__fastcall*)(void* pThis, void*);

		REQUIRE(g_RawCallConventionHook.Set(pVTable[0]) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_RawCallConventionHook.UnHook();
			g_RawCallConventionHook.Release();
		});
		REQUIRE(g_RawCallConventionHook.Hook(CallConventionRawHook, true, 0x10, true) == true);
		CHECK(reinterpret_cast<fnFoo>(pVTable[0])(g_pTestingRTTI, nullptr) == false);
		CHECK(g_RawCallConventionHook.UnHook() == true);
		bool const bReleased = g_RawCallConventionHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

#pragma optimize("", on)

	unsigned int DemoFunction() {
		SELF_EXPORT("DemoFunction");

		int nCPUIDRegisters[kCPUIDRegisterCount];
		__cpuidex(nCPUIDRegisters, 7, 0);
		_tprintf_s(_T("nCPUIDRegisters[0] = 0x%08X\n"), nCPUIDRegisters[0]);
		_tprintf_s(_T("nCPUIDRegisters[1] = 0x%08X\n"), nCPUIDRegisters[1]);
		_tprintf_s(_T("nCPUIDRegisters[2] = 0x%08X\n"), nCPUIDRegisters[2]);
		_tprintf_s(_T("nCPUIDRegisters[3] = 0x%08X\n"), nCPUIDRegisters[3]);

		return nCPUIDRegisters[1];
	}

	TEST_CASE("RawHook 4") {
		Detours::rddisasm::INSTRUCTION ins {};
		std::size_t unOffset = 0;
		void* pFoundCPUID = nullptr;
#ifdef _DEBUG
		void* const pStartAddress = Detours::rddisasm::RdGetAddressFromRelOrDisp(DemoFunction);
		if (!pStartAddress) {
			FAIL("Can't resolve JMP address from JMP table.");
		}
#else
		void* const pStartAddress = DemoFunction;
#endif
		while (unOffset < 0xFF) {
#if defined(_M_X64)
			if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pStartAddress) + unOffset, RD_DATA_64, RD_DATA_64))) {
#elif defined(_M_IX86)
			if (!RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, reinterpret_cast<unsigned char*>(pStartAddress) + unOffset, RD_DATA_32, RD_DATA_32))) {
#endif
				FAIL("Failed to decode DemoFunction while locating `cpuid`.");
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

		CHECK(g_RawCPUIDHook.Set(pFoundCPUID) == true);
		CHECK(DemoFunction() != 0x11223344);
		CHECK(g_RawCPUIDHook.Hook(CPUIDRawHook, true, 0x8, true) == true);
		CHECK(DemoFunction() == 0x11223344);
		CHECK(g_RawCPUIDHook.UnHook() == true);
		CHECK(g_RawCPUIDHook.Release() == true);
	}
} // TEST_SUITE("Detours::Hook")

#elif defined(__linux__)

// ============================================================================
// Linux tests
// ============================================================================

constexpr std::size_t kLinuxHookCodeSize = 64;
constexpr unsigned int kLinuxInlineOriginalValue = 11;
constexpr unsigned int kLinuxInlineHookValue = 37;
constexpr unsigned int kLinuxRawHookValue = 23;
constexpr unsigned int kLinuxRawRedirectValue = 61;
constexpr unsigned int kLinuxRawFailSafeValue = 67;
constexpr unsigned int kLinuxRawReservedStackSize = 0x20;
constexpr unsigned int kLinuxRawRedirectReservedStackSize = sizeof(void*) * 2;
constexpr int kLinuxRawStackValidationFailureExitCode = 132;
constexpr unsigned int kLinuxMemoryHookMinimumCalls = 8;
constexpr unsigned int kLinuxMemoryHookWaitMilliseconds = 2000;
constexpr unsigned int kLinuxChildWaitMilliseconds = 3000;
constexpr unsigned int kLinuxExceptionRawExitWaitMilliseconds = 30000;
constexpr unsigned int kLinuxMemoryHookOwnerExitPhaseNone = 0;
constexpr unsigned int kLinuxMemoryHookOwnerExitPhaseAfterOwnerCAS = 1;
constexpr unsigned int kLinuxMemoryHookOwnerExitPhaseAfterOwnerExchange = 2;
constexpr std::size_t kLinuxProtectedMemoryRawExitCodeSize = 13;
constexpr unsigned int kLinuxSuspendObservationMilliseconds = 100;
constexpr unsigned int kLinuxPipeClientDelayMilliseconds = 100;
constexpr unsigned int kLinuxProtectedForkReleaseMilliseconds = 100;
constexpr unsigned int kLinuxSyncWaitMilliseconds = 50;
constexpr unsigned int kLinuxSyncWaitEarlyToleranceMilliseconds = 5;
constexpr unsigned int kLinuxSyncWaitSlackMilliseconds = 500;
constexpr unsigned int kLinuxPipeRequestValue = 0x13572468;
constexpr unsigned int kLinuxPipeResponseValue = 0x24681357;
constexpr unsigned int kLinuxPipeFreshGenerationValue = 0x1A2B3C4D;
constexpr unsigned int kLinuxFirstRawCapacityValue = 41;
constexpr unsigned int kLinuxSecondRawCapacityValue = 53;
constexpr unsigned int kLinuxRedZoneValue = 0x12345678;
constexpr int kLinuxBoundarySignalExitCode = 77;
constexpr int kLinuxPipeFailureExitCode = 78;
constexpr int kLinuxSecureForkFailureExitCode = 79;
constexpr int kLinuxProtectedForkFailureExitCode = 80;
constexpr int kLinuxSignalChainingSuccessExitCode = 81;
constexpr int kLinuxSignalChainingFailureExitCode = 82;
constexpr int kLinuxMemoryHookForkFailureExitCode = 83;
constexpr int kLinuxInterruptHookForkFailureExitCode = 84;
constexpr int kLinuxHardwareHookForkFailureExitCode = 85;
constexpr int kLinuxProtectedSignalForkFailureExitCode = 86;
constexpr int kLinuxParallelThreadForkFailureExitCode = 87;
constexpr int kLinuxGeneratedCodeForkFailureExitCode = 88;
constexpr int kLinuxHardwareHookUnavailableExitCode = 89;
constexpr int kLinuxThreadIdentityForkFailureExitCode = 90;
constexpr int kLinuxExceptionForcedUnwindFailureExitCode = 91;
constexpr int kLinuxThreadSuspendCancellationFailureExitCode = 92;
constexpr int kLinuxExceptionRawExitFailureExitCode = 93;
constexpr int kLinuxInterruptRawExitFailureExitCode = 94;
constexpr int kLinuxMultiRecordMemoryHookFailureExitCode = 110;
constexpr int kLinuxUnmappedMemoryHookFailureExitCode = 111;
constexpr int kLinuxMemoryHookCleanupRetryFailureExitCode = 112;
constexpr int kLinuxProtectedSignalDeathSetupFailureExitCode = 113;
constexpr int kLinuxProtectedSignalOrphanFailureExitCode = 114;
constexpr int kLinuxProtectedSignalChildFailureExitCode = 115;
constexpr int kLinuxProtectedSignalParentFailureExitCode = 116;
constexpr int kLinuxProtectedSignalWaitFailureExitCode = 117;
constexpr int kLinuxProtectedSignalStatusFailureExitCode = 118;
constexpr int kLinuxHookForcedUnwindFailureExitCode = 119;
constexpr int kLinuxHardwareHookForcedUnwindUnavailableExitCode = 120;
constexpr int kLinuxPtraceCancellationFailureExitCode = 121;
constexpr int kLinuxPtraceCancellationUnavailableExitCode = 122;
constexpr int kLinuxCancellationRegressionFailureExitCode = 123;
constexpr int kLinuxProtectedSignalMaskFailureExitCode = 124;
constexpr int kLinuxDeferredSignalInformationFailureExitCode = 125;
constexpr int kLinuxProtectedAtForkFailureExitCode = 126;
constexpr int kLinuxHookForkSignalFailureExitCode = 127;
constexpr int kLinuxProtectedMemoryRawExitFailureExitCode = 128;
constexpr int kLinuxMemoryHookDeferredExitFailureExitCode = 129;
constexpr int kLinuxMemoryHookSynchronousFaultFailureExitCode = 130;
constexpr int kLinuxSynchronousFaultPredecessorExitCode = 131;
constexpr int kLinuxProtectedMemoryThreadExitCode = 65;
constexpr int kLinuxProtectedMemoryProcessExitCode = 66;
constexpr char kLinuxIsolatedTestEnvironment[] = "DETOURS_LINUX_ISOLATED_TEST";
constexpr int kLinuxProtectedSignalQueueValue = 0x1357;
constexpr std::uintptr_t kLinuxMemoryPreForcedUnwindResult = 0x101;
constexpr std::uintptr_t kLinuxMemoryPostForcedUnwindResult = 0x102;
constexpr std::uintptr_t kLinuxInterruptForcedUnwindResult = 0x103;
constexpr std::uintptr_t kLinuxHardwareForcedUnwindResult = 0x104;
constexpr std::uintptr_t kLinuxHardwareUnavailableResult = 0x105;
constexpr unsigned char kLinuxNoOperationOpcode = 0x90;
constexpr unsigned char kLinuxMoveImmediateOpcode = 0xB8;
constexpr unsigned char kLinuxMoveImmediateEDIImmediateOpcode = 0xBF;
constexpr unsigned char kLinuxMoveImmediateEBXImmediateOpcode = 0xBB;
constexpr unsigned char kLinuxReturnOpcode = 0xC3;
constexpr unsigned char kLinuxMoveStackSegmentOpcode = 0x8E;
constexpr unsigned char kLinuxMoveStackSegmentAXModRM = 0xD0;
constexpr unsigned char kLinuxSystemCallFirstOpcode = 0x0F;
constexpr unsigned char kLinuxSystemCallSecondOpcode = 0x05;
constexpr unsigned int kLinuxBitsPerByte = 8;
constexpr unsigned long kLinuxContextTrapFlagMask = 1UL << 8;
constexpr std::size_t kLinuxImmediateOffset = 1;
constexpr std::size_t kLinuxProtectedMemoryRawExitArgumentOpcodeOffset = 5;
constexpr std::size_t kLinuxProtectedMemoryRawExitArgumentImmediateOffset = 6;
constexpr std::size_t kLinuxProtectedMemoryRawExitSystemCallOffset = 10;
constexpr std::size_t kLinuxProtectedMemoryRawExitReturnOffset = 12;
constexpr std::size_t kLinuxReturnCodeSize = 6;
constexpr std::size_t kLinuxRedZoneHookOffset = 8;
constexpr std::size_t kLinuxRedZoneReturnOffset = 32;
constexpr std::size_t kLinuxAbsoluteJumpAddressOffset = 6;
constexpr std::size_t kLinuxMaximumRelativeJumpDistance = 0x7FFFFFFB;
constexpr std::uintptr_t kLinuxHighCodeAddressHint = 0x700000000000;
constexpr std::size_t kLinuxSelfUnHookEventCapacity = 3;
constexpr std::size_t kLinuxPipeFileDescriptorCount = 2;
constexpr std::size_t kLinuxProtectedRegistryThreadCount = 4;
constexpr std::size_t kLinuxProtectedRegistryIterationCount = 4;
constexpr std::size_t kLinuxProtectedForkIterationCount = 16;
constexpr std::size_t kLinuxProtectedAtForkPageCount = 32;
constexpr std::size_t kLinuxDeepStackSize = 16 * 1024 * 1024;
constexpr std::size_t kLinuxDeepStackAllocationSize = 9 * 1024 * 1024;
constexpr std::size_t kLinuxExceptionRawExitIterationCount = 512;
constexpr std::size_t kLinuxHookDispatchRawExitIterationCount = 512;

static_assert(kLinuxHookCodeSize >= kLinuxReturnCodeSize, "Linux hook fixture must contain the complete return sequence");
static_assert(ATOMIC_INT_LOCK_FREE == 2, "Linux signal callbacks require lock-free unsigned int atomics");
static_assert(std::atomic<bool>::is_always_lock_free, "Linux signal callbacks require lock-free bool atomics");
static_assert(sizeof(unsigned int) == 4, "Linux hook fixture requires a 32-bit unsigned int");

using fnLinuxHookTarget = int (*)();
using fnLinuxPendingCancellationOperation = bool (*)(void*);

enum class LinuxProtectedUnsafeInstructionFixture : unsigned char {
	SIGNAL_MASK_SYSTEM_CALL = 0,
	FORK_SYSTEM_CALL,
	MOVE_STACK_SEGMENT
};

typedef struct _LINUX_WAIT_CANCELLATION_DATA {
	_LINUX_WAIT_CANCELLATION_DATA() noexcept;
	void* m_pObject;
	bool m_bSemaphore;
	std::atomic<bool> m_bReturned;
} LINUX_WAIT_CANCELLATION_DATA, *PLINUX_WAIT_CANCELLATION_DATA;

typedef struct _LINUX_PIPE_CANCELLATION_DATA {
	_LINUX_PIPE_CANCELLATION_DATA() noexcept;
	Detours::Pipe::PipeServer* m_pPipeServer;
	std::atomic<bool> m_bReturned;
} LINUX_PIPE_CANCELLATION_DATA, *PLINUX_PIPE_CANCELLATION_DATA;

typedef struct _LINUX_PENDING_CANCELLATION_DATA {
	_LINUX_PENDING_CANCELLATION_DATA() noexcept;
	fnLinuxPendingCancellationOperation m_pOperation;
	void* m_pContext;
	std::atomic<bool> m_bOperationCompleted;
	std::atomic<bool> m_bOperationSucceeded;
	std::atomic<bool> m_bReturned;
} LINUX_PENDING_CANCELLATION_DATA, *PLINUX_PENDING_CANCELLATION_DATA;

typedef struct _LINUX_SUSPENDER_CANCELLATION_DATA {
	_LINUX_SUSPENDER_CANCELLATION_DATA() noexcept;
	Detours::Sync::Suspender* m_pSuspender;
	std::atomic<bool> m_bOperationCompleted;
	std::atomic<bool> m_bReturned;
} LINUX_SUSPENDER_CANCELLATION_DATA, *PLINUX_SUSPENDER_CANCELLATION_DATA;

typedef struct _LINUX_SUSPENDER_TARGET_DATA {
	_LINUX_SUSPENDER_TARGET_DATA() noexcept;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bStop;
	std::atomic<unsigned int> m_unIterations;
} LINUX_SUSPENDER_TARGET_DATA, *PLINUX_SUSPENDER_TARGET_DATA;

typedef struct _LINUX_STALE_SUSPEND_DATA {
	_LINUX_STALE_SUSPEND_DATA() noexcept;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bSignalBlocked;
	std::atomic<bool> m_bUnblock;
	std::atomic<bool> m_bUnblocked;
	std::atomic<bool> m_bStop;
	std::atomic<unsigned int> m_unIterations;
} LINUX_STALE_SUSPEND_DATA, *PLINUX_STALE_SUSPEND_DATA;

typedef struct _LINUX_FORK_THREAD_DATA {
	_LINUX_FORK_THREAD_DATA() noexcept;
	std::atomic<unsigned int> m_unReady;
	std::atomic<unsigned int> m_unCalls;
	std::atomic<bool> m_bStop;
} LINUX_FORK_THREAD_DATA, *PLINUX_FORK_THREAD_DATA;

typedef struct _LINUX_THREAD_SUSPEND_DATA {
	_LINUX_THREAD_SUSPEND_DATA() noexcept;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bStop;
	std::atomic<pid_t> m_nThreadID;
	std::atomic<unsigned int> m_unIterations;
} LINUX_THREAD_SUSPEND_DATA, *PLINUX_THREAD_SUSPEND_DATA;

typedef struct _LINUX_DEEP_STACK_DATA {
	_LINUX_DEEP_STACK_DATA() noexcept;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bStop;
	std::atomic<std::uintptr_t> m_unStackAddress;
} LINUX_DEEP_STACK_DATA, *PLINUX_DEEP_STACK_DATA;

typedef struct _LINUX_JOIN_CANCEL_DATA {
	_LINUX_JOIN_CANCEL_DATA() noexcept;
	Detours::Parallel::Thread* m_pThread;
	std::atomic<bool> m_bStarted;
	std::atomic<bool> m_bReturned;
} LINUX_JOIN_CANCEL_DATA, *PLINUX_JOIN_CANCEL_DATA;

typedef struct _LINUX_THREAD_OPERATION_CANCEL_DATA {
	_LINUX_THREAD_OPERATION_CANCEL_DATA() noexcept;
	Detours::Parallel::Thread* m_pThread;
	bool m_bSuspend;
	std::atomic<bool> m_bStarted;
	std::atomic<bool> m_bOperationCompleted;
	std::atomic<bool> m_bOperationSucceeded;
	std::atomic<bool> m_bReturned;
} LINUX_THREAD_OPERATION_CANCEL_DATA, *PLINUX_THREAD_OPERATION_CANCEL_DATA;

typedef struct _LINUX_THREAD_IDENTITY_FORK_DATA {
	_LINUX_THREAD_IDENTITY_FORK_DATA() noexcept;
	std::atomic<bool> m_bReady;
	std::atomic<bool> m_bSignalBlocked;
	std::atomic<bool> m_bForkRequested;
	std::atomic<bool> m_bStop;
	std::atomic<pid_t> m_nChildProcessID;
} LINUX_THREAD_IDENTITY_FORK_DATA, *PLINUX_THREAD_IDENTITY_FORK_DATA;

typedef struct _LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA {
	_LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA() noexcept;
	volatile unsigned int* m_pValue;
} LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA, *PLINUX_MEMORY_HOOK_FORCED_UNWIND_DATA;

typedef struct _LINUX_PTRACE_CANCELLATION_DATA {
	_LINUX_PTRACE_CANCELLATION_DATA() noexcept;
	std::atomic<unsigned int> m_unTargetThreadID;
	std::atomic<unsigned int> m_unTargetIterations;
	std::atomic<bool> m_bStopTarget;
	std::atomic<bool> m_bConfigureReturned;
	std::atomic<bool> m_bHooked;
} LINUX_PTRACE_CANCELLATION_DATA, *PLINUX_PTRACE_CANCELLATION_DATA;

typedef enum _LINUX_SELF_UNHOOK_EVENT {
	LinuxSelfUnHookPreBegin = 0,
	LinuxSelfUnHookPreReturned = 1,
	LinuxSelfUnHookPost = 2
} LINUX_SELF_UNHOOK_EVENT;

_LINUX_WAIT_CANCELLATION_DATA::_LINUX_WAIT_CANCELLATION_DATA() noexcept :
	m_pObject(nullptr),
	m_bSemaphore(false),
	m_bReturned(false)
{
}

_LINUX_PIPE_CANCELLATION_DATA::_LINUX_PIPE_CANCELLATION_DATA() noexcept :
	m_pPipeServer(nullptr),
	m_bReturned(false)
{
}

_LINUX_PENDING_CANCELLATION_DATA::_LINUX_PENDING_CANCELLATION_DATA() noexcept :
	m_pOperation(nullptr),
	m_pContext(nullptr),
	m_bOperationCompleted(false),
	m_bOperationSucceeded(false),
	m_bReturned(false)
{
}

_LINUX_SUSPENDER_CANCELLATION_DATA::_LINUX_SUSPENDER_CANCELLATION_DATA() noexcept :
	m_pSuspender(nullptr),
	m_bOperationCompleted(false),
	m_bReturned(false)
{
}

_LINUX_SUSPENDER_TARGET_DATA::_LINUX_SUSPENDER_TARGET_DATA() noexcept :
	m_bReady(false),
	m_bStop(false),
	m_unIterations(0)
{
}

_LINUX_STALE_SUSPEND_DATA::_LINUX_STALE_SUSPEND_DATA() noexcept :
	m_bReady(false),
	m_bSignalBlocked(false),
	m_bUnblock(false),
	m_bUnblocked(false),
	m_bStop(false),
	m_unIterations(0)
{
}

_LINUX_FORK_THREAD_DATA::_LINUX_FORK_THREAD_DATA() noexcept :
	m_unReady(0),
	m_unCalls(0),
	m_bStop(false)
{
}

_LINUX_THREAD_SUSPEND_DATA::_LINUX_THREAD_SUSPEND_DATA() noexcept :
	m_bReady(false),
	m_bStop(false),
	m_nThreadID(0),
	m_unIterations(0)
{
}

_LINUX_DEEP_STACK_DATA::_LINUX_DEEP_STACK_DATA() noexcept :
	m_bReady(false),
	m_bStop(false),
	m_unStackAddress(0)
{
}

_LINUX_JOIN_CANCEL_DATA::_LINUX_JOIN_CANCEL_DATA() noexcept :
	m_pThread(nullptr),
	m_bStarted(false),
	m_bReturned(false)
{
}

_LINUX_THREAD_OPERATION_CANCEL_DATA::_LINUX_THREAD_OPERATION_CANCEL_DATA() noexcept :
	m_pThread(nullptr),
	m_bSuspend(false),
	m_bStarted(false),
	m_bOperationCompleted(false),
	m_bOperationSucceeded(false),
	m_bReturned(false)
{
}

_LINUX_THREAD_IDENTITY_FORK_DATA::_LINUX_THREAD_IDENTITY_FORK_DATA() noexcept :
	m_bReady(false),
	m_bSignalBlocked(false),
	m_bForkRequested(false),
	m_bStop(false),
	m_nChildProcessID(0)
{
}

_LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA::_LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA() noexcept :
	m_pValue(nullptr)
{
}

_LINUX_PTRACE_CANCELLATION_DATA::_LINUX_PTRACE_CANCELLATION_DATA() noexcept :
	m_unTargetThreadID(0),
	m_unTargetIterations(0),
	m_bStopTarget(false),
	m_bConfigureReturned(false),
	m_bHooked(false)
{
}

Detours::Hook::RawHook g_LinuxRawHook;
Detours::Hook::RawHook g_LinuxFirstCapacityRawHook;
Detours::Hook::RawHook g_LinuxSecondCapacityRawHook;
std::atomic<unsigned int> g_unLinuxRawHookCalls = 0;
std::atomic<unsigned int> g_unLinuxFirstCapacityRawHookCalls = 0;
std::atomic<unsigned int> g_unLinuxSecondCapacityRawHookCalls = 0;
std::atomic<unsigned int> g_unLinuxRawRedirectCalls = 0;
volatile std::sig_atomic_t g_nLinuxExceptionCalls = 0;
volatile std::sig_atomic_t g_nLinuxExceptionContextObserved = 0;
volatile std::sig_atomic_t g_nLinuxFirstExceptionCalls = 0;
volatile std::sig_atomic_t g_nLinuxSecondExceptionCalls = 0;
volatile std::sig_atomic_t g_nLinuxConfiguredExceptionCalls = 0;
volatile std::sig_atomic_t g_nLinuxDestroyedExceptionCalls = 0;
volatile std::sig_atomic_t g_nLinuxResetSignalCalls = 0;
volatile std::sig_atomic_t g_nLinuxSuspendPredecessorCalls = 0;
volatile std::sig_atomic_t g_nLinuxSuspendPredecessorValue = 0;
volatile std::sig_atomic_t g_nLinuxRollbackSignalCalls = 0;
volatile std::sig_atomic_t g_nLinuxSelfUnHookPreCalls = 0;
volatile std::sig_atomic_t g_nLinuxSelfUnHookPostCalls = 0;
volatile std::sig_atomic_t g_nLinuxSelfUnHookResult = 0;
volatile std::sig_atomic_t g_nLinuxSelfUnHookEventCount = 0;
volatile std::sig_atomic_t g_arrLinuxSelfUnHookEvents[kLinuxSelfUnHookEventCapacity] {};
volatile std::sig_atomic_t g_nLinuxVirtualSelfUnHookResult = 0;
std::atomic<bool> g_bLinuxUnHookRaceCallBackEntered = false;
std::atomic<bool> g_bLinuxUnHookRaceCallBackMayContinue = false;
std::atomic<bool> g_bLinuxUnHookRaceCallBackResult = false;
unsigned char g_unLinuxDeepStackSentinel = 0;
volatile std::sig_atomic_t g_nLinuxZeroInterruptCalls = 0;
std::atomic<unsigned int> g_unLinuxConcurrentInstallCalls = 0;
std::atomic<unsigned int> g_unLinuxNestedExceptionCalls = 0;
std::atomic<unsigned int> g_unLinuxNestedExceptionFallbackCalls = 0;
std::atomic<bool> g_bLinuxBlockingExceptionCallBackEntered = false;
std::atomic<bool> g_bLinuxReleaseBlockingExceptionCallBack = false;
std::atomic<bool> g_bLinuxBlockNextExceptionOrderDispatch = false;
std::atomic<bool> g_bLinuxExceptionOrderDispatchBlocked = false;
std::atomic<bool> g_bLinuxReleaseExceptionOrderDispatch = false;
std::atomic<bool> g_bLinuxCycleExceptionOrderCallBack = false;
std::atomic<bool> g_bLinuxExceptionOrderCycleSucceeded = false;
std::atomic<unsigned int> g_unLinuxExceptionForkCallBacksEntered = 0;
std::atomic<bool> g_bLinuxExceptionForkRelease = false;
std::atomic<int> g_nLinuxExceptionForkChildPID = 0;
std::atomic<bool> g_bLinuxNestedExceptionRemovalSucceeded = false;
std::atomic<bool> g_bLinuxConcurrentInstallStop = false;
std::atomic<bool> g_bLinuxResetRaceEntered = false;
std::atomic<int> g_nLinuxExceptionForkOwnerThreadID = 0;
volatile std::sig_atomic_t g_bLinuxExceptionForkChild = 0;
Detours::Exception::ExceptionListener* g_pLinuxExceptionForkListener = nullptr;
Detours::Exception::ExceptionListener* g_pLinuxNestedExceptionListener = nullptr;
Detours::Exception::ExceptionListener* g_pLinuxExceptionOrderListener = nullptr;
std::atomic<unsigned int> g_unLinuxMemoryReadCalls = 0;
std::atomic<unsigned int> g_unLinuxMemoryWriteCalls = 0;
std::atomic<unsigned int> g_unLinuxMemoryExecuteCalls = 0;
std::atomic<unsigned int> g_unLinuxMemoryPostCalls = 0;
std::atomic<unsigned int> g_unLinuxMemoryInvalidCalls = 0;
std::atomic<unsigned int> g_unLinuxMultiRecordFirstPreCalls = 0;
std::atomic<unsigned int> g_unLinuxMultiRecordSecondPreCalls = 0;
std::atomic<unsigned int> g_unLinuxMultiRecordFirstPostCalls = 0;
std::atomic<unsigned int> g_unLinuxMultiRecordSecondPostCalls = 0;
std::atomic<unsigned int> g_unLinuxMultiRecordInvalidCalls = 0;
void* g_pLinuxMultiRecordFirstPage = nullptr;
void* g_pLinuxMultiRecordSecondPage = nullptr;
std::atomic<int> g_nLinuxMemoryHookForkChildPID = 0;
std::atomic<bool> g_bLinuxMemoryHookForkFromPostCallBack = false;
std::atomic<bool> g_bLinuxMemoryHookProtectedLifecycleEntered = false;
std::atomic<bool> g_bLinuxMemoryHookProtectedLifecycleMayContinue = false;
std::atomic<bool> g_bLinuxMemoryHookProtectedLifecycleSucceeded = false;
std::atomic<int> g_nLinuxProtectedSignalForkChildPID = 0;
std::atomic<bool> g_bLinuxProtectedSignalForkParentMayExit = false;
std::atomic<int> g_nLinuxProtectedSignalTargetThreadID = 0;
void const* g_pLinuxProtectedSignalProbeAddress = nullptr;
int g_nLinuxProtectedSignalProbeFileDescriptor = -1;
volatile std::sig_atomic_t g_nLinuxProtectedSignalExpectedSignal = SIGUSR1;
volatile std::sig_atomic_t g_nLinuxProtectedSignalExpectedCode = SI_TKILL;
volatile std::sig_atomic_t g_nLinuxDeferredSignal = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalCode = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalProcessID = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalUserID = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalValue = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalCount = 0;
volatile std::sig_atomic_t g_bLinuxDeferredSignalEnterNestedMask = 0;
volatile std::sig_atomic_t g_bLinuxDeferredSignalFork = 0;
volatile std::sig_atomic_t g_bLinuxDeferredSignalForkChild = 0;
volatile std::sig_atomic_t g_nLinuxDeferredSignalForkChildPID = 0;
volatile std::sig_atomic_t g_nLinuxAsyncFaultSignalCalls = 0;
volatile std::sig_atomic_t g_nLinuxProtectedAtForkSignalCalls = 0;
volatile std::sig_atomic_t g_nLinuxProtectedAtForkNestedChildPID = 0;
volatile std::sig_atomic_t g_bLinuxProtectedAtForkNestedChild = 0;
volatile std::sig_atomic_t g_bLinuxMemoryHookForkAttempted = 0;
volatile std::sig_atomic_t g_bLinuxMemoryHookForkChild = 0;
sigjmp_buf g_LinuxMemoryHookSynchronousFaultJumpBuffer;
volatile std::sig_atomic_t g_nLinuxMemoryHookSynchronousFaultSignal = 0;
volatile std::sig_atomic_t g_bLinuxMemoryHookSynchronousFaultMaskRestored = 0;
volatile std::sig_atomic_t g_bLinuxMemoryHookSynchronousFaultTrapFlagRestored = 0;
volatile std::sig_atomic_t g_bLinuxProtectedSignalForkChild = 0;
std::atomic<unsigned int> g_unLinuxInterruptHookForkCallBacksEntered = 0;
std::atomic<int> g_nLinuxInterruptHookForkChildPID = 0;
std::atomic<bool> g_bLinuxInterruptHookForkRelease = false;
alignas(8) volatile unsigned int g_unLinuxHardwareHookForkValue = 0;
alignas(8) volatile unsigned int g_unLinuxHardwareForcedUnwindValue = 0;
volatile std::sig_atomic_t g_nLinuxHardwareHookForkCalls = 0;
std::atomic<int> g_nLinuxInterruptHookForkOwnerThreadID = 0;
volatile std::sig_atomic_t g_bLinuxInterruptHookForkChild = 0;
volatile std::sig_atomic_t g_bLinuxInterruptHookForkAttempted = 0;
volatile std::sig_atomic_t g_bLinuxInterruptHookForkUnHooked = 0;
volatile std::sig_atomic_t g_nLinuxHookForkSignalCalls = 0;
volatile std::sig_atomic_t g_nLinuxHookForkSignalChildPID = 0;
void* g_pLinuxHookForkSignalAddress = nullptr;
std::size_t g_unLinuxHookForkSignalSize = 0;
void* g_pLinuxSignalAlternateStack = nullptr;
std::size_t g_unLinuxSignalAlternateStackSize = 0;

static bool WaitForChildProcess(pid_t nChildPID, int* pStatus, unsigned int unMilliseconds) {
	if ((nChildPID <= 0) || !pStatus) {
		return false;
	}

	auto const EndTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(unMilliseconds);
	while (true) {
		pid_t const nWaitResult = ::waitpid(nChildPID, pStatus, WNOHANG);
		if (nWaitResult == nChildPID) {
			return true;
		}

		if ((nWaitResult < 0) && (errno != EINTR)) {
			return false;
		}

		if (std::chrono::steady_clock::now() >= EndTime) {
			::kill(nChildPID, SIGKILL);
			while ((::waitpid(nChildPID, pStatus, 0) < 0) && (errno == EINTR)) {
			}

			return false;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}



static bool IsLinuxIsolatedTestProcess(char const* const pTestCase) noexcept {
	char const* const pIsolatedTest = std::getenv(kLinuxIsolatedTestEnvironment);
	return pTestCase && pIsolatedTest && (std::strcmp(pIsolatedTest, pTestCase) == 0);
}

static bool RunLinuxIsolatedTest(char const* const pTestCase, int const nExpectedExitCode = EXIT_SUCCESS) {
	if (!pTestCase || IsLinuxIsolatedTestProcess(pTestCase)) {
		return false;
	}

	std::string const strTestCaseArgument = std::string("--test-case=") + pTestCase;
	std::string const strEnvironmentPrefix = std::string(kLinuxIsolatedTestEnvironment) + "=";
	std::string const strEnvironmentEntry = strEnvironmentPrefix + pTestCase;
	std::vector<char*> vecEnvironment;
	try {
		for (char** pEnvironment = ::environ; pEnvironment && *pEnvironment; ++pEnvironment) {
			if (std::strncmp(*pEnvironment, strEnvironmentPrefix.c_str(), strEnvironmentPrefix.size()) != 0) {
				vecEnvironment.push_back(*pEnvironment);
			}
		}

		vecEnvironment.push_back(const_cast<char*>(strEnvironmentEntry.c_str()));
		vecEnvironment.push_back(nullptr);
	} catch (...) {
		return false;
	}

	char* const arrArguments[] = {
		const_cast<char*>("/proc/self/exe"),
		const_cast<char*>(strTestCaseArgument.c_str()),
		const_cast<char*>("--no-version"),
		const_cast<char*>("--no-intro"),
		const_cast<char*>("--minimal"),
		nullptr
	};
	pid_t nChildPID = 0;
	if (::posix_spawn(&nChildPID, arrArguments[0], nullptr, nullptr, arrArguments, vecEnvironment.data()) != 0) {
		return false;
	}

	int nStatus = 0;
	return WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds * 2) &&
		   WIFEXITED(nStatus) && (WEXITSTATUS(nStatus) == nExpectedExitCode);
}

template <typename HoldFunction, typename WaitFunction>
static bool RunLinuxLockedWaitScenario(unsigned int const unMilliseconds, HoldFunction HoldFunctionObject, WaitFunction WaitFunctionObject) {
	std::atomic<bool> bLocked = false;
	std::atomic<bool> bRelease = false;
	std::atomic<bool> bHoldReturned = false;
	bool bHoldSucceeded = false;
	std::thread HoldThread([&]() {
		bHoldSucceeded = HoldFunctionObject(&bLocked, &bRelease);
		bHoldReturned.store(true, std::memory_order_release);
	});
	auto Cleanup = MakeScopeExit([&bRelease, &HoldThread]() {
		bRelease.store(true, std::memory_order_release);
		if (HoldThread.joinable()) {
			HoldThread.join();
		}
	});

	bool const bHoldReady = WaitForTestCondition([&bLocked, &bHoldReturned]() {
		return bLocked.load(std::memory_order_acquire) || bHoldReturned.load(std::memory_order_acquire);
	},
												 kLinuxChildWaitMilliseconds);
	if (!bHoldReady || !bLocked.load(std::memory_order_acquire)) {
		return false;
	}

	auto const BeginTime = std::chrono::steady_clock::now();
	bool const bWaited = WaitFunctionObject(unMilliseconds);
	std::chrono::steady_clock::duration const ElapsedTime = std::chrono::steady_clock::now() - BeginTime;
	bRelease.store(true, std::memory_order_release);
	HoldThread.join();
	Cleanup.Release();

	unsigned int const unMinimumMilliseconds = unMilliseconds > kLinuxSyncWaitEarlyToleranceMilliseconds
												   ? unMilliseconds - kLinuxSyncWaitEarlyToleranceMilliseconds
												   : 0;
	std::chrono::milliseconds const MinimumTime = std::chrono::milliseconds(unMinimumMilliseconds);
	std::chrono::milliseconds const MaximumTime = std::chrono::milliseconds(unMilliseconds) +
							 std::chrono::milliseconds(kLinuxSyncWaitSlackMilliseconds);
	return bHoldSucceeded && !bWaited && (ElapsedTime >= MinimumTime) && (ElapsedTime <= MaximumTime);
}

template <typename HoldFunction, typename WaitFunction>
static bool RunLinuxLockedNamedWaitScenario(unsigned int const unMilliseconds, HoldFunction HoldFunctionObject, WaitFunction WaitFunctionObject) {
	pid_t const nChildPID = ::fork();
	if (nChildPID < 0) {
		return false;
	}

	if (nChildPID == 0) {
		bool const bSucceeded = RunLinuxLockedWaitScenario(
			unMilliseconds,
			HoldFunctionObject,
			WaitFunctionObject);
		::_exit(bSucceeded ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	int nStatus = 0;
	return WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) &&
		   WIFEXITED(nStatus) && (WEXITSTATUS(nStatus) == EXIT_SUCCESS);
}

static bool WriteTestFileDescriptor(int nFileDescriptor, void const* pData, std::size_t unSize) {
	if ((nFileDescriptor < 0) || !pData || !unSize) {
		return false;
	}

	unsigned char const* pBytes = static_cast<unsigned char const*>(pData);
	std::size_t unWritten = 0;
	while (unWritten < unSize) {
		ssize_t const nResult = ::write(nFileDescriptor, pBytes + unWritten, unSize - unWritten);
		if (nResult > 0) {
			unWritten += static_cast<std::size_t>(nResult);
			continue;
		}

		if ((nResult < 0) && (errno == EINTR)) {
			continue;
		}

		return false;
	}

	return true;
}

static bool ReadTestFileDescriptor(int nFileDescriptor, void* pData, std::size_t unSize) {
	if ((nFileDescriptor < 0) || !pData || !unSize) {
		return false;
	}

	unsigned char* pBytes = static_cast<unsigned char*>(pData);
	std::size_t unRead = 0;
	while (unRead < unSize) {
		ssize_t const nResult = ::read(nFileDescriptor, pBytes + unRead, unSize - unRead);
		if (nResult > 0) {
			unRead += static_cast<std::size_t>(nResult);
			continue;
		}

		if ((nResult < 0) && (errno == EINTR)) {
			continue;
		}

		return false;
	}

	return true;
}

static std::size_t GetTestPageSize() noexcept {
	long const nPageSize = ::sysconf(_SC_PAGESIZE);
	return (nPageSize > 0) ? static_cast<std::size_t>(nPageSize) : 0;
}

static void* OpenLinuxScanTestModule(void** const ppModuleBase) noexcept {
	if (ppModuleBase) {
		*ppModuleBase = nullptr;
	}

	void* const pSymbol = ::dlsym(RTLD_DEFAULT, "cos");
	Dl_info SymbolInformation {};
	if (!pSymbol || (::dladdr(pSymbol, &SymbolInformation) == 0) || !SymbolInformation.dli_fname || !SymbolInformation.dli_fname[0]) {
		return nullptr;
	}

	void* const hModule = ::dlopen(SymbolInformation.dli_fname, RTLD_NOW | RTLD_LOCAL);
	if (hModule && ppModuleBase) {
		*ppModuleBase = SymbolInformation.dli_fbase;
	}

	return hModule;
}

static bool CanProtectLinuxScanTestModule(void* const pModuleBase) noexcept {
	void* const pRuntimeSymbol = ::dlsym(RTLD_DEFAULT, "mprotect");
	Dl_info RuntimeInformation {};
	return pModuleBase && pRuntimeSymbol &&
		   (::dladdr(pRuntimeSymbol, &RuntimeInformation) != 0) &&
		   RuntimeInformation.dli_fbase && (pModuleBase != RuntimeInformation.dli_fbase);
}

static bool ArmLinuxPendingCancellation() {
	int nPreviousType = PTHREAD_CANCEL_DEFERRED;
	int nPreviousState = PTHREAD_CANCEL_ENABLE;
	if ((::pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &nPreviousType) != 0) ||
		(::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &nPreviousState) != 0)) {
		return false;
	}

	if ((nPreviousType != PTHREAD_CANCEL_DEFERRED) || (nPreviousState != PTHREAD_CANCEL_ENABLE) ||
		(::pthread_cancel(::pthread_self()) != 0)) {
		::pthread_setcancelstate(nPreviousState, nullptr);
		::pthread_setcanceltype(nPreviousType, nullptr);
		return false;
	}

	return ::pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) == 0;
}



static void* LinuxPendingCancellationThreadCallBack(void* pData) {
	PLINUX_PENDING_CANCELLATION_DATA const pCancellationData = static_cast<PLINUX_PENDING_CANCELLATION_DATA>(pData);
	if (!pCancellationData || !pCancellationData->m_pOperation || !ArmLinuxPendingCancellation()) {
		return nullptr;
	}

	bool const bSucceeded = pCancellationData->m_pOperation(pCancellationData->m_pContext);
	pCancellationData->m_bOperationSucceeded.store(bSucceeded, std::memory_order_release);
	pCancellationData->m_bOperationCompleted.store(true, std::memory_order_release);
	::pthread_testcancel();
	pCancellationData->m_bReturned.store(true, std::memory_order_release);
	return nullptr;
}

static bool QueryMemoryWithPendingCancellation(void* pContext) {
	if (!pContext) {
		return false;
	}

	Detours::Memory::Page Page(pContext, false, false);
	int nProtection = PROT_NONE;
	return Page.GetPageAddress() && Page.GetProtection(&nProtection) && (nProtection != PROT_NONE);
}

static bool ScanMemoryWithPendingCancellation(void* pContext) {
	std::array<unsigned char, 4>* const pData = static_cast<std::array<unsigned char, 4>*>(pContext);
	return pData &&
		   (Detours::Scan::FindData(pData->data(), pData->size(), pData->data() + 1, 2) == (pData->data() + 1));
}

static bool FindELFSectionWithPendingCancellation(void* pContext) {
	void* pSection = nullptr;
	std::size_t unSectionSize = 0;
	return pContext && Detours::Scan::FindSection(pContext, { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize) &&
		   pSection && unSectionSize;
}

static bool RunLinuxPendingCancellationScenario(fnLinuxPendingCancellationOperation const pOperation, void* const pContext) {
	pid_t const nChildPID = ::fork();
	if (nChildPID < 0) {
		return false;
	}

	if (nChildPID == 0) {
		LINUX_PENDING_CANCELLATION_DATA CancellationData {};
		CancellationData.m_pOperation = pOperation;
		CancellationData.m_pContext = pContext;
		pthread_t hThread {};
		if (::pthread_create(&hThread, nullptr, LinuxPendingCancellationThreadCallBack, &CancellationData) != 0) {
			::_exit(kLinuxCancellationRegressionFailureExitCode);
		}

		void* pThreadResult = nullptr;
		bool const bJoined = ::pthread_join(hThread, &pThreadResult) == 0;
		bool const bSucceeded = bJoined && (pThreadResult == PTHREAD_CANCELED) &&
								CancellationData.m_bOperationCompleted.load(std::memory_order_acquire) &&
								CancellationData.m_bOperationSucceeded.load(std::memory_order_acquire) &&
								!CancellationData.m_bReturned.load(std::memory_order_acquire);
		::_exit(bSucceeded ? EXIT_SUCCESS : kLinuxCancellationRegressionFailureExitCode);
	}

	int nStatus = 0;
	return WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) &&
		   WIFEXITED(nStatus) && (WEXITSTATUS(nStatus) == EXIT_SUCCESS);
}

static void* LinuxNoCancelDestructorThreadCallBack(void* pData) {
	PLINUX_PENDING_CANCELLATION_DATA const pCancellationData = static_cast<PLINUX_PENDING_CANCELLATION_DATA>(pData);
	if (!pCancellationData) {
		return nullptr;
	}

	bool bReady = false;
	{
		Detours::Sync::EventServer EventServer(false, true, false);
		Detours::Sync::MutexServer MutexServer(false, false);
		Detours::Sync::SemaphoreServer SemaphoreServer(false, 0, 1);
		Detours::Memory::SharedServer SharedServer(sizeof(unsigned int), false);
		Detours::Pipe::PipeServer PipeServer(sizeof(unsigned int));
		char szPipeName[Detours::kNamedObjectNameCapacity] {};
		bReady = EventServer.GetEvent() && MutexServer.GetMutex() && SemaphoreServer.GetSemaphore() &&
				 SharedServer.GetAddress() && PipeServer.GetPipeName(szPipeName) && PipeServer.Open();
		if (!bReady || !ArmLinuxPendingCancellation()) {
			return nullptr;
		}
	}

	pCancellationData->m_bOperationSucceeded.store(bReady, std::memory_order_release);
	pCancellationData->m_bOperationCompleted.store(true, std::memory_order_release);
	::pthread_testcancel();
	pCancellationData->m_bReturned.store(true, std::memory_order_release);
	return nullptr;
}

static bool RunLinuxNoCancelDestructorScenario() {
	pid_t const nChildPID = ::fork();
	if (nChildPID < 0) {
		return false;
	}

	if (nChildPID == 0) {
		LINUX_PENDING_CANCELLATION_DATA CancellationData {};
		pthread_t hThread {};
		if (::pthread_create(&hThread, nullptr, LinuxNoCancelDestructorThreadCallBack, &CancellationData) != 0) {
			::_exit(kLinuxCancellationRegressionFailureExitCode);
		}

		void* pThreadResult = nullptr;
		bool const bJoined = ::pthread_join(hThread, &pThreadResult) == 0;
		bool const bSucceeded = bJoined && (pThreadResult == PTHREAD_CANCELED) &&
								CancellationData.m_bOperationCompleted.load(std::memory_order_acquire) &&
								CancellationData.m_bOperationSucceeded.load(std::memory_order_acquire) &&
								!CancellationData.m_bReturned.load(std::memory_order_acquire);
		::_exit(bSucceeded ? EXIT_SUCCESS : kLinuxCancellationRegressionFailureExitCode);
	}

	int nStatus = 0;
	return WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) &&
		   WIFEXITED(nStatus) && (WEXITSTATUS(nStatus) == EXIT_SUCCESS);
}



static long CallProtectedReadSystemCall(void* pCode, int nFileDescriptor, void* pBuffer, std::size_t unSize) noexcept {
	if (!pCode || (nFileDescriptor < 0) || !pBuffer || !unSize) {
		return -1;
	}

#if defined(__x86_64__)
	long nResult = SYS_read;
	__asm__ __volatile__(
		"call *%[CodeAddress]"
		: "+a"(nResult)
		: [CodeAddress] "r"(pCode), "D"(static_cast<long>(nFileDescriptor)), "S"(pBuffer), "d"(unSize)
		: "rcx", "r11", "memory");
	return nResult;
#else
	return -1;
#endif
}

static long CallProtectedUnsafeSystemCall(void* pCode, long const nSystemCall) noexcept {
	if (!pCode) {
		return -1;
	}

#if defined(__x86_64__)
	long nResult = nSystemCall;
	__asm__ __volatile__(
		"call *%[CodeAddress]"
		: "+a"(nResult)
		: [CodeAddress] "r"(pCode)
		: "rcx", "r11", "memory");
	return nResult;
#else
	return -1;
#endif
}

static void CallProtectedMoveStackSegment(void* pCode) noexcept {
	if (!pCode) {
		return;
	}

#if defined(__x86_64__)
	unsigned long unStackSegment = 0;
	__asm__ __volatile__(
		"mov %%ss, %%ax\n\t"
		"call *%[CodeAddress]"
		: "+a"(unStackSegment)
		: [CodeAddress] "r"(pCode)
		: "memory");
#endif
}




static bool LinuxProtectedUnsafeInstructionFailureExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t*) {
	if (Exception.m_nSignal != SIGSEGV) {
		return false;
	}

	if (!g_pLinuxProtectedSignalProbeAddress || (g_nLinuxProtectedSignalProbeFileDescriptor < 0)) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	long const nProbeResult = ::syscall(
		SYS_write,
		g_nLinuxProtectedSignalProbeFileDescriptor,
		g_pLinuxProtectedSignalProbeAddress,
		1);
	bool const bPayloadHidden = (nProbeResult == -1) && (errno == EFAULT);
	::_exit(bPayloadHidden ? EXIT_SUCCESS : kLinuxProtectedSignalMaskFailureExitCode);
}


static bool LinuxAsyncFaultSignalCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t*) {
	if ((Exception.m_nSignal != SIGSEGV) || (Exception.m_nSignalCode != SI_QUEUE)) {
		return false;
	}

	++g_nLinuxAsyncFaultSignalCalls;
	return true;
}

static void* CreateLinuxHookTarget(unsigned int unReturnValue) {
	std::size_t const unPageSize = GetTestPageSize();
	if (unPageSize < kLinuxHookCodeSize) {
		return nullptr;
	}

	void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pMapping == MAP_FAILED) {
		return nullptr;
	}

	unsigned char* const pCode = static_cast<unsigned char*>(pMapping);
	std::memset(pCode, kLinuxNoOperationOpcode, std::min(unPageSize, kLinuxHookCodeSize));
	pCode[0] = kLinuxMoveImmediateOpcode;
	pCode[kLinuxImmediateOffset] = static_cast<unsigned char>(unReturnValue);
	pCode[kLinuxImmediateOffset + 1] = static_cast<unsigned char>(unReturnValue >> kLinuxBitsPerByte);
	pCode[kLinuxImmediateOffset + 2] = static_cast<unsigned char>(unReturnValue >> (kLinuxBitsPerByte * 2));
	pCode[kLinuxImmediateOffset + 3] = static_cast<unsigned char>(unReturnValue >> (kLinuxBitsPerByte * 3));
	pCode[kLinuxReturnCodeSize - 1] = kLinuxReturnOpcode;
	__builtin___clear_cache(reinterpret_cast<char*>(pCode), reinterpret_cast<char*>(pCode + kLinuxHookCodeSize));

	if (::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) {
		::munmap(pMapping, unPageSize);
		return nullptr;
	}

	return pMapping;
}

#if defined(__x86_64__) && defined(MAP_32BIT)
static void* CreateLinuxRedZoneHookTarget() {
	std::size_t const unPageSize = GetTestPageSize();
	if (unPageSize < kLinuxHookCodeSize) {
		return nullptr;
	}

	void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (pMapping == MAP_FAILED) {
		return nullptr;
	}

	unsigned char* const pCode = static_cast<unsigned char*>(pMapping);
	std::memset(pCode, kLinuxNoOperationOpcode, kLinuxHookCodeSize);
	pCode[0] = 0xC7;
	pCode[1] = 0x44;
	pCode[2] = 0x24;
	pCode[3] = 0xF8;
	std::memcpy(pCode + 4, &kLinuxRedZoneValue, sizeof(kLinuxRedZoneValue));
	pCode[kLinuxRedZoneReturnOffset] = 0x8B;
	pCode[kLinuxRedZoneReturnOffset + 1] = 0x44;
	pCode[kLinuxRedZoneReturnOffset + 2] = 0x24;
	pCode[kLinuxRedZoneReturnOffset + 3] = 0xF8;
	pCode[kLinuxRedZoneReturnOffset + 4] = kLinuxReturnOpcode;
	__builtin___clear_cache(reinterpret_cast<char*>(pCode), reinterpret_cast<char*>(pCode + kLinuxHookCodeSize));

	if (::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) {
		::munmap(pMapping, unPageSize);
		return nullptr;
	}

	return pMapping;
}

static void* CreateLinuxRedZoneHookReplacement() {
	std::size_t const unPageSize = GetTestPageSize();
	if (unPageSize < kLinuxHookCodeSize) {
		return nullptr;
	}

	void* const pAddressHint = reinterpret_cast<void*>(kLinuxHighCodeAddressHint);
	void* const pMapping = ::mmap(pAddressHint, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pMapping == MAP_FAILED) {
		return nullptr;
	}

	unsigned char* const pCode = static_cast<unsigned char*>(pMapping);
	std::memset(pCode, kLinuxNoOperationOpcode, kLinuxHookCodeSize);
	pCode[0] = 0x8B;
	pCode[1] = 0x44;
	pCode[2] = 0x24;
	pCode[3] = 0xF8;
	pCode[4] = kLinuxReturnOpcode;
	__builtin___clear_cache(reinterpret_cast<char*>(pCode), reinterpret_cast<char*>(pCode + kLinuxHookCodeSize));

	if (::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) {
		::munmap(pMapping, unPageSize);
		return nullptr;
	}

	return pMapping;
}
#endif

static int LinuxInlineHookReplacement() {
	return static_cast<int>(kLinuxInlineHookValue);
}


static int LinuxRawRedirectTarget() {
	g_unLinuxRawRedirectCalls.fetch_add(1, std::memory_order_relaxed);
	return static_cast<int>(kLinuxRawRedirectValue);
}

static bool LinuxRawHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX) {
		return false;
	}

	g_unLinuxRawHookCalls.fetch_add(1, std::memory_order_relaxed);
	g_LinuxRawHook.CallTrampoline(pCTX);
	return true;
}

static bool LinuxRawSingleRedirectHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX) {
		return false;
	}

	pCTX->m_Stack.Push(LinuxRawRedirectTarget);
	return true;
}

static bool LinuxRawUnsupportedRedirectHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX) {
		return false;
	}

#if defined(DETOURS_ARCH_X64)
	pCTX->m_unRAX = kLinuxRawFailSafeValue;
#elif defined(DETOURS_ARCH_X86)
	pCTX->m_unEAX = kLinuxRawFailSafeValue;
#endif
	pCTX->m_Stack.Push(LinuxRawRedirectTarget);
	pCTX->m_Stack.Push(LinuxRawRedirectTarget);
	return true;
}

__attribute__((noinline)) static int LinuxRawStackValidationTarget(std::uintptr_t, std::uintptr_t) {
	return static_cast<int>(kLinuxRawHookValue);
}

[[noreturn]] static void LinuxRawStackValidationFailureTarget() noexcept {
	::_exit(kLinuxRawStackValidationFailureExitCode);
}

static void SetLinuxRawStackValidationResult(Detours::Hook::PRAW_CONTEXT pCTX) noexcept {
#if defined(DETOURS_ARCH_X64)
	pCTX->m_unRAX = kLinuxRawFailSafeValue;
#elif defined(DETOURS_ARCH_X86)
	pCTX->m_unEAX = kLinuxRawFailSafeValue;
#endif
}

static bool LinuxRawStackGapBelowEntryHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX || !pCTX->m_Stack.GetAddress()) {
		return false;
	}

	void* pReturnAddress = nullptr;
	std::memcpy(&pReturnAddress, pCTX->m_Stack.GetAddress(), sizeof(pReturnAddress));
	SetLinuxRawStackValidationResult(pCTX);
	pCTX->m_Stack.Push(pReturnAddress);
	pCTX->m_Stack.Push(LinuxRawStackValidationFailureTarget);
	return true;
}

static bool LinuxRawStackAboveEntryHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX || !pCTX->m_Stack.GetAddress()) {
		return false;
	}

	static_assert(
		sizeof(&LinuxRawStackValidationFailureTarget) == sizeof(void*),
		"RawHook stack fixtures require code and data pointers with equal size");
	unsigned char* const pEntryStack = static_cast<unsigned char*>(pCTX->m_Stack.GetAddress());
	void* pReturnAddress = nullptr;
	void (*pFailureTarget)() noexcept = LinuxRawStackValidationFailureTarget;
	std::memcpy(&pReturnAddress, pEntryStack, sizeof(pReturnAddress));
	std::memcpy(pEntryStack + sizeof(void*), &pFailureTarget, sizeof(pFailureTarget));
	std::memcpy(pEntryStack + (sizeof(void*) * 2), &pReturnAddress, sizeof(pReturnAddress));
	SetLinuxRawStackValidationResult(pCTX);
	pCTX->m_Stack.SetAddress(pEntryStack + sizeof(void*));
	return true;
}

static bool RunLinuxRawStackValidationScenario(Detours::Hook::fnRawHookCallBack pCallBack) noexcept {
	if (!pCallBack) {
		return false;
	}

	pid_t const nChildPID = ::fork();
	if (nChildPID < 0) {
		return false;
	}

	if (nChildPID == 0) {
		Detours::Hook::RawHook Hook;
		if (!Hook.Set(reinterpret_cast<void*>(LinuxRawStackValidationTarget)) ||
			!Hook.Hook(pCallBack, false, kLinuxRawRedirectReservedStackSize, false)) {
			::_exit(EXIT_FAILURE);
		}

		using fnLinuxRawStackValidationTarget = int (*)(
			std::uintptr_t,
			std::uintptr_t);
		fnLinuxRawStackValidationTarget volatile pTarget = LinuxRawStackValidationTarget;
		bool const bSucceeded =
			(pTarget(1, 2) == static_cast<int>(kLinuxRawFailSafeValue)) &&
			Hook.UnHook() && Hook.Release();
		::_exit(bSucceeded ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	int nStatus = 0;
	pid_t nWaitResult = -1;
	do {
		nWaitResult = ::waitpid(nChildPID, &nStatus, 0);
	} while ((nWaitResult < 0) && (errno == EINTR));
	return (nWaitResult == nChildPID) && WIFEXITED(nStatus) &&
		(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
}

static bool LinuxFirstCapacityRawHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX) {
		return false;
	}

	g_unLinuxFirstCapacityRawHookCalls.fetch_add(1, std::memory_order_relaxed);
	g_LinuxFirstCapacityRawHook.CallTrampoline(pCTX);
	return true;
}

static bool LinuxSecondCapacityRawHookCallBack(Detours::Hook::PRAW_CONTEXT pCTX) {
	if (!pCTX) {
		return false;
	}

	g_unLinuxSecondCapacityRawHookCalls.fetch_add(1, std::memory_order_relaxed);
	g_LinuxSecondCapacityRawHook.CallTrampoline(pCTX);
	return true;
}

static int LinuxVTableRollbackOriginal() {
	return 17;
}

static int LinuxVTableRollbackReplacement() {
	return 29;
}

static bool LinuxZeroInterruptHook(ucontext_t* const pCTX, unsigned char const unInterrupt) {
	if (!pCTX || unInterrupt) {
		return false;
	}

	++g_nLinuxZeroInterruptCalls;
	return true;
}


static bool LinuxBoundaryInterruptHook(ucontext_t* const, unsigned char const) {
	return false;
}

static void LinuxBoundarySignalHandler(int, siginfo_t*, void*) {
	::_exit(kLinuxBoundarySignalExitCode);
}

static void LinuxStaleSuspendThreadCallBack(void* pData) {
	PLINUX_STALE_SUSPEND_DATA const pSuspendData = static_cast<PLINUX_STALE_SUSPEND_DATA>(pData);
	if (!pSuspendData) {
		return;
	}

	sigset_t SignalSet {};
	sigset_t OldSignalSet {};
	sigemptyset(&SignalSet);
	sigaddset(&SignalSet, SIGUSR2);
	bool const bSignalBlocked = pthread_sigmask(SIG_BLOCK, &SignalSet, &OldSignalSet) == 0;
	pSuspendData->m_bSignalBlocked.store(bSignalBlocked, std::memory_order_release);
	pSuspendData->m_bReady.store(true, std::memory_order_release);

	while (!pSuspendData->m_bUnblock.load(std::memory_order_acquire) && !pSuspendData->m_bStop.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}

	if (bSignalBlocked) {
		pthread_sigmask(SIG_SETMASK, &OldSignalSet, nullptr);
	}

	pSuspendData->m_bUnblocked.store(true, std::memory_order_release);

	while (!pSuspendData->m_bStop.load(std::memory_order_acquire)) {
		pSuspendData->m_unIterations.fetch_add(1, std::memory_order_relaxed);
		std::this_thread::yield();
	}
}

static bool LinuxExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const pCTX) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	++g_nLinuxExceptionCalls;
	if (pCTX && Exception.m_pExceptionAddress) {
		g_nLinuxExceptionContextObserved = 1;
	}

	return true;
}

static void LinuxMemoryHookCallBack(ucontext_t* const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pAddress, void const* pAccessAddress) {
	if (!pCTX || !pExceptionAddress || !pAddress || !pAccessAddress) {
		g_unLinuxMemoryInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}

	switch (unOperation) {
		case Detours::Hook::MEMORY_READ:
			g_unLinuxMemoryReadCalls.fetch_add(1, std::memory_order_relaxed);
			break;

		case Detours::Hook::MEMORY_WRITE:
			g_unLinuxMemoryWriteCalls.fetch_add(1, std::memory_order_relaxed);
			break;

		case Detours::Hook::MEMORY_EXECUTE:
			g_unLinuxMemoryExecuteCalls.fetch_add(1, std::memory_order_relaxed);
			break;
	}
}

static void LinuxPostMemoryHookCallBack(ucontext_t* const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION, void const* pAddress, void const* pAccessAddress) {
	if (!pCTX || !pExceptionAddress || !pAddress || !pAccessAddress) {
		g_unLinuxMemoryInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}

	g_unLinuxMemoryPostCalls.fetch_add(1, std::memory_order_relaxed);
}

static void LinuxMemoryHookNoOpCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
}

static void LinuxSynchronousFaultPredecessor(int, siginfo_t*, void*) {
	::_exit(kLinuxSynchronousFaultPredecessorExitCode);
}

static void LinuxMemoryHookIllegalInstructionCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	__asm__ __volatile__("ud2");
	__builtin_unreachable();
}

static bool RunLinuxMemoryHookCallBackSynchronousFaultChild(bool const bPostCallBack) {
	pid_t const nChildPID = ::fork();
	if (nChildPID < 0) {
		return false;
	}

	if (nChildPID == 0) {
		struct sigaction PreviousAction {};
		PreviousAction.sa_sigaction =
			LinuxSynchronousFaultPredecessor;
		PreviousAction.sa_flags = SA_SIGINFO;
		if ((::sigemptyset(&PreviousAction.sa_mask) != 0) ||
			(::sigaction(SIGILL, &PreviousAction, nullptr) != 0)) {
			::_exit(EXIT_FAILURE);
		}

		std::size_t const unPageSize = GetTestPageSize();
		void* const pMapping = unPageSize
			? ::mmap(
				nullptr,
				unPageSize,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1,
				0)
			: MAP_FAILED;
		if (pMapping == MAP_FAILED) {
			::_exit(EXIT_FAILURE);
		}

		volatile unsigned int* const pValue =
			static_cast<volatile unsigned int*>(pMapping);
		*pValue = 0x1357;
		Detours::Hook::fnMemoryHookCallBack const pCallBack = bPostCallBack
			? LinuxMemoryHookNoOpCallBack
			: LinuxMemoryHookIllegalInstructionCallBack;
		Detours::Hook::fnMemoryHookCallBack const pPostCallBack = bPostCallBack
			? LinuxMemoryHookIllegalInstructionCallBack
			: nullptr;
		if (!Detours::Hook::HookMemory(
				pCallBack,
				pMapping,
				sizeof(*pValue),
				pPostCallBack)) {
			::_exit(EXIT_FAILURE);
		}

		*pValue;
		::_exit(EXIT_FAILURE);
	}

	int nStatus = 0;
	return WaitForChildProcess(
			   nChildPID,
			   &nStatus,
			   kLinuxChildWaitMilliseconds) &&
		   WIFEXITED(nStatus) &&
		   (WEXITSTATUS(nStatus) ==
			kLinuxMemoryHookDeferredExitFailureExitCode);
}


static void LinuxMemoryHookPreForcedUnwindCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	::pthread_exit(reinterpret_cast<void*>(kLinuxMemoryPreForcedUnwindResult));
}

static void LinuxMemoryHookPostForcedUnwindCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	::pthread_exit(reinterpret_cast<void*>(kLinuxMemoryPostForcedUnwindResult));
}

static void* LinuxMemoryHookForcedUnwindThreadCallBack(void* const pData) {
	PLINUX_MEMORY_HOOK_FORCED_UNWIND_DATA const pAccessData = static_cast<PLINUX_MEMORY_HOOK_FORCED_UNWIND_DATA>(pData);
	if (!pAccessData || !pAccessData->m_pValue) {
		return nullptr;
	}

	unsigned int const unValue = *pAccessData->m_pValue;
	return reinterpret_cast<void*>(static_cast<std::uintptr_t>(unValue));
}

static void LinuxMultiRecordMemoryHookCallBack(ucontext_t* const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pAddress, void const* pAccessAddress) {
	if (!pCTX || !pExceptionAddress || !pAddress || !pAccessAddress ||
		(unOperation != Detours::Hook::MEMORY_WRITE)) {
		g_unLinuxMultiRecordInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}

	if (pAddress == g_pLinuxMultiRecordFirstPage) {
		g_unLinuxMultiRecordFirstPreCalls.fetch_add(1, std::memory_order_relaxed);
	} else if (pAddress == g_pLinuxMultiRecordSecondPage) {
		g_unLinuxMultiRecordSecondPreCalls.fetch_add(1, std::memory_order_relaxed);
	} else {
		g_unLinuxMultiRecordInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}
}

static void LinuxMultiRecordPostMemoryHookCallBack(ucontext_t* const pCTX, void const* pExceptionAddress, Detours::Hook::MEMORY_HOOK_OPERATION unOperation, void const* pAddress, void const* pAccessAddress) {
	if (!pCTX || !pExceptionAddress || !pAddress || !pAccessAddress ||
		(unOperation != Detours::Hook::MEMORY_WRITE)) {
		g_unLinuxMultiRecordInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}

	if (pAddress == g_pLinuxMultiRecordFirstPage) {
		g_unLinuxMultiRecordFirstPostCalls.fetch_add(1, std::memory_order_relaxed);
	} else if (pAddress == g_pLinuxMultiRecordSecondPage) {
		g_unLinuxMultiRecordSecondPostCalls.fetch_add(1, std::memory_order_relaxed);
	} else {
		g_unLinuxMultiRecordInvalidCalls.fetch_add(1, std::memory_order_relaxed);
	}
}

#if defined(DETOURS_ARCH_X64)
static std::uint64_t LinuxCrossPageExchangeAdd(void* const pAddress, std::uint64_t unAddend) noexcept {
	__asm__ __volatile__(
		"xaddq %0, (%1)"
		: "+r"(unAddend)
		: "r"(pAddress)
		: "cc", "memory");
	return unAddend;
}
#elif defined(DETOURS_ARCH_X86)
static std::uint32_t LinuxCrossPageExchangeAdd(void* const pAddress, std::uint32_t unAddend) noexcept {
	__asm__ __volatile__(
		"xaddl %0, (%1)"
		: "+r"(unAddend)
		: "r"(pAddress)
		: "cc", "memory");
	return unAddend;
}
#endif

static void LinuxMemoryHookProtectedLifecycleCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	g_bLinuxMemoryHookProtectedLifecycleEntered.store(true, std::memory_order_release);
	while (!g_bLinuxMemoryHookProtectedLifecycleMayContinue.load(std::memory_order_acquire)) {
		__asm__ __volatile__("pause");
	}

	Detours::Memory::SecurePage Page;
	g_bLinuxMemoryHookProtectedLifecycleSucceeded.store(
		Page.GetPageAddress() && Page.Release(),
		std::memory_order_release);
}

static void ForkFromLinuxMemoryHookCallBack(bool const bPostCallBack) noexcept {
	if ((g_bLinuxMemoryHookForkFromPostCallBack.load(std::memory_order_acquire) != bPostCallBack) ||
		g_bLinuxMemoryHookForkAttempted) {
		return;
	}

	g_bLinuxMemoryHookForkAttempted = 1;
	pid_t const nChildPID = ::fork();
	if (nChildPID == 0) {
		g_bLinuxMemoryHookForkChild = 1;
	} else {
		g_nLinuxMemoryHookForkChildPID.store(static_cast<int>(nChildPID), std::memory_order_release);
	}
}

static void LinuxMemoryHookForkCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	ForkFromLinuxMemoryHookCallBack(false);
}

static void LinuxMemoryHookForkPostCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	ForkFromLinuxMemoryHookCallBack(true);
}

static bool VerifyLinuxProtectedRegistryConcurrency() {
	std::atomic<bool> bSucceeded = true;
	std::vector<std::thread> vecThreads;
	try {
		vecThreads.reserve(kLinuxProtectedRegistryThreadCount);
		for (std::size_t unThread = 0; unThread < kLinuxProtectedRegistryThreadCount; ++unThread) {
			vecThreads.emplace_back([&bSucceeded]() {
				for (std::size_t unIteration = 0; unIteration < kLinuxProtectedRegistryIterationCount; ++unIteration) {
					Detours::Memory::SecurePage Page;
					if (!Page.GetPageAddress() || !Page.Release()) {
						bSucceeded.store(false, std::memory_order_release);
						return;
					}
				}
			});
		}
	} catch (...) {
		bSucceeded.store(false, std::memory_order_release);
	}

	for (auto& Thread : vecThreads) {
		if (Thread.joinable()) {
			Thread.join();
		}
	}

	return bSucceeded.load(std::memory_order_acquire);
}

static void ChurnLinuxProtectedMemoryForFork(std::atomic<bool>* const pStop, std::atomic<bool>* const pSucceeded, std::atomic<unsigned int>* const pIterations) {
	if (!pStop || !pSucceeded || !pIterations) {
		return;
	}

	while (!pStop->load(std::memory_order_acquire)) {
		Detours::Memory::SecurePage Page;
		if (!Page.GetPageAddress() || !Page.Release()) {
			pSucceeded->store(false, std::memory_order_release);
			return;
		}

		pIterations->fetch_add(1, std::memory_order_release);
	}
}

static bool LinuxInterruptHookForkCallBack(ucontext_t* const, unsigned char const unInterrupt) {
	if (unInterrupt != 0) {
		return false;
	}

	g_unLinuxInterruptHookForkCallBacksEntered.fetch_add(1, std::memory_order_release);
	while (g_unLinuxInterruptHookForkCallBacksEntered.load(std::memory_order_acquire) < 2) {
		__asm__ __volatile__("pause");
	}

	int const nThreadID = static_cast<int>(::syscall(SYS_gettid));
	bool const bOwner =
		g_nLinuxInterruptHookForkOwnerThreadID.load(std::memory_order_acquire) == nThreadID;
	if (bOwner && !g_bLinuxInterruptHookForkAttempted) {
		g_bLinuxInterruptHookForkAttempted = 1;
		pid_t const nChildPID = ::fork();
		if (nChildPID == 0) {
			g_nLinuxInterruptHookForkOwnerThreadID.store(
				static_cast<int>(::syscall(SYS_gettid)),
				std::memory_order_release);
			g_bLinuxInterruptHookForkChild = 1;
			g_bLinuxInterruptHookForkUnHooked =
				Detours::Hook::UnHookInterrupt(LinuxInterruptHookForkCallBack) ? 1 : 0;
		} else {
			g_nLinuxInterruptHookForkChildPID.store(static_cast<int>(nChildPID), std::memory_order_release);
			g_bLinuxInterruptHookForkRelease.store(true, std::memory_order_release);
		}
	} else if (!bOwner) {
		while (!g_bLinuxInterruptHookForkRelease.load(std::memory_order_acquire)) {
			__asm__ __volatile__("pause");
		}
	}

	return true;
}

static bool LinuxInterruptHookForcedUnwindCallBack(ucontext_t* const, unsigned char const unInterrupt) {
	if (unInterrupt != 0) {
		return false;
	}

	::pthread_exit(reinterpret_cast<void*>(kLinuxInterruptForcedUnwindResult));
}

static void* LinuxInterruptHookForcedUnwindThreadCallBack(void* const pData) {
	if (!pData) {
		return nullptr;
	}

	int const nResult = reinterpret_cast<fnLinuxHookTarget>(pData)();
	return reinterpret_cast<void*>(static_cast<std::uintptr_t>(nResult));
}

static void LinuxHardwareHookForkCallBack(ucontext_t* const pCTX) {
	if (pCTX) {
		++g_nLinuxHardwareHookForkCalls;
	}
}

static void InvokeLinuxInterruptHookFork(unsigned char* const pCode, bool const bOwner, std::atomic<int>* const pResult) {
	if (!pCode || !pResult) {
		return;
	}

	if (bOwner) {
		g_nLinuxInterruptHookForkOwnerThreadID.store(
			static_cast<int>(::syscall(SYS_gettid)),
			std::memory_order_release);
		g_bLinuxInterruptHookForkChild = 0;
		g_bLinuxInterruptHookForkAttempted = 0;
		g_bLinuxInterruptHookForkUnHooked = 0;
	}

	int const nResult = reinterpret_cast<fnLinuxHookTarget>(pCode)();
	if (g_bLinuxInterruptHookForkChild) {
		bool const bReHooked = g_bLinuxInterruptHookForkUnHooked &&
							   Detours::Hook::HookInterrupt(LinuxInterruptHookForkCallBack, 0);
		int const nSecondResult = bReHooked ? reinterpret_cast<fnLinuxHookTarget>(pCode)() : 0;
		bool const bSecondUnHooked = bReHooked &&
									 Detours::Hook::UnHookInterrupt(LinuxInterruptHookForkCallBack);
		bool const bSuccess = (nResult == 42) && (nSecondResult == 42) && bSecondUnHooked;
		::munmap(pCode, GetTestPageSize());
		::_exit(bSuccess ? 0 : kLinuxInterruptHookForkFailureExitCode);
	}

	pResult->store(nResult, std::memory_order_release);
	if (bOwner) {
		g_nLinuxInterruptHookForkOwnerThreadID.store(0, std::memory_order_release);
	}
}

static bool RunLinuxMemoryHookForcedUnwindScenario(bool const bPostCallBack) {
	std::size_t const unPageSize = GetTestPageSize();
	if (!unPageSize) {
		return false;
	}

	void* const pMapping = ::mmap(
		nullptr,
		unPageSize,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0);
	if (pMapping == MAP_FAILED) {
		return false;
	}

	volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
	*pValue = 17;
	Detours::Hook::fnMemoryHookCallBack const pCallBack = bPostCallBack
															  ? LinuxMemoryHookNoOpCallBack
															  : LinuxMemoryHookPreForcedUnwindCallBack;
	Detours::Hook::fnMemoryHookCallBack const pPostCallBack = bPostCallBack
																  ? LinuxMemoryHookPostForcedUnwindCallBack
																  : nullptr;
	if (!Detours::Hook::HookMemory(pCallBack, pMapping, sizeof(*pValue), pPostCallBack)) {
		::munmap(pMapping, unPageSize);
		return false;
	}

	LINUX_MEMORY_HOOK_FORCED_UNWIND_DATA AccessData;
	AccessData.m_pValue = pValue;
	pthread_t hAccessThread {};
	if (::pthread_create(&hAccessThread, nullptr, LinuxMemoryHookForcedUnwindThreadCallBack, &AccessData) != 0) {
		Detours::Hook::UnHookMemory(pCallBack, pMapping);
		::munmap(pMapping, unPageSize);
		return false;
	}

	void* pThreadResult = nullptr;
	bool const bJoined = ::pthread_join(hAccessThread, &pThreadResult) == 0;
	void const* const pExpectedResult = reinterpret_cast<void*>(
		bPostCallBack ? kLinuxMemoryPostForcedUnwindResult : kLinuxMemoryPreForcedUnwindResult);
	bool const bUnHooked = Detours::Hook::UnHookMemory(pCallBack, pMapping);
	bool const bUnmapped = ::munmap(pMapping, unPageSize) == 0;
	return bJoined && (pThreadResult == pExpectedResult) && bUnHooked && bUnmapped;
}

static bool RunLinuxInterruptHookForcedUnwindScenario() {
	std::size_t const unPageSize = GetTestPageSize();
	if (!unPageSize) {
		return false;
	}

	void* const pMapping = ::mmap(
		nullptr,
		unPageSize,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0);
	if (pMapping == MAP_FAILED) {
		return false;
	}

	unsigned char const arrCode[] = { 0xCD, 0x00, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
	std::memcpy(pMapping, arrCode, sizeof(arrCode));
	__builtin___clear_cache(
		static_cast<char*>(pMapping),
		static_cast<char*>(pMapping) + sizeof(arrCode));
	if (::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) {
		::munmap(pMapping, unPageSize);
		return false;
	}

	if (!Detours::Hook::HookInterrupt(LinuxInterruptHookForcedUnwindCallBack, 0)) {
		::munmap(pMapping, unPageSize);
		return false;
	}

	pthread_t hAccessThread {};
	if (::pthread_create(&hAccessThread, nullptr, LinuxInterruptHookForcedUnwindThreadCallBack, pMapping) != 0) {
		Detours::Hook::UnHookInterrupt(LinuxInterruptHookForcedUnwindCallBack);
		::munmap(pMapping, unPageSize);
		return false;
	}

	void* pThreadResult = nullptr;
	bool const bJoined = ::pthread_join(hAccessThread, &pThreadResult) == 0;
	bool const bUnHooked = Detours::Hook::UnHookInterrupt(LinuxInterruptHookForcedUnwindCallBack);
	bool const bUnmapped = ::munmap(pMapping, unPageSize) == 0;
	return bJoined &&
		   (pThreadResult == reinterpret_cast<void*>(kLinuxInterruptForcedUnwindResult)) &&
		   bUnHooked && bUnmapped;
}

static void LinuxHardwareHookForcedUnwindCallBack(ucontext_t* const) {
	::pthread_exit(reinterpret_cast<void*>(kLinuxHardwareForcedUnwindResult));
}


static void* LinuxHardwareHookForcedUnwindThreadCallBack(void*) {
	if (!Detours::Hook::HookHardware(
			0,
			Detours::Hook::REGISTER_DR0,
			LinuxHardwareHookForcedUnwindCallBack,
			const_cast<unsigned int*>(&g_unLinuxHardwareForcedUnwindValue),
			Detours::Hook::TYPE_WRITE,
			sizeof(g_unLinuxHardwareForcedUnwindValue))) {
		return reinterpret_cast<void*>(kLinuxHardwareUnavailableResult);
	}

	g_unLinuxHardwareForcedUnwindValue = g_unLinuxHardwareForcedUnwindValue + 1;
	return nullptr;
}



static int RunLinuxHardwareHookForcedUnwindScenario() {
	pthread_t hAccessThread {};
	if (::pthread_create(&hAccessThread, nullptr, LinuxHardwareHookForcedUnwindThreadCallBack, nullptr) != 0) {
		return kLinuxHookForcedUnwindFailureExitCode;
	}

	void* pThreadResult = nullptr;
	if (::pthread_join(hAccessThread, &pThreadResult) != 0) {
		return kLinuxHookForcedUnwindFailureExitCode;
	}

	if (pThreadResult == reinterpret_cast<void*>(kLinuxHardwareUnavailableResult)) {
		return kLinuxHardwareHookForcedUnwindUnavailableExitCode;
	}

	bool const bUnHooked = Detours::Hook::UnHookHardware(0, Detours::Hook::REGISTER_DR0);
	return (pThreadResult == reinterpret_cast<void*>(kLinuxHardwareForcedUnwindResult)) && bUnHooked
			   ? EXIT_SUCCESS
			   : kLinuxHookForcedUnwindFailureExitCode;
}

static void RecordLinuxSelfUnHookEvent(LINUX_SELF_UNHOOK_EVENT Event) {
	std::sig_atomic_t const nEventIndex = g_nLinuxSelfUnHookEventCount;
	if ((nEventIndex >= 0) && (static_cast<std::size_t>(nEventIndex) < (sizeof(g_arrLinuxSelfUnHookEvents) / sizeof(g_arrLinuxSelfUnHookEvents[0])))) {
		g_arrLinuxSelfUnHookEvents[nEventIndex] = static_cast<std::sig_atomic_t>(Event);
	}

	++g_nLinuxSelfUnHookEventCount;
}

static void LinuxSelfUnHookMemoryCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const* pHookAddress, void const*) {
	++g_nLinuxSelfUnHookPreCalls;
	RecordLinuxSelfUnHookEvent(LinuxSelfUnHookPreBegin);
	g_nLinuxSelfUnHookResult = Detours::Hook::UnHookMemory(LinuxSelfUnHookMemoryCallBack, const_cast<void*>(pHookAddress)) ? 1 : -1;
	RecordLinuxSelfUnHookEvent(LinuxSelfUnHookPreReturned);
}

static void LinuxSelfUnHookPostMemoryCallBack(ucontext_t* const, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const*, void const*) {
	++g_nLinuxSelfUnHookPostCalls;
	RecordLinuxSelfUnHookEvent(LinuxSelfUnHookPost);
}

#if defined(DETOURS_ARCH_X64)
__attribute__((naked, noinline)) static void TriggerLinuxVirtualMemoryRead(void*) {
	__asm__(
		"mov (%rdi), %eax\n\t"
		"ret\n\t");
}
#elif defined(DETOURS_ARCH_X86)
__attribute__((naked, noinline)) static void TriggerLinuxVirtualMemoryRead(void*) {
	__asm__(
		"mov 4(%esp), %eax\n\t"
		"mov (%eax), %eax\n\t"
		"ret\n\t");
}
#endif

static void LinuxVirtualSelfUnHookMemoryCallBack(ucontext_t* const pCTX, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const* pHookAddress, void const*) {
	if (!pCTX || !pHookAddress) {
		g_nLinuxVirtualSelfUnHookResult = -1;
		return;
	}

#if defined(DETOURS_ARCH_X64)
	pCTX->uc_mcontext.gregs[REG_RIP] += 2;
#elif defined(DETOURS_ARCH_X86)
	pCTX->uc_mcontext.gregs[REG_EIP] += 2;
#endif
	g_nLinuxVirtualSelfUnHookResult = Detours::Hook::UnHookMemory(LinuxVirtualSelfUnHookMemoryCallBack, const_cast<void*>(pHookAddress)) ? 1 : -1;
}

static void LinuxUnHookRaceMemoryCallBack(ucontext_t*, void const*, Detours::Hook::MEMORY_HOOK_OPERATION, void const* pHookAddress, void const*) {
	g_bLinuxUnHookRaceCallBackEntered.store(true, std::memory_order_release);
	while (!g_bLinuxUnHookRaceCallBackMayContinue.load(std::memory_order_acquire)) {
		__asm__ __volatile__("pause");
	}

	g_bLinuxUnHookRaceCallBackResult.store(
		pHookAddress && Detours::Hook::UnHookMemory(LinuxUnHookRaceMemoryCallBack, const_cast<void*>(pHookAddress)),
		std::memory_order_release);
}

static void ResetLinuxMemoryHookCounters() {
	g_unLinuxMemoryReadCalls.store(0, std::memory_order_relaxed);
	g_unLinuxMemoryWriteCalls.store(0, std::memory_order_relaxed);
	g_unLinuxMemoryExecuteCalls.store(0, std::memory_order_relaxed);
	g_unLinuxMemoryPostCalls.store(0, std::memory_order_relaxed);
	g_unLinuxMemoryInvalidCalls.store(0, std::memory_order_relaxed);
}

static bool WaitForLinuxMemoryHookCalls(unsigned int unMinimumCalls, unsigned int unMilliseconds) {
	auto const EndTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(unMilliseconds);
	while ((g_unLinuxMemoryReadCalls.load(std::memory_order_relaxed) + g_unLinuxMemoryWriteCalls.load(std::memory_order_relaxed)) < unMinimumCalls) {
		if (std::chrono::steady_clock::now() >= EndTime) {
			return false;
		}

		std::this_thread::yield();
	}

	return true;
}

static void LinuxThreadCallBack(void* pData) {
	std::atomic<unsigned int>* const pCalls = static_cast<std::atomic<unsigned int>*>(pData);
	if (!pCalls) {
		return;
	}

	pCalls->fetch_add(1, std::memory_order_relaxed);
}

static void LinuxPthreadExitCallBack(void*) {
	::pthread_exit(nullptr);
}

static void LinuxSelfCancelCallBack(void*) {
	::pthread_cancel(::pthread_self());
	::pthread_testcancel();
}

static void LinuxFiberPthreadExitCallBack(void*) {
	::pthread_exit(nullptr);
}

static void LinuxFiberForcedUnwindCallBack(void*) {
	Detours::Parallel::Fiber Fiber(LinuxFiberPthreadExitCallBack);
	Fiber.Switch();
}

static void* LinuxJoinCancelCallBack(void* pData) {
	PLINUX_JOIN_CANCEL_DATA const pJoinData = static_cast<PLINUX_JOIN_CANCEL_DATA>(pData);
	if (!pJoinData || !pJoinData->m_pThread) {
		return nullptr;
	}

	pJoinData->m_bStarted.store(true, std::memory_order_release);
	pJoinData->m_pThread->Join();
	pJoinData->m_bReturned.store(true, std::memory_order_release);
	return nullptr;
}



static void LinuxForkThreadCallBack(void* pData) {
	PLINUX_FORK_THREAD_DATA const pForkData = static_cast<PLINUX_FORK_THREAD_DATA>(pData);
	if (!pForkData) {
		return;
	}

	pForkData->m_unCalls.fetch_add(1, std::memory_order_relaxed);
	pForkData->m_unReady.fetch_add(1, std::memory_order_release);
	while (!pForkData->m_bStop.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
}

static void LinuxThreadSuspendCallBack(void* pData) {
	PLINUX_THREAD_SUSPEND_DATA const pSuspendData = static_cast<PLINUX_THREAD_SUSPEND_DATA>(pData);
	if (!pSuspendData) {
		return;
	}

	pSuspendData->m_nThreadID.store(
		static_cast<pid_t>(::syscall(SYS_gettid)),
		std::memory_order_relaxed);
	pSuspendData->m_bReady.store(true, std::memory_order_release);
	while (!pSuspendData->m_bStop.load(std::memory_order_acquire)) {
		pSuspendData->m_unIterations.fetch_add(1, std::memory_order_relaxed);
		std::this_thread::yield();
	}
}

static void* LinuxDeepStackCallBack(void* pData) {
	PLINUX_DEEP_STACK_DATA const pStackData = static_cast<PLINUX_DEEP_STACK_DATA>(pData);
	if (!pStackData) {
		return nullptr;
	}

	std::array<unsigned char, kLinuxDeepStackAllocationSize> arrStack {};
	pStackData->m_unStackAddress.store(
		reinterpret_cast<std::uintptr_t>(arrStack.data()),
		std::memory_order_relaxed);
	__asm__ volatile("" : : "r"(arrStack.data()) : "memory");
	pStackData->m_bReady.store(true, std::memory_order_release);
	while (!pStackData->m_bStop.load(std::memory_order_acquire)) {
		__asm__ volatile("" : : "r"(arrStack.data()) : "memory");
		std::this_thread::yield();
	}

	return nullptr;
}

static bool LinuxExceptionForcedUnwindCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const&, ucontext_t* const) {
	::pthread_exit(nullptr);
}


static void LinuxExceptionForcedUnwindThreadCallBack(void* pData) {
	std::atomic<bool>* const pReturned = static_cast<std::atomic<bool>*>(pData);
	::raise(SIGTRAP);
	if (pReturned) {
		pReturned->store(true, std::memory_order_release);
	}
}

static bool LinuxFirstExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const&, ucontext_t* const) {
	++g_nLinuxFirstExceptionCalls;
	if (g_bLinuxCycleExceptionOrderCallBack.exchange(false, std::memory_order_acq_rel)) {
		Detours::Exception::ExceptionListener* const pListener = g_pLinuxExceptionOrderListener;
		bool const bSucceeded = pListener &&
								pListener->RemoveCallBack(LinuxFirstExceptionCallBack) &&
								pListener->AddCallBack(LinuxFirstExceptionCallBack) &&
								pListener->RemoveCallBack(LinuxFirstExceptionCallBack) &&
								pListener->AddCallBack(LinuxFirstExceptionCallBack);
		g_bLinuxExceptionOrderCycleSucceeded.store(bSucceeded, std::memory_order_release);
	}

	return true;
}

static bool LinuxSecondExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const&, ucontext_t* const) {
	++g_nLinuxSecondExceptionCalls;
	return false;
}

static bool LinuxBlockingExceptionOrderCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const&, ucontext_t* const) {
	if (!g_bLinuxBlockNextExceptionOrderDispatch.exchange(false, std::memory_order_acq_rel)) {
		return false;
	}

	g_bLinuxExceptionOrderDispatchBlocked.store(true, std::memory_order_release);
	while (!g_bLinuxReleaseExceptionOrderDispatch.load(std::memory_order_acquire)) {
		std::atomic_signal_fence(std::memory_order_seq_cst);
	}

	return false;
}

static bool LinuxExceptionOrderFallback(Detours::Exception::SIGNAL_EXCEPTION_RECORD const&, ucontext_t* const) {
	return true;
}

static bool LinuxErrnoExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	errno = EOVERFLOW;
	return true;
}

static bool LinuxConfiguredExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	++g_nLinuxConfiguredExceptionCalls;
	return true;
}

static bool LinuxDestroyedExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	++g_nLinuxDestroyedExceptionCalls;
	return true;
}

static bool LinuxExceptionCallBackFallback(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	return Exception.m_nSignal == SIGTRAP;
}

static bool LinuxDestroyedExceptionCallBackFallback(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	return Exception.m_nSignal == SIGTRAP;
}

static void LinuxMaskedOnStackSignalHandler(int, siginfo_t*, void*) {
	sigset_t SignalMask {};
	if (::sigprocmask(SIG_SETMASK, nullptr, &SignalMask) != 0) {
		::_exit(kLinuxSignalChainingFailureExitCode);
	}

	if ((::sigismember(&SignalMask, SIGILL) != 1) || (::sigismember(&SignalMask, SIGUSR1) != 1)) {
		::_exit(kLinuxSignalChainingFailureExitCode);
	}

	volatile unsigned char unStackMarker = 0;
	std::uintptr_t const unStackAddress = reinterpret_cast<std::uintptr_t>(&unStackMarker);
	std::uintptr_t const unAlternateStackBegin = reinterpret_cast<std::uintptr_t>(g_pLinuxSignalAlternateStack);
	std::uintptr_t const unAlternateStackEnd = unAlternateStackBegin + g_unLinuxSignalAlternateStackSize;
	if ((unStackAddress < unAlternateStackBegin) || (unStackAddress >= unAlternateStackEnd)) {
		::_exit(kLinuxSignalChainingFailureExitCode);
	}

	::_exit(kLinuxSignalChainingSuccessExitCode);
}

static void LinuxResetSignalHandler(int, siginfo_t*, void*) {
	++g_nLinuxResetSignalCalls;
}

static void LinuxSuspendPredecessorSignalHandler(int, siginfo_t* pInfo, void*) {
	++g_nLinuxSuspendPredecessorCalls;
	if (pInfo) {
		g_nLinuxSuspendPredecessorValue = pInfo->si_value.sival_int;
	}

	errno = EOVERFLOW;
}

static void LinuxConcurrentInstallSignalHandler(int, siginfo_t*, void*) {
	g_unLinuxConcurrentInstallCalls.fetch_add(1, std::memory_order_relaxed);
}

static void LinuxRollbackSignalHandler(int, siginfo_t*, void*) {
	++g_nLinuxRollbackSignalCalls;
}

static void LinuxExternalReplacementSignalHandler(int, siginfo_t*, void*) {
	::_exit(kLinuxSignalChainingSuccessExitCode);
}

static void LinuxResetRaceSignalHandler(int, siginfo_t*, void*) {
	g_bLinuxResetRaceEntered.store(true, std::memory_order_release);
	for (;;) {
		::pause();
	}
}


static bool LinuxExceptionForkCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	g_unLinuxExceptionForkCallBacksEntered.fetch_add(1, std::memory_order_release);
	while (g_unLinuxExceptionForkCallBacksEntered.load(std::memory_order_acquire) < 2) {
		std::atomic_signal_fence(std::memory_order_seq_cst);
	}

	int const nThreadID = static_cast<int>(::syscall(SYS_gettid));
	if (g_nLinuxExceptionForkOwnerThreadID.load(std::memory_order_acquire) == nThreadID) {
		pid_t const nChildPID = ::fork();
		if (nChildPID == 0) {
			g_nLinuxExceptionForkOwnerThreadID.store(
				static_cast<int>(::syscall(SYS_gettid)),
				std::memory_order_release);
			g_bLinuxExceptionForkChild = 1;
			return true;
		}

		g_nLinuxExceptionForkChildPID.store(static_cast<int>(nChildPID), std::memory_order_release);
	}

	while (!g_bLinuxExceptionForkRelease.load(std::memory_order_acquire)) {
		std::atomic_signal_fence(std::memory_order_seq_cst);
	}

	return true;
}

static bool LinuxNestedExceptionCallBack(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	unsigned int const unCalls = g_unLinuxNestedExceptionCalls.fetch_add(1, std::memory_order_relaxed) + 1;
	if (unCalls == 1) {
		::raise(SIGTRAP);
	} else if ((unCalls == 2) && g_pLinuxNestedExceptionListener) {
		g_bLinuxNestedExceptionRemovalSucceeded.store(
			g_pLinuxNestedExceptionListener->RemoveCallBack(LinuxNestedExceptionCallBack), std::memory_order_release);
	}

	return true;
}

static bool LinuxNestedExceptionFallback(Detours::Exception::SIGNAL_EXCEPTION_RECORD const& Exception, ucontext_t* const) {
	if (Exception.m_nSignal != SIGTRAP) {
		return false;
	}

	g_unLinuxNestedExceptionFallbackCalls.fetch_add(1, std::memory_order_relaxed);
	return true;
}

static bool InstallLinuxSigactionFailureFilter(int const nSignal) noexcept {
	struct sock_filter arrFilter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(nSignal), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog Program {};
	Program.len = static_cast<unsigned short>(sizeof(arrFilter) / sizeof(arrFilter[0]));
	Program.filter = arrFilter;
	return (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) &&
		   (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &Program) == 0);
}

static bool InstallLinuxSigactionRestoreFailureFilter(int const nSignal) noexcept {
	struct sock_filter arrFilter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 7),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(nSignal), 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]) + sizeof(unsigned int)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog Program {};
	Program.len = static_cast<unsigned short>(sizeof(arrFilter) / sizeof(arrFilter[0]));
	Program.filter = arrFilter;
	return (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) &&
		   (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &Program) == 0);
}

[[noreturn]] static void RunLinuxProtectedUnsafeInstructionScenario(LinuxProtectedUnsafeInstructionFixture const unFixture) {
	g_pLinuxProtectedSignalProbeAddress = nullptr;
	g_nLinuxProtectedSignalProbeFileDescriptor = -1;

	Detours::Exception::ExceptionListener SignalListener;
	if (!SignalListener.AddCallBack(LinuxProtectedUnsafeInstructionFailureExceptionCallBack) ||
		!SignalListener.EnableHandler()) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	int nProbePipeFileDescriptors[kLinuxPipeFileDescriptorCount] = { -1, -1 };
	if (::pipe(nProbePipeFileDescriptors) != 0) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	int const nProbeFlags = ::fcntl(nProbePipeFileDescriptors[1], F_GETFL, 0);
	if ((nProbeFlags < 0) || (::fcntl(nProbePipeFileDescriptors[1], F_SETFL, nProbeFlags | O_NONBLOCK) != 0)) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	g_nLinuxProtectedSignalProbeFileDescriptor = nProbePipeFileDescriptors[1];

	Detours::Memory::SecurePage SecurePage;
	volatile unsigned char* const pCode = static_cast<volatile unsigned char*>(SecurePage.Alloc(3));
	if (!pCode) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	if (unFixture == LinuxProtectedUnsafeInstructionFixture::MOVE_STACK_SEGMENT) {
		pCode[0] = kLinuxMoveStackSegmentOpcode;
		pCode[1] = kLinuxMoveStackSegmentAXModRM;
	} else {
		pCode[0] = kLinuxSystemCallFirstOpcode;
		pCode[1] = kLinuxSystemCallSecondOpcode;
	}

	pCode[2] = kLinuxReturnOpcode;
	g_pLinuxProtectedSignalProbeAddress = const_cast<unsigned char*>(pCode);
	if (!SecurePage.IsSecured()) {
		::_exit(kLinuxProtectedSignalMaskFailureExitCode);
	}

	if (unFixture == LinuxProtectedUnsafeInstructionFixture::MOVE_STACK_SEGMENT) {
		CallProtectedMoveStackSegment(const_cast<unsigned char*>(pCode));
	} else {
		long const nSystemCall =
			unFixture == LinuxProtectedUnsafeInstructionFixture::FORK_SYSTEM_CALL
				? SYS_fork
				: SYS_rt_sigprocmask;
		CallProtectedUnsafeSystemCall(
			const_cast<unsigned char*>(pCode), nSystemCall);
	}

	::_exit(kLinuxProtectedSignalMaskFailureExitCode);
}

TEST_SUITE("Detours::Codec") {
	TEST_CASE("Encode and Decode reject unterminated maximum-length input") {
		constexpr unsigned short kUTF8CodePage = 65001;
		constexpr std::size_t kMaximumTextLength = 0x1000;
		std::array<char, kMaximumTextLength> arrNarrowText {};
		std::array<wchar_t, kMaximumTextLength> arrWideText {};
		arrNarrowText.fill('A');
		arrWideText.fill(L'A');

		CHECK(Detours::Codec::Encode(kUTF8CodePage, arrNarrowText.data(), arrNarrowText.size()) == -1);
		CHECK(Detours::Codec::Decode(kUTF8CodePage, arrWideText.data(), arrWideText.size()) == -1);
	}

	TEST_CASE("Encode and Decode array frontends derive capacities") {
		constexpr unsigned short kUTF8CodePage = 65001;
		wchar_t szWideBuffer[3] {};
		char szNarrowBuffer[3] {};
		CHECK(Detours::Codec::Encode(kUTF8CodePage, "AB", szWideBuffer) == 2);
		CHECK(std::wcscmp(szWideBuffer, L"AB") == 0);
		CHECK(Detours::Codec::Decode(kUTF8CodePage, L"AB", szNarrowBuffer) == 2);
		CHECK(std::strcmp(szNarrowBuffer, "AB") == 0);
	}

	TEST_CASE("Encode and Decode reject bounded guard-page input") {
		constexpr unsigned short kUTF8CodePage = 65001;
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize >= sizeof(wchar_t));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));
		void* const pMapping = ::mmap(
			nullptr,
			unPageSize * 2,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1,
			0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MemoryCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize * 2);
		});
		void* const pGuardPage = static_cast<unsigned char*>(pMapping) + unPageSize;
		REQUIRE(::mprotect(pGuardPage, unPageSize, PROT_NONE) == 0);

		char* const szNarrowText = static_cast<char*>(pGuardPage) - 1;
		*szNarrowText = 'A';
		CHECK(Detours::Codec::Encode(kUTF8CodePage, szNarrowText, 1) == -1);

		wchar_t* const szWideText = reinterpret_cast<wchar_t*>(
			static_cast<unsigned char*>(pGuardPage) - sizeof(wchar_t));
		*szWideText = L'A';
		CHECK(Detours::Codec::Decode(kUTF8CodePage, szWideText, 1) == -1);
	}
} // TEST_SUITE("Detours::Codec")

TEST_SUITE("Detours::Hexadecimal") {
	TEST_CASE("Encode accepts exact capacity and terminates output") {
		unsigned char const arrData[] = { 'A', 0x00, 'B' };
		char szNarrowHex[7] {};
		wchar_t szWideHex[7] {};
		char szHex[7] {};

		CHECK(Detours::Hexadecimal::EncodeA(arrData, sizeof(arrData), szNarrowHex, 0x00) == true);
		CHECK(std::strcmp(szNarrowHex, "410042") == 0);
		CHECK(szNarrowHex[6] == '\0');
		CHECK(Detours::Hexadecimal::EncodeW(arrData, sizeof(arrData), szWideHex, 0x00) == true);
		CHECK(std::wcscmp(szWideHex, L"410042") == 0);
		CHECK(szWideHex[6] == L'\0');
		CHECK(Detours::Hexadecimal::Encode(arrData, sizeof(arrData), szHex, 0x00) == true);
		CHECK(std::strcmp(szHex, "410042") == 0);
		CHECK(szHex[6] == '\0');
	}

	TEST_CASE("Encode rejects undersized and overflowing output without writes") {
		unsigned char const arrData[] = { 'A', 'B' };
		char szNarrowHex[] = { 'x', 'y', 'z', '!' };
		wchar_t szWideHex[] = { L'x', L'y', L'z', L'!' };
		char szHex[] = { '1', '2', '3', '4' };
		char const szOriginalNarrowHex[] = { 'x', 'y', 'z', '!' };
		wchar_t const szOriginalWideHex[] = { L'x', L'y', L'z', L'!' };
		char const szOriginalHex[] = { '1', '2', '3', '4' };

		CHECK(Detours::Hexadecimal::EncodeA(arrData, sizeof(arrData), szNarrowHex, 0x00) == false);
		CHECK(std::memcmp(szNarrowHex, szOriginalNarrowHex, sizeof(szNarrowHex)) == 0);
		CHECK(Detours::Hexadecimal::EncodeW(arrData, sizeof(arrData), szWideHex, 0x00) == false);
		CHECK(std::memcmp(szWideHex, szOriginalWideHex, sizeof(szWideHex)) == 0);
		CHECK(Detours::Hexadecimal::Encode(arrData, sizeof(arrData), szHex, 0x00) == false);
		CHECK(std::memcmp(szHex, szOriginalHex, sizeof(szHex)) == 0);

		char szOverflowNarrowHex[] = { 'N' };
		wchar_t szOverflowWideHex[] = { L'W' };
		CHECK(Detours::Hexadecimal::EncodeA(
			arrData,
			std::numeric_limits<std::size_t>::max(),
			szOverflowNarrowHex,
			sizeof(szOverflowNarrowHex),
			0x00) == false);
		CHECK(szOverflowNarrowHex[0] == 'N');
		CHECK(Detours::Hexadecimal::EncodeW(
			arrData,
			std::numeric_limits<std::size_t>::max(),
			szOverflowWideHex,
			sizeof(szOverflowWideHex) / sizeof(szOverflowWideHex[0]),
			0x00) == false);
		CHECK(szOverflowWideHex[0] == L'W');
	}

	TEST_CASE("Decode accepts exact capacity and preserves ignored bytes") {
		char szData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::DecodeA("412A42", szData, 0x2A) == true);
		CHECK(std::memcmp(szData, "AyB", sizeof(szData)) == 0);

		unsigned char arrNarrowData[2] {};
		unsigned char arrWideData[2] {};
		unsigned char arrData[2] {};
		CHECK(Detours::Hexadecimal::DecodeA("4142", arrNarrowData, 0x00) == true);
		CHECK(std::memcmp(arrNarrowData, "AB", sizeof(arrNarrowData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142", arrWideData, 0x00) == true);
		CHECK(std::memcmp(arrWideData, "AB", sizeof(arrWideData)) == 0);
		CHECK(Detours::Hexadecimal::Decode("4142", arrData, 0x00) == true);
		CHECK(std::memcmp(arrData, "AB", sizeof(arrData)) == 0);
	}

	TEST_CASE("Decode rejects invalid or undersized output without writes") {
		char szData[] = { 'x', 'y', 'z' };
		char const szOriginalData[] = { 'x', 'y', 'z' };
		CHECK(Detours::Hexadecimal::Decode("A", szData, 0x2A) == false);
		CHECK(std::memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::Decode("GG", szData, 0x2A) == false);
		CHECK(std::memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeA("4142GG", szData, 0x2A) == false);
		CHECK(std::memcmp(szData, szOriginalData, sizeof(szData)) == 0);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142GG", szData, 0x2A) == false);
		CHECK(std::memcmp(szData, szOriginalData, sizeof(szData)) == 0);

		unsigned char arrNarrowCanary[] = { 0xA5 };
		unsigned char arrWideCanary[] = { 0x5A };
		CHECK(Detours::Hexadecimal::DecodeA("4142", arrNarrowCanary, 0x00) == false);
		CHECK(arrNarrowCanary[0] == 0xA5);
		CHECK(Detours::Hexadecimal::DecodeW(L"4142", arrWideCanary, 0x00) == false);
		CHECK(arrWideCanary[0] == 0x5A);
	}

	TEST_CASE("Decode rejects bounded guard-page input without writes") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize >= sizeof(wchar_t));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));
		void* const pMapping = ::mmap(
			nullptr,
			unPageSize * 2,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1,
			0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MemoryCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize * 2);
		});
		void* const pGuardPage = static_cast<unsigned char*>(pMapping) + unPageSize;
		REQUIRE(::mprotect(pGuardPage, unPageSize, PROT_NONE) == 0);

		unsigned char arrData[] = { 0xA5, 0x5A };
		unsigned char const arrOriginalData[] = { 0xA5, 0x5A };
		char* const szNarrowHex = static_cast<char*>(pGuardPage) - 1;
		*szNarrowHex = 'A';
		CHECK(Detours::Hexadecimal::DecodeA(szNarrowHex, 1, arrData, sizeof(arrData), 0x00) == false);
		CHECK(std::memcmp(arrData, arrOriginalData, sizeof(arrData)) == 0);

		wchar_t* const szWideHex = reinterpret_cast<wchar_t*>(
			static_cast<unsigned char*>(pGuardPage) - sizeof(wchar_t));
		*szWideHex = L'A';
		CHECK(Detours::Hexadecimal::DecodeW(szWideHex, 1, arrData, sizeof(arrData), 0x00) == false);
		CHECK(std::memcmp(arrData, arrOriginalData, sizeof(arrData)) == 0);
	}
} // TEST_SUITE("Detours::Hexadecimal")

TEST_SUITE("Detours::Scan") {
	TEST_CASE("Linux scans defer pending pthread cancellation across noexcept I/O") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pMapping = ::mmap(
			nullptr,
			unPageSize,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1,
			0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MemoryCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});
		std::array<unsigned char, 4> arrData { 1, 2, 3, 4 };
		CHECK(RunLinuxPendingCancellationScenario(QueryMemoryWithPendingCancellation, pMapping) == true);
		CHECK(RunLinuxPendingCancellationScenario(ScanMemoryWithPendingCancellation, &arrData) == true);

		void* const hModule = OpenLinuxScanTestModule(nullptr);
		REQUIRE(hModule != nullptr);
		auto ModuleCleanup = MakeScopeExit([hModule]() {
			::dlclose(hModule);
		});
		CHECK(RunLinuxPendingCancellationScenario(FindELFSectionWithPendingCancellation, hModule) == true);
	}

	TEST_CASE("FindSection resolves an opaque dlopen handle") {
		void* const hModule = OpenLinuxScanTestModule(nullptr);
		REQUIRE(hModule != nullptr);
		auto ModuleCleanup = MakeScopeExit([hModule]() {
			::dlclose(hModule);
		});

		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		REQUIRE(Detours::Scan::FindSection(hModule, { '.', 't', 'e', 'x', 't', 0, 0, 0 }, &pSection, &unSectionSize) == true);
		CHECK(pSection != nullptr);
		CHECK(unSectionSize != 0);
	}

	TEST_CASE("FindSection rejects nonzero bytes after a section-name terminator") {
		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		CHECK(Detours::Scan::FindSection(
			static_cast<void*>(nullptr),
			{ '.', 't', 'e', 'x', 't', 0, 'X', 0 },
			&pSection,
			&unSectionSize) == false);
	}

	TEST_CASE("Module scans resolve a relative dlopen path after the working directory changes") {
		constexpr std::array<unsigned char const, Detours::Scan::kSectionNameSize> kTextSectionName = {
			'.', 't', 'e', 'x', 't', 0, 0, 0
		};
		void* const pSymbol = ::dlsym(RTLD_DEFAULT, "cos");
		Dl_info SymbolInformation {};
		REQUIRE(pSymbol != nullptr);
		REQUIRE(::dladdr(pSymbol, &SymbolInformation) != 0);
		REQUIRE(SymbolInformation.dli_fname != nullptr);
		REQUIRE(SymbolInformation.dli_fname[0] != '\0');
		char szSourceModulePath[PATH_MAX] {};
		REQUIRE(::realpath(SymbolInformation.dli_fname, szSourceModulePath) != nullptr);

		char szSourceDirectory[] = "/tmp/detours-relative-module-XXXXXX";
		REQUIRE(::mkdtemp(szSourceDirectory) != nullptr);
		std::string const strSourceDirectory = szSourceDirectory;
		std::string const strModulePath = strSourceDirectory + "/fixture.so";
		auto SourceDirectoryCleanup = MakeScopeExit([&strModulePath, &strSourceDirectory]() {
			::unlink(strModulePath.c_str());
			::rmdir(strSourceDirectory.c_str());
		});

		char szEmptyDirectory[] = "/tmp/detours-relative-cwd-XXXXXX";
		REQUIRE(::mkdtemp(szEmptyDirectory) != nullptr);
		std::string const strEmptyDirectory = szEmptyDirectory;
		auto EmptyDirectoryCleanup = MakeScopeExit([&strEmptyDirectory]() {
			::rmdir(strEmptyDirectory.c_str());
		});

		{
			std::ifstream SourceStream(szSourceModulePath, std::ios::binary);
			std::ofstream TargetStream(strModulePath, std::ios::binary | std::ios::trunc);
			REQUIRE(SourceStream.is_open());
			REQUIRE(TargetStream.is_open());

			TargetStream << SourceStream.rdbuf();
			REQUIRE(!SourceStream.bad());
			TargetStream.close();
			REQUIRE(TargetStream.good());
		}

		int const nCurrentDirectory = ::open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		REQUIRE(nCurrentDirectory >= 0);
		auto CurrentDirectoryCleanup = MakeScopeExit([nCurrentDirectory]() {
			if (::fchdir(nCurrentDirectory) != 0) {
				::close(nCurrentDirectory);
				return;
			}
			::close(nCurrentDirectory);
		});

		REQUIRE(::chdir(strSourceDirectory.c_str()) == 0);
		void* const hModule = ::dlopen("./fixture.so", RTLD_NOW | RTLD_LOCAL);
		auto ModuleCleanup = MakeScopeExit([hModule]() {
			if (hModule) {
				::dlclose(hModule);
			}
		});
		REQUIRE(hModule != nullptr);
		REQUIRE(::chdir(strEmptyDirectory.c_str()) == 0);

		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		REQUIRE(Detours::Scan::FindSection(
			hModule,
			kTextSectionName,
			&pSection,
			&unSectionSize) == true);
		REQUIRE(pSection != nullptr);
		REQUIRE(unSectionSize != 0);

		unsigned char const* const pSectionBytes = static_cast<unsigned char const*>(pSection);
		CHECK(Detours::Scan::FindData(
			hModule,
			kTextSectionName,
			pSectionBytes,
			1) == pSection);
	}

	TEST_CASE("FindSignature rejects an overflowing result offset") {
		std::array<unsigned char, 1> const arrData = { 'A' };
		constexpr std::size_t kOverflowingOffset = std::numeric_limits<std::size_t>::max();
		CHECK(Detours::Scan::FindSignatureNative(arrData.data(), arrData.size(), "A", '*', kOverflowingOffset) == nullptr);
		CHECK(Detours::Scan::FindSignature(arrData.data(), arrData.size(), "A", '*', kOverflowingOffset) == nullptr);
	}

	TEST_CASE("FindSignature rejects an unterminated maximum-length signature before a guard page") {
		constexpr std::size_t kMaximumSignatureLength = 0x1000;
		long const nPageSize = ::sysconf(_SC_PAGESIZE);
		REQUIRE(nPageSize > 0);
		std::size_t const unPageSize = static_cast<std::size_t>(nPageSize);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() - (kMaximumSignatureLength - 1)));
		std::size_t const unReadableSize = ((kMaximumSignatureLength + unPageSize - 1) / unPageSize) * unPageSize;
		REQUIRE(unReadableSize <= (std::numeric_limits<std::size_t>::max() - unPageSize));

		void* const pAllocation = ::mmap(nullptr, unReadableSize + unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pAllocation != MAP_FAILED);
		auto MemoryCleanup = MakeScopeExit([pAllocation, unReadableSize, unPageSize]() {
			::munmap(pAllocation, unReadableSize + unPageSize);
		});

		char* const szSignature = static_cast<char*>(pAllocation) + unReadableSize - kMaximumSignatureLength;
		void* const pGuardPage = static_cast<unsigned char*>(pAllocation) + unReadableSize;
		std::memset(szSignature, 'A', kMaximumSignatureLength);
		REQUIRE(::mprotect(pGuardPage, unPageSize, PROT_NONE) == 0);

		std::array<unsigned char, kMaximumSignatureLength> arrData {};
		arrData.fill('A');
		CHECK(Detours::Scan::FindSignatureNative(arrData.data(), arrData.size(), szSignature) == nullptr);
		CHECK(Detours::Scan::FindSignature(arrData.data(), arrData.size(), szSignature) == nullptr);
	}

	TEST_CASE("Module scans skip PROT_NONE image pages") {
		constexpr std::array<unsigned char const, Detours::Scan::kSectionNameSize> kTextSectionName = { '.', 't', 'e', 'x', 't', 0, 0, 0 };
		constexpr std::array<unsigned char, 16> kUnlikelyData = {
			0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88,
			0x79, 0x6A, 0x5B, 0x4C, 0x3D, 0x2E, 0x1F, 0xF0
		};
		void* pModuleBase = nullptr;
		void* const hModule = OpenLinuxScanTestModule(&pModuleBase);
		REQUIRE(hModule != nullptr);
		auto ModuleCleanup = MakeScopeExit([hModule]() {
			::dlclose(hModule);
		});
		if (!CanProtectLinuxScanTestModule(pModuleBase)) {
			MESSAGE("The loaded math implementation shares runtime text and cannot be protected safely.");
			return;
		}

		void* pSection = nullptr;
		std::size_t unSectionSize = 0;
		REQUIRE(Detours::Scan::FindSection(hModule, kTextSectionName, &pSection, &unSectionSize) == true);

		long const nPageSize = ::sysconf(_SC_PAGESIZE);
		REQUIRE(nPageSize > 0);
		std::size_t const unPageSize = static_cast<std::size_t>(nPageSize);
		std::uintptr_t const unSectionStart = reinterpret_cast<std::uintptr_t>(pSection);
		std::uintptr_t const unSectionEnd = unSectionStart + static_cast<std::uintptr_t>(unSectionSize);
		REQUIRE(unSectionEnd > unSectionStart);
		REQUIRE(unSectionStart <= (std::numeric_limits<std::uintptr_t>::max() - (unPageSize - 1)));

		std::uintptr_t unProtectedPage = (unSectionStart + (unPageSize - 1)) & ~static_cast<std::uintptr_t>(unPageSize - 1);
		if (unProtectedPage == unSectionStart) {
			REQUIRE(unProtectedPage <= (std::numeric_limits<std::uintptr_t>::max() - unPageSize));
			unProtectedPage += unPageSize;
		}

		if ((unProtectedPage >= unSectionEnd) || (unPageSize > (unSectionEnd - unProtectedPage))) {
			MESSAGE("The scan fixture's .text is too small for an isolated PROT_NONE-page test.");
			return;
		}

		REQUIRE(::mprotect(reinterpret_cast<void*>(unProtectedPage), unPageSize, PROT_NONE) == 0);
		auto ProtectionCleanup = MakeScopeExit([unProtectedPage, unPageSize]() {
			::mprotect(reinterpret_cast<void*>(unProtectedPage), unPageSize, PROT_READ | PROT_EXEC);
		});

		CHECK(Detours::Scan::FindSignature(hModule, kTextSectionName, "\xF1\xE2\xD3\xC4\xB5\xA6\x97\x88", '*') == nullptr);
		CHECK(Detours::Scan::FindData(hModule, kTextSectionName, kUnlikelyData.data(), kUnlikelyData.size()) == nullptr);

		REQUIRE(::mprotect(reinterpret_cast<void*>(unProtectedPage), unPageSize, PROT_READ | PROT_EXEC) == 0);
		ProtectionCleanup.Release();
	}
} // TEST_SUITE("Detours::Scan")

TEST_SUITE("Detours::Sync") {
	TEST_CASE("Manual-reset named EventServer and EventClient") {
		char szEventName[Detours::kNamedObjectNameCapacity] {};
		Detours::Sync::EventServer EventServer(false, true, false);
		REQUIRE(EventServer.GetEvent() != nullptr);
		REQUIRE(EventServer.GetEventName(szEventName) == true);

		Detours::Sync::EventClient EventClient(szEventName);
		REQUIRE(EventClient.GetEvent() != nullptr);
		CHECK(EventServer.Wait(0) == false);
		CHECK(EventClient.Signal() == true);
		CHECK(EventServer.Wait(0) == true);
		CHECK(EventClient.Wait(0) == true);
		CHECK(EventServer.Reset() == true);
		CHECK(EventClient.Wait(0) == false);
		CHECK(EventServer.Signal() == true);
		CHECK(EventClient.Wait(0) == true);
	}

	TEST_CASE("Auto-reset named EventServer and EventClient") {
		char szEventName[Detours::kNamedObjectNameCapacity] {};
		Detours::Sync::EventServer EventServer(false, false, false);
		REQUIRE(EventServer.GetEvent() != nullptr);
		REQUIRE(EventServer.GetEventName(szEventName) == true);

		Detours::Sync::EventClient EventClient(szEventName);
		REQUIRE(EventClient.GetEvent() != nullptr);
		CHECK(EventClient.Signal() == true);
		CHECK(EventServer.Wait(0) == true);
		CHECK(EventClient.Wait(0) == false);
		CHECK(EventServer.Signal() == true);
		CHECK(EventClient.Wait(0) == true);
		CHECK(EventServer.Wait(0) == false);
	}






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

	TEST_CASE("Forked child destruction preserves parent named objects") {
		pid_t nForkResult = -1;
		int const nResult = [&nForkResult]() {
			char szEventName[Detours::kNamedObjectNameCapacity] {};
			char szMutexName[Detours::kNamedObjectNameCapacity] {};
			char szSemaphoreName[Detours::kNamedObjectNameCapacity] {};
			char szPipeName[Detours::kNamedObjectNameCapacity] {};
			char szSharedName[Detours::kNamedObjectNameCapacity] {};
			Detours::Sync::EventServer EventServer;
			Detours::Sync::MutexServer MutexServer;
			Detours::Sync::SemaphoreServer SemaphoreServer;
			Detours::Pipe::PipeServer PipeServer(1);
			Detours::Memory::SharedServer SharedServer(1);
			if (!EventServer.GetEventName(szEventName) ||
				!MutexServer.GetMutexName(szMutexName) ||
				!SemaphoreServer.GetSemaphoreName(szSemaphoreName) ||
				!PipeServer.GetPipeName(szPipeName) ||
				!SharedServer.GetSharedName(szSharedName) ||
				!PipeServer.Open()) {
				return 1;
			}

			nForkResult = ::fork();
			if (nForkResult < 0) {
				return 2;
			}

			if (nForkResult == 0) {
				return 0;
			}

			int nStatus = 0;
			if (!WaitForChildProcess(nForkResult, &nStatus, kLinuxChildWaitMilliseconds) ||
				!WIFEXITED(nStatus) || (WEXITSTATUS(nStatus) != 0)) {
				return 3;
			}

			Detours::Sync::EventClient EventClient(szEventName);
			Detours::Sync::MutexClient MutexClient(szMutexName);
			Detours::Sync::SemaphoreClient SemaphoreClient(szSemaphoreName);
			Detours::Memory::SharedClient SharedClient(szSharedName);
			return (EventClient.GetEvent() && MutexClient.GetMutex() && SemaphoreClient.GetSemaphore() &&
					SharedClient.GetAddress() && (::access(szPipeName, F_OK) == 0))
					   ? 0
					   : 4;
		}();

		if (nForkResult == 0) {
			::_exit(nResult);
		}

		CHECK(nResult == 0);
	}

	TEST_CASE("Mutex initial ownership is recursive and thread-owned") {
		Detours::Sync::Mutex Mutex(true);
		REQUIRE(Mutex.GetMutex() != nullptr);
		std::atomic<bool> bForeignLockResult = true;
		std::thread ForeignThread([&Mutex, &bForeignLockResult]() {
			bool const bLocked = Mutex.Lock(0);
			bForeignLockResult.store(bLocked, std::memory_order_release);
			if (bLocked) {
				Mutex.UnLock();
			}
		});
		ForeignThread.join();

		CHECK(bForeignLockResult.load(std::memory_order_acquire) == false);
		CHECK(Mutex.Lock(0) == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == true);
		CHECK(Mutex.UnLock() == false);
	}

	TEST_CASE("Named mutex initial ownership is recursive and thread-owned") {
		Detours::Sync::MutexServer MutexServer(false, true);
		REQUIRE(MutexServer.GetMutex() != nullptr);
		char szMutexName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(MutexServer.GetMutexName(szMutexName) == true);
		std::atomic<bool> bClientOpened = false;
		std::atomic<bool> bForeignLockResult = true;
		std::thread ForeignThread([&szMutexName, &bClientOpened, &bForeignLockResult]() {
			Detours::Sync::MutexClient MutexClient(szMutexName);
			bClientOpened.store(MutexClient.GetMutex() != nullptr, std::memory_order_release);
			bool const bLocked = MutexClient.Lock(0);
			bForeignLockResult.store(bLocked, std::memory_order_release);
			if (bLocked) {
				MutexClient.UnLock();
			}
		});
		ForeignThread.join();

		CHECK(bClientOpened.load(std::memory_order_acquire) == true);
		CHECK(bForeignLockResult.load(std::memory_order_acquire) == false);
		CHECK(MutexServer.Lock(0) == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == true);
		CHECK(MutexServer.UnLock() == false);
	}

	TEST_CASE("Mutex lock acquires abandoned ownership") {
		Detours::Sync::Mutex Mutex;
		REQUIRE(Mutex.GetMutex() != nullptr);
		std::atomic<bool> bOwnerLocked = false;
		std::thread OwnerThread([&Mutex, &bOwnerLocked]() {
			bOwnerLocked.store(Mutex.Lock(), std::memory_order_release);
		});
		OwnerThread.join();

		REQUIRE(bOwnerLocked.load(std::memory_order_acquire) == true);
		CHECK(Mutex.Lock(0) == true);
		CHECK(Mutex.UnLock() == true);
	}

	TEST_CASE("Named mutex lock acquires abandoned ownership") {
		Detours::Sync::MutexServer MutexServer;
		REQUIRE(MutexServer.GetMutex() != nullptr);
		char szMutexName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(MutexServer.GetMutexName(szMutexName) == true);
		std::atomic<bool> bOwnerOpened = false;
		std::atomic<bool> bOwnerLocked = false;
		std::thread OwnerThread([&szMutexName, &bOwnerOpened, &bOwnerLocked]() {
			Detours::Sync::MutexClient MutexClient(szMutexName);
			bOwnerOpened.store(MutexClient.GetMutex() != nullptr, std::memory_order_release);
			bOwnerLocked.store(MutexClient.Lock(), std::memory_order_release);
		});
		OwnerThread.join();

		REQUIRE(bOwnerOpened.load(std::memory_order_acquire) == true);
		REQUIRE(bOwnerLocked.load(std::memory_order_acquire) == true);
		CHECK(MutexServer.Lock(0) == true);
		CHECK(MutexServer.UnLock() == true);
	}

	TEST_CASE("Named mutex ownership is shared between handles") {
		char szMutexName[Detours::kNamedObjectNameCapacity] {};
		{
			Detours::Sync::MutexServer MutexServer;
			REQUIRE(MutexServer.GetMutex() != nullptr);
			REQUIRE(MutexServer.GetMutexName(szMutexName) == true);

			Detours::Sync::MutexClient MutexClient(szMutexName);
			REQUIRE(MutexClient.GetMutex() != nullptr);
			REQUIRE(MutexServer.Lock() == true);
			CHECK(MutexClient.UnLock() == true);

			std::atomic<bool> bForeignLockResult = false;
			std::thread ForeignThread([&MutexServer, &bForeignLockResult]() {
				bool const bLocked = MutexServer.Lock(kLinuxMemoryHookWaitMilliseconds);
				bForeignLockResult.store(bLocked, std::memory_order_release);
				if (bLocked) {
					MutexServer.UnLock();
				}
			});
			ForeignThread.join();
			REQUIRE(bForeignLockResult.load(std::memory_order_acquire) == true);

			pid_t const nChildPID = ::fork();
			REQUIRE(nChildPID >= 0);
			if (nChildPID == 0) {
				::_exit(MutexClient.Lock(kLinuxMemoryHookWaitMilliseconds) ? EXIT_SUCCESS : EXIT_FAILURE);
			}

			int nStatus = 0;
			REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
			REQUIRE(WIFEXITED(nStatus));
			REQUIRE(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
			REQUIRE(MutexServer.Lock(kLinuxMemoryHookWaitMilliseconds) == true);
			CHECK(MutexClient.UnLock() == true);
		}

		Detours::Sync::MutexClient RemovedClient(szMutexName);
		CHECK(RemovedClient.GetMutex() == nullptr);
	}

	TEST_CASE("Mutex serializes concurrent access on one handle") {
		MutexStressResult const Result = RunMutexStress();
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kMutexStressThreadCount * kMutexStressIterations));
	}

	TEST_CASE("Unnamed mutex starts a fresh process generation after fork") {
		Detours::Sync::Mutex Mutex;
		REQUIRE(Mutex.GetMutex() != nullptr);
		std::atomic<bool> bOwnerLocked = false;
		std::atomic<bool> bReleaseOwner = false;
		std::thread OwnerThread([&Mutex, &bOwnerLocked, &bReleaseOwner]() {
			if (!Mutex.Lock()) {
				return;
			}

			bOwnerLocked.store(true, std::memory_order_release);
			while (!bReleaseOwner.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			Mutex.UnLock();
		});
		auto Cleanup = MakeScopeExit([&OwnerThread, &bReleaseOwner]() {
			bReleaseOwner.store(true, std::memory_order_release);
			if (OwnerThread.joinable()) {
				OwnerThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&bOwnerLocked]() {
			return bOwnerLocked.load(std::memory_order_acquire);
		},
									 1000));
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			bool const bLocked = Mutex.Lock(1000);
			bool const bUnlocked = bLocked && Mutex.UnLock();
			::_exit((bLocked && bUnlocked) ? 0 : 1);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		bReleaseOwner.store(true, std::memory_order_release);
		OwnerThread.join();
		Cleanup.Release();
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
	}

	TEST_CASE("Mutex move assignment releases recursive ownership on Linux") {
		Detours::Sync::Mutex OwnedMutex(true);
		REQUIRE(OwnedMutex.GetMutex() != nullptr);
		REQUIRE(OwnedMutex.Lock() == true);
		void* pReplacementMutex = nullptr;
		{
			Detours::Sync::Mutex ReplacementMutex;
			pReplacementMutex = ReplacementMutex.GetMutex();
			REQUIRE(pReplacementMutex != nullptr);
			OwnedMutex = std::move(ReplacementMutex);
		}

		CHECK(OwnedMutex.GetMutex() == pReplacementMutex);
		CHECK(OwnedMutex.Lock(0) == true);
		CHECK(OwnedMutex.UnLock() == true);

		char szOwnedName[Detours::kNamedObjectNameCapacity] {};
		Detours::Sync::MutexServer OwnedServer(false, true);
		REQUIRE(OwnedServer.GetMutex() != nullptr);
		REQUIRE(OwnedServer.GetMutexName(szOwnedName) == true);
		REQUIRE(OwnedServer.Lock() == true);
		void* pReplacementServer = nullptr;
		{
			Detours::Sync::MutexServer ReplacementServer;
			pReplacementServer = ReplacementServer.GetMutex();
			REQUIRE(pReplacementServer != nullptr);
			OwnedServer = std::move(ReplacementServer);
		}

		CHECK(OwnedServer.GetMutex() == pReplacementServer);
		CHECK(OwnedServer.Lock(0) == true);
		CHECK(OwnedServer.UnLock() == true);
		Detours::Sync::MutexClient RemovedClient(szOwnedName);
		CHECK(RemovedClient.GetMutex() == nullptr);
	}

	TEST_CASE("Semaphore enforces initial and maximum counts") {
		Detours::Sync::Semaphore NegativeInitial(-1, 1);
		Detours::Sync::Semaphore ExcessiveInitial(2, 1);
		Detours::Sync::Semaphore InvalidMaximum(0, 0);
		CHECK(NegativeInitial.GetSemaphore() == nullptr);
		CHECK(ExcessiveInitial.GetSemaphore() == nullptr);
		CHECK(InvalidMaximum.GetSemaphore() == nullptr);

		Detours::Sync::Semaphore Semaphore(1, 2);
		REQUIRE(Semaphore.GetSemaphore() != nullptr);
		CHECK(Semaphore.Leave(0) == false);
		CHECK(Semaphore.Leave(-1) == false);
		CHECK(Semaphore.Leave(2) == false);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == false);
		CHECK(Semaphore.Leave(2) == true);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == true);
		CHECK(Semaphore.Enter(0) == false);

		Detours::Sync::SemaphoreServer InvalidServer(false, 2, 1);
		CHECK(InvalidServer.GetSemaphore() == nullptr);
		Detours::Sync::SemaphoreServer SemaphoreServer(false, 1, 2);
		REQUIRE(SemaphoreServer.GetSemaphore() != nullptr);
		char szSemaphoreName[Detours::kNamedObjectNameCapacity] {};
		REQUIRE(SemaphoreServer.GetSemaphoreName(szSemaphoreName) == true);
		Detours::Sync::SemaphoreClient SemaphoreClient(szSemaphoreName);
		REQUIRE(SemaphoreClient.GetSemaphore() != nullptr);
		CHECK(SemaphoreClient.Leave(2) == false);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == false);
		CHECK(SemaphoreClient.Leave(2) == true);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == true);
		CHECK(SemaphoreServer.Enter(0) == false);
	}


	TEST_CASE("Named-object destruction defers pending pthread cancellation") {
		CHECK(RunLinuxNoCancelDestructorScenario() == true);
	}



	TEST_CASE("CriticalSection raw handle shares lock ownership") {
		Detours::Sync::CriticalSection CriticalSection;
		pthread_mutex_t* const pCriticalSection = CriticalSection.GetCriticalSection();
		REQUIRE(pCriticalSection != nullptr);
		REQUIRE(::pthread_mutex_lock(pCriticalSection) == 0);

		CriticalSection.Leave();
		std::atomic<bool> bForeignLockResult = false;
		std::thread ForeignThread([pCriticalSection, &bForeignLockResult]() {
			int const nLockResult = ::pthread_mutex_trylock(pCriticalSection);
			bForeignLockResult.store(nLockResult == 0, std::memory_order_release);
			if (nLockResult == 0) {
				::pthread_mutex_unlock(pCriticalSection);
			}
		});
		ForeignThread.join();
		if (!bForeignLockResult.load(std::memory_order_acquire)) {
			::pthread_mutex_unlock(pCriticalSection);
		}

		CHECK(bForeignLockResult.load(std::memory_order_acquire) == true);

		CriticalSection.Enter();
		CHECK(::pthread_mutex_unlock(pCriticalSection) == 0);
		REQUIRE(::pthread_mutex_lock(pCriticalSection) == 0);
		CriticalSection.Leave();
	}

	TEST_CASE("CriticalSection starts a fresh process generation after fork") {
		Detours::Sync::CriticalSection CriticalSection;
		pthread_mutex_t* const pParentCriticalSection = CriticalSection.GetCriticalSection();
		REQUIRE(pParentCriticalSection != nullptr);

		std::atomic<bool> bOwnerEntered = false;
		std::atomic<bool> bReleaseOwner = false;
		std::thread OwnerThread([&CriticalSection, &bOwnerEntered, &bReleaseOwner]() {
			CriticalSection.Enter();
			bOwnerEntered.store(true, std::memory_order_release);
			while (!bReleaseOwner.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			CriticalSection.Leave();
		});
		auto Cleanup = MakeScopeExit([&OwnerThread, &bReleaseOwner]() {
			bReleaseOwner.store(true, std::memory_order_release);
			if (OwnerThread.joinable()) {
				OwnerThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&bOwnerEntered]() {
			return bOwnerEntered.load(std::memory_order_acquire);
		},
									 1000));

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			pthread_mutex_t* const pChildCriticalSection = CriticalSection.GetCriticalSection();
			if (!pChildCriticalSection || (pChildCriticalSection == pParentCriticalSection)) {
				::_exit(EXIT_FAILURE);
			}

			if (::pthread_mutex_lock(pChildCriticalSection) != 0) {
				::_exit(EXIT_FAILURE);
			}

			CriticalSection.Leave();
			CriticalSection.Enter();
			::_exit((::pthread_mutex_unlock(pChildCriticalSection) == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
		}

		bReleaseOwner.store(true, std::memory_order_release);
		OwnerThread.join();
		Cleanup.Release();

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("Named clients reject an undersized non-NUL name before a guard page") {
		long const nPageSize = ::sysconf(_SC_PAGESIZE);
		REQUIRE(nPageSize > 0);
		std::size_t const unPageSize = static_cast<std::size_t>(nPageSize);
		constexpr std::size_t kInputCapacity = 1;
		REQUIRE(unPageSize >= kInputCapacity);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		unsigned char* const pAllocation = static_cast<unsigned char*>(::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		REQUIRE(pAllocation != MAP_FAILED);
		auto MemoryCleanup = MakeScopeExit([pAllocation, unPageSize]() {
			::munmap(pAllocation, unPageSize * 2);
		});

		char* const szName = reinterpret_cast<char*>(pAllocation + unPageSize - kInputCapacity);
		std::memset(szName, 'A', kInputCapacity);
		REQUIRE(::mprotect(pAllocation, unPageSize, PROT_READ) == 0);
		REQUIRE(::mprotect(pAllocation + unPageSize, unPageSize, PROT_NONE) == 0);

		Detours::Sync::EventClient EventClient(szName, kInputCapacity);
		Detours::Sync::MutexClient MutexClient(szName, kInputCapacity);
		Detours::Sync::SemaphoreClient SemaphoreClient(szName, kInputCapacity);
		Detours::Memory::SharedClient SharedClient(szName, kInputCapacity);
		Detours::Pipe::PipeClient PipeClient(1);
		CHECK(EventClient.GetEvent() == nullptr);
		CHECK(MutexClient.GetMutex() == nullptr);
		CHECK(SemaphoreClient.GetSemaphore() == nullptr);
		CHECK(SharedClient.GetShared() == nullptr);
		CHECK(PipeClient.Open(szName, kInputCapacity) == false);
		CHECK(szName[0] == 'A');
	}

	TEST_CASE("Suspend signal chains ordinary sigqueue without restarting read") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			constexpr int kSignalValue = 0x1357;
			g_nLinuxSuspendPredecessorCalls = 0;
			g_nLinuxSuspendPredecessorValue = 0;

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxSuspendPredecessorSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			if (::sigaction(SIGUSR2, &PreviousAction, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			std::atomic<bool> bWorkerReady = false;
			std::atomic<bool> bWorkerStop = false;
			std::thread Worker([&bWorkerReady, &bWorkerStop]() {
				bWorkerReady.store(true, std::memory_order_release);
				while (!bWorkerStop.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
			});
			Detours::Sync::Suspender Suspender;
			if (!WaitForTestCondition([&bWorkerReady]() {
					return bWorkerReady.load(std::memory_order_acquire);
				},
									  1000) ||
				!Suspender.Suspend(false)) {
				bWorkerStop.store(true, std::memory_order_release);
				Worker.join();
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (!Suspender.Resume()) {
				bWorkerStop.store(true, std::memory_order_release);
				Worker.join();
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			bWorkerStop.store(true, std::memory_order_release);
			Worker.join();

			errno = EDOM;
		long const nDirectSignalResult = ::syscall(
				SYS_tgkill,
				::getpid(),
				static_cast<pid_t>(::syscall(SYS_gettid)),
				SIGUSR2);
		int const nPreservedError = errno;
			if ((nDirectSignalResult != 0) || (nPreservedError != EDOM) ||
				(g_nLinuxSuspendPredecessorCalls != 1)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			g_nLinuxSuspendPredecessorCalls = 0;
			g_nLinuxSuspendPredecessorValue = 0;

			int arrPipe[kLinuxPipeFileDescriptorCount] { -1, -1 };
			if (::pipe(arrPipe) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			std::atomic<bool> bSignalQueued = false;
			std::thread Sender([&bSignalQueued, &arrPipe]() {
				sigset_t SignalSet {};
				sigemptyset(&SignalSet);
				sigaddset(&SignalSet, SIGUSR2);
				if (::pthread_sigmask(SIG_BLOCK, &SignalSet, nullptr) == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(20));
					union sigval SignalValue {};
					SignalValue.sival_int = kSignalValue;
					bSignalQueued.store(::sigqueue(::getpid(), SIGUSR2, SignalValue) == 0, std::memory_order_release);
				}

				if (!bSignalQueued.load(std::memory_order_acquire)) {
					unsigned char const unValue = 1;
					ssize_t const nWriteResult = ::write(arrPipe[1], &unValue, sizeof(unValue));
					if (nWriteResult != static_cast<ssize_t>(sizeof(unValue))) {
						::_exit(kLinuxSignalChainingFailureExitCode);
					}
				}
			});

			unsigned char unValue = 0;
			errno = 0;
			ssize_t const nReadResult = ::read(arrPipe[0], &unValue, sizeof(unValue));
			int const nReadError = errno;
			Sender.join();
			::close(arrPipe[0]);
			::close(arrPipe[1]);
			bool const bSuccess = bSignalQueued.load(std::memory_order_acquire) &&
								  (nReadResult == -1) && (nReadError == EINTR) &&
								  (g_nLinuxSuspendPredecessorCalls == 1) &&
								  (g_nLinuxSuspendPredecessorValue == kSignalValue);
			::_exit(bSuccess ? kLinuxSignalChainingSuccessExitCode : kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}





	TEST_CASE("Suspender treats an unscanned deep stack tail as referenced") {
		LINUX_DEEP_STACK_DATA StackData {};
		pthread_attr_t ThreadAttributes {};
		REQUIRE(::pthread_attr_init(&ThreadAttributes) == 0);
		auto AttributeCleanup = MakeScopeExit([&ThreadAttributes]() {
			::pthread_attr_destroy(&ThreadAttributes);
		});
		REQUIRE(::pthread_attr_setstacksize(&ThreadAttributes, kLinuxDeepStackSize) == 0);

		pthread_t hThread {};
		REQUIRE(::pthread_create(
				&hThread,
				&ThreadAttributes,
				LinuxDeepStackCallBack,
				&StackData) == 0);
		bool bThreadCreated = true;
		Detours::Sync::Suspender Suspender;
		bool bSuspended = false;
		auto Cleanup = MakeScopeExit([&]() {
			if (bSuspended && !RetryTestCleanup([&Suspender]() {
					return Suspender.Resume();
				})) {
				std::abort();
			}

			StackData.m_bStop.store(true, std::memory_order_release);
			if (bThreadCreated) {
				::pthread_join(hThread, nullptr);
			}
		});

		REQUIRE(WaitForTestCondition([&StackData]() {
			return StackData.m_bReady.load(std::memory_order_acquire) &&
				   (StackData.m_unStackAddress.load(std::memory_order_relaxed) != 0);
		},
								 1000));
		REQUIRE(Suspender.Suspend(false) == true);
		bSuspended = true;
		CHECK(Suspender.IsRegionInCallStacks(
				  &g_unLinuxDeepStackSentinel,
				  sizeof(g_unLinuxDeepStackSentinel)) == true);
		REQUIRE(Suspender.Resume() == true);
		bSuspended = false;
		StackData.m_bStop.store(true, std::memory_order_release);
		REQUIRE(::pthread_join(hThread, nullptr) == 0);
		bThreadCreated = false;
		Cleanup.Release();
		AttributeCleanup.Release();
		CHECK(::pthread_attr_destroy(&ThreadAttributes) == 0);
	}

	TEST_CASE("Suspender replaces inherited global state while a request is active") {
		sigset_t SuspendSignalSet {};
		sigset_t OldSignalSet {};
		sigemptyset(&SuspendSignalSet);
		sigaddset(&SuspendSignalSet, SIGUSR2);
		REQUIRE(::pthread_sigmask(SIG_BLOCK, &SuspendSignalSet, &OldSignalSet) == 0);

		Detours::Sync::Suspender BlockingSuspender;
		std::atomic<bool> bRequestStarted = false;
		std::atomic<bool> bRequestReturned = false;
		std::atomic<bool> bRequestSucceeded = false;
		std::thread RequestThread([&BlockingSuspender, &bRequestStarted, &bRequestReturned, &bRequestSucceeded]() {
			bRequestStarted.store(true, std::memory_order_release);
			bool const bSuspended = BlockingSuspender.Suspend(false);
			bool bResumed = false;
			if (bSuspended) {
				bResumed = BlockingSuspender.Resume();
				if (!bResumed && !RetryTestCleanup([&BlockingSuspender]() {
						return BlockingSuspender.Resume();
					})) {
					std::abort();
				}
			}

			bRequestSucceeded.store(bSuspended && bResumed, std::memory_order_release);
			bRequestReturned.store(true, std::memory_order_release);
		});
		bool bSignalMaskRestored = false;
		auto Cleanup = MakeScopeExit([&RequestThread, &OldSignalSet, &bSignalMaskRestored]() {
			if (!bSignalMaskRestored) {
				if (::pthread_sigmask(SIG_SETMASK, &OldSignalSet, nullptr) != 0) {
					std::abort();
				}

				bSignalMaskRestored = true;
			}

			if (RequestThread.joinable()) {
				RequestThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&bRequestStarted]() {
			return bRequestStarted.load(std::memory_order_acquire);
		},
									 1000));
		REQUIRE(WaitForTestCondition([]() {
			sigset_t PendingSignals {};
			return (::sigpending(&PendingSignals) == 0) && (::sigismember(&PendingSignals, SIGUSR2) == 1);
		},
									 1000));

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			if (::pthread_sigmask(SIG_SETMASK, &OldSignalSet, nullptr) != 0) {
				::_exit(1);
			}

			std::atomic<bool> bWorkerReady = false;
			std::atomic<bool> bStopWorker = false;
			std::thread Worker([&bWorkerReady, &bStopWorker]() {
				bWorkerReady.store(true, std::memory_order_release);
				while (!bStopWorker.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
			});
			Detours::Sync::Suspender ChildSuspender;
			bool const bReady = WaitForTestCondition([&bWorkerReady]() {
				return bWorkerReady.load(std::memory_order_acquire);
			},
													 1000);
			bool const bSuspended = bReady && ChildSuspender.Suspend(false);
			bool const bResumed = bSuspended && ChildSuspender.Resume();
			bStopWorker.store(true, std::memory_order_release);
			Worker.join();
			::_exit((bReady && bSuspended && bResumed) ? 0 : 2);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
		REQUIRE(::pthread_sigmask(SIG_SETMASK, &OldSignalSet, nullptr) == 0);
		bSignalMaskRestored = true;
		RequestThread.join();
		CHECK(bRequestReturned.load(std::memory_order_acquire) == true);
		CHECK(bRequestSucceeded.load(std::memory_order_acquire) == true);
		Cleanup.Release();
	}

	TEST_CASE("Suspender Suspend(false) stops an existing worker") {
		std::atomic<bool> bReady = false;
		std::atomic<bool> bStop = false;
		std::atomic<unsigned int> unIterations = 0;
		Detours::Sync::Suspender Suspender;
		bool bSuspended = false;
		std::thread Worker([&bReady, &bStop, &unIterations]() {
			bReady.store(true, std::memory_order_release);
			while (!bStop.load(std::memory_order_acquire)) {
				unIterations.fetch_add(1, std::memory_order_relaxed);
				std::this_thread::yield();
			}
		});

		auto Cleanup = MakeScopeExit([&Suspender, &Worker, &bSuspended, &bStop]() {
			if (bSuspended && !RetryTestCleanup([&Suspender]() {
					return Suspender.Resume();
				})) {
				std::abort();
			}

			bStop.store(true, std::memory_order_release);
			if (Worker.joinable()) {
				Worker.join();
			}
		});

		REQUIRE(WaitForTestCondition([&bReady, &unIterations]() {
			return bReady.load(std::memory_order_acquire) && (unIterations.load(std::memory_order_relaxed) != 0);
		},
									 1000));
		REQUIRE(Suspender.Suspend(false) == true);
		bSuspended = true;
		std::size_t const unSuspendedIterations = unIterations.load(std::memory_order_relaxed);
		std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxSuspendObservationMilliseconds));
		CHECK(unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);

		REQUIRE(Suspender.Resume() == true);
		bSuspended = false;
		REQUIRE(WaitForTestCondition([&unIterations, unSuspendedIterations]() {
			return unIterations.load(std::memory_order_relaxed) > unSuspendedIterations;
		},
									 1000));
		bStop.store(true, std::memory_order_release);
		Worker.join();
		Cleanup.Release();
	}

	TEST_CASE("Suspender resets inherited ownership and state after fork") {
		std::atomic<bool> bWorkerReady = false;
		std::atomic<bool> bStopWorker = false;
		std::thread Worker([&bWorkerReady, &bStopWorker]() {
			bWorkerReady.store(true, std::memory_order_release);
			while (!bStopWorker.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
		});
		Detours::Sync::Suspender Suspender;
		bool bSuspended = false;
		auto Cleanup = MakeScopeExit([&Suspender, &Worker, &bSuspended, &bStopWorker]() {
			if (bSuspended && !RetryTestCleanup([&Suspender]() {
					return Suspender.Resume();
				})) {
				std::abort();
			}

			bStopWorker.store(true, std::memory_order_release);
			if (Worker.joinable()) {
				Worker.join();
			}
		});

		REQUIRE(WaitForTestCondition([&bWorkerReady]() {
			return bWorkerReady.load(std::memory_order_acquire);
		},
									 1000));
		REQUIRE(Suspender.Suspend(false) == true);
		bSuspended = true;
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			if ((Suspender.GetSuspendDepth() != 0) || Suspender.IsSuspended()) {
				::_exit(1);
			}

			std::atomic<bool> bChildWorkerReady = false;
			std::atomic<bool> bStopChildWorker = false;
			std::thread ChildWorker([&bChildWorkerReady, &bStopChildWorker]() {
				bChildWorkerReady.store(true, std::memory_order_release);
				while (!bStopChildWorker.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
			});
			bool const bReady = WaitForTestCondition([&bChildWorkerReady]() {
				return bChildWorkerReady.load(std::memory_order_acquire);
			},
													 1000);
			bool const bChildSuspended = bReady && Suspender.Suspend(false);
			bool const bChildResumed = bChildSuspended && Suspender.Resume();
			bStopChildWorker.store(true, std::memory_order_release);
			ChildWorker.join();
			::_exit((bReady && bChildSuspended && bChildResumed) ? 0 : 2);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
		REQUIRE(Suspender.Resume() == true);
		bSuspended = false;
		bStopWorker.store(true, std::memory_order_release);
		Worker.join();
		Cleanup.Release();
	}

	TEST_CASE("SuspendTransaction discards inherited active state after fork") {
		Detours::Sync::Suspender Suspender;
		Detours::Sync::SuspendTransaction Transaction(Suspender, false);
		REQUIRE(Transaction.IsActive() == true);

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			if (Transaction.IsActive() || (Suspender.GetSuspendDepth() != 0) ||
				!Suspender.Suspend(false)) {
				::_exit(1);
			}

			bool const bInheritedEndResult = Transaction.End();
			bool const bIndependentStatePreserved = Suspender.GetSuspendDepth() == 1;
			bool const bResumed = Suspender.Resume();
			::_exit((!bInheritedEndResult && bIndependentStatePreserved && bResumed) ? 0 : 2);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
		CHECK(Transaction.End() == true);
	}

	TEST_CASE("SuspendTransaction rejects a second Begin") {
		Detours::Sync::Suspender Suspender;
		Detours::Sync::SuspendTransaction Transaction(Suspender, false);
		REQUIRE(Transaction.IsActive() == true);
		CHECK(Transaction.Begin(false) == false);
		CHECK(Transaction.IsActive() == true);
		REQUIRE(Transaction.End() == true);
		CHECK(Transaction.IsActive() == false);
	}

} // TEST_SUITE("Detours::Sync")

TEST_SUITE("Detours::Pipe") {
	constexpr std::size_t kPipeBufferSize = sizeof(unsigned int);
	constexpr std::size_t kUndersizedPipeBufferSize = kPipeBufferSize - 1;


	TEST_CASE("Pipe lifecycle reports inactive state") {
		char szPipeName[Detours::kNamedObjectNameCapacity] {};
		Detours::Pipe::PipeServer InvalidServer(0);
		CHECK(InvalidServer.GetPipeName(szPipeName) == false);
		CHECK(InvalidServer.Close() == false);

		Detours::Pipe::PipeServer SourceServer(1);
		REQUIRE(SourceServer.GetPipeName(szPipeName) == true);
		Detours::Pipe::PipeServer MovedServer(std::move(SourceServer));
		CHECK(MovedServer.GetPipeName(szPipeName) == true);

		Detours::Pipe::PipeClient PipeClient(1);
		CHECK(PipeClient.Close() == false);
	}


	TEST_CASE("PipeServer discards an accepted connection inherited across fork") {
		pid_t const nScenarioProcessID = ::fork();
		REQUIRE(nScenarioProcessID >= 0);
		if (nScenarioProcessID == 0) {
			Detours::Pipe::PipeServer PipeServer(sizeof(unsigned int));
			char szPipeName[Detours::kNamedObjectNameCapacity] {};
			if (!PipeServer.GetPipeName(szPipeName) || !PipeServer.Open()) {
				::unlink(szPipeName);
				::_exit(kLinuxPipeFailureExitCode);
			}

			Detours::Pipe::PipeClient InheritedClient(sizeof(unsigned int));
			unsigned int unHandshake = kLinuxPipeRequestValue;
			unsigned int unReceivedHandshake = 0;
			unsigned int unInheritedValue = kLinuxPipeResponseValue;
			if (!InheritedClient.Open(szPipeName) ||
				!InheritedClient.Send(reinterpret_cast<unsigned char const*>(&unHandshake), sizeof(unHandshake)) ||
				!PipeServer.Receive(reinterpret_cast<unsigned char*>(&unReceivedHandshake), sizeof(unReceivedHandshake)) ||
				(unReceivedHandshake != unHandshake) ||
				!InheritedClient.Send(reinterpret_cast<unsigned char const*>(&unInheritedValue), sizeof(unInheritedValue))) {
				InheritedClient.Close();
				PipeServer.Close();
				::_exit(kLinuxPipeFailureExitCode);
			}

			pid_t const nParentProcessID = ::getpid();
			pid_t const nChildProcessID = ::fork();
			if (nChildProcessID < 0) {
				InheritedClient.Close();
				PipeServer.Close();
				::_exit(kLinuxPipeFailureExitCode);
			}

			if (nChildProcessID == 0) {
				if ((::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) ||
					(::getppid() != nParentProcessID)) {
					::_exit(kLinuxPipeFailureExitCode);
				}

				unsigned int unReceivedValue = 0;
				bool const bReceived = PipeServer.Receive(reinterpret_cast<unsigned char*>(&unReceivedValue), sizeof(unReceivedValue));
				::_exit((bReceived && (unReceivedValue == kLinuxPipeFreshGenerationValue)) ?
					EXIT_SUCCESS : kLinuxPipeFailureExitCode);
			}

			Detours::Pipe::PipeClient FreshClient(sizeof(unsigned int));
			unsigned int unFreshValue = kLinuxPipeFreshGenerationValue;
			bool const bFreshOpened = FreshClient.Open(szPipeName);
			bool const bFreshSent = bFreshOpened &&
				FreshClient.Send(reinterpret_cast<unsigned char const*>(&unFreshValue), sizeof(unFreshValue));
			int nChildStatus = 0;
			bool const bChildWaited = WaitForChildProcess(nChildProcessID, &nChildStatus, kLinuxChildWaitMilliseconds);
			bool const bFreshClosed = !bFreshOpened || FreshClient.Close();
			bool const bInheritedClosed = InheritedClient.Close();
			bool const bServerClosed = PipeServer.Close();
			bool const bSucceeded = bFreshOpened && bFreshSent && bChildWaited &&
				WIFEXITED(nChildStatus) && (WEXITSTATUS(nChildStatus) == EXIT_SUCCESS) &&
				bFreshClosed && bInheritedClosed && bServerClosed;
			::_exit(bSucceeded ? EXIT_SUCCESS : kLinuxPipeFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(
				nScenarioProcessID,
				&nStatus,
				kLinuxChildWaitMilliseconds * 2) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("Pipe endpoints reject undersized buffers before I/O") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Pipe::PipeServer PipeServer(kPipeBufferSize);
			char szPipeName[Detours::kNamedObjectNameCapacity] {};
			if (!PipeServer.GetPipeName(szPipeName)) {
				::_exit(kLinuxPipeFailureExitCode);
			}

			std::atomic<bool> bClientReady = false;
			std::atomic<bool> bClientSucceeded = false;
			std::thread ClientThread([&szPipeName, &bClientReady, &bClientSucceeded]() {
				Detours::Pipe::PipeClient PipeClient(kPipeBufferSize);
				auto const EndTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(kLinuxMemoryHookWaitMilliseconds);
				while (!PipeClient.Open(szPipeName)) {
					if (std::chrono::steady_clock::now() >= EndTime) {
						::_exit(kLinuxPipeFailureExitCode);
					}

					std::this_thread::yield();
				}

				unsigned char arrCanary[kUndersizedPipeBufferSize] = { 0xA5, 0x5A, 0xC3 };
				unsigned char const arrOriginalCanary[kUndersizedPipeBufferSize] = { 0xA5, 0x5A, 0xC3 };
				if (PipeClient.Receive(arrCanary) || PipeClient.Send(arrCanary) ||
					(std::memcmp(arrCanary, arrOriginalCanary, sizeof(arrCanary)) != 0)) {
					::_exit(kLinuxPipeFailureExitCode);
				}

				bClientReady.store(true, std::memory_order_release);
				std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxPipeClientDelayMilliseconds));
				unsigned int unRequest = 0;
				if (!PipeClient.Receive(reinterpret_cast<unsigned char*>(&unRequest), sizeof(unRequest)) || (unRequest != kLinuxPipeRequestValue)) {
					::_exit(kLinuxPipeFailureExitCode);
				}

				unsigned int unResponse = kLinuxPipeResponseValue;
				if (!PipeClient.Send(reinterpret_cast<unsigned char const*>(&unResponse), sizeof(unResponse))) {
					::_exit(kLinuxPipeFailureExitCode);
				}

				bClientSucceeded.store(true, std::memory_order_release);
			});

			if (!PipeServer.Open() || !WaitForTestCondition([&bClientReady]() {
					return bClientReady.load(std::memory_order_acquire);
				},
															kLinuxMemoryHookWaitMilliseconds)) {
				::_exit(kLinuxPipeFailureExitCode);
			}

			unsigned char arrCanary[kUndersizedPipeBufferSize] = { 0x3C, 0xC3, 0x69 };
			unsigned char const arrOriginalCanary[kUndersizedPipeBufferSize] = { 0x3C, 0xC3, 0x69 };
			if (PipeServer.Receive(arrCanary) || PipeServer.Send(arrCanary) ||
				(std::memcmp(arrCanary, arrOriginalCanary, sizeof(arrCanary)) != 0)) {
				::_exit(kLinuxPipeFailureExitCode);
			}

			unsigned int unRequest = kLinuxPipeRequestValue;
			if (!PipeServer.Send(reinterpret_cast<unsigned char const*>(&unRequest), sizeof(unRequest))) {
				::_exit(kLinuxPipeFailureExitCode);
			}

			unsigned int unResponse = 0;
			if (!PipeServer.Receive(reinterpret_cast<unsigned char*>(&unResponse), sizeof(unResponse)) || (unResponse != kLinuxPipeResponseValue)) {
				::_exit(kLinuxPipeFailureExitCode);
			}

			ClientThread.join();
			::_exit(bClientSucceeded.load(std::memory_order_acquire) ? EXIT_SUCCESS : kLinuxPipeFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}
} // TEST_SUITE("Detours::Pipe")

TEST_SUITE("Detours::Parallel") {
	TEST_CASE("Thread lifecycle") {
		std::atomic<unsigned int> unCalls = 0;
		Detours::Parallel::Thread Thread;
		CHECK(Thread.GetCallBack() == nullptr);
		CHECK(Thread.GetData() == nullptr);
		CHECK(Thread.SetCallBack(nullptr) == false);
		CHECK(Thread.SetData(nullptr) == false);
		REQUIRE(Thread.SetCallBack(LinuxThreadCallBack) == true);
		REQUIRE(Thread.SetData(&unCalls) == true);
		CHECK(Thread.GetCallBack() == LinuxThreadCallBack);
		CHECK(Thread.GetData() == &unCalls);
		REQUIRE(Thread.Start() == true);
		CHECK(Thread.Start() == false);
		CHECK(Thread.SetCallBack(LinuxThreadCallBack) == false);
		CHECK(Thread.SetData(nullptr) == false);
		CHECK(Thread.Join() == true);
		CHECK(Thread.Join() == true);
		CHECK(unCalls.load(std::memory_order_relaxed) == 1);
		CHECK(Thread.Suspend() == false);
		CHECK(Thread.Resume() == false);
		REQUIRE(Thread.SetCallBack(LinuxThreadCallBack) == true);
		REQUIRE(Thread.SetData(&unCalls) == true);
		REQUIRE(Thread.Start() == true);
		CHECK(Thread.Join() == true);
		CHECK(unCalls.load(std::memory_order_relaxed) == 2);

		{
			Detours::Parallel::Thread AutoJoinThread(LinuxThreadCallBack, &unCalls);
			REQUIRE(AutoJoinThread.Start() == true);
		}

		CHECK(unCalls.load(std::memory_order_relaxed) == 3);
	}


	TEST_CASE("Thread and Fiber preserve pthread forced unwind") {
		Detours::Parallel::Thread ExitThread(LinuxPthreadExitCallBack);
		REQUIRE(ExitThread.Start() == true);
		CHECK(ExitThread.Join() == true);

		Detours::Parallel::Thread CancelThread(LinuxSelfCancelCallBack);
		REQUIRE(CancelThread.Start() == true);
		CHECK(CancelThread.Join() == true);

		Detours::Parallel::Thread FiberThread(LinuxFiberForcedUnwindCallBack);
		REQUIRE(FiberThread.Start() == true);
		CHECK(FiberThread.Join() == true);
	}

	TEST_CASE("Thread Join preserves cancellation of the joining thread") {
		LINUX_THREAD_SUSPEND_DATA ThreadData {};
		Detours::Parallel::Thread Thread(LinuxThreadSuspendCallBack, &ThreadData);
		REQUIRE(Thread.Start() == true);
		LINUX_JOIN_CANCEL_DATA JoinData {};
		JoinData.m_pThread = &Thread;
		pthread_t hJoinThread {};
		bool bJoinThreadCreated = false;
		auto Cleanup = MakeScopeExit([&Thread, &ThreadData, &hJoinThread, &bJoinThreadCreated]() {
			ThreadData.m_bStop.store(true, std::memory_order_release);
			if (bJoinThreadCreated) {
				::pthread_cancel(hJoinThread);
				::pthread_join(hJoinThread, nullptr);
			}

			Thread.Join();
		});

		REQUIRE(WaitForTestCondition([&ThreadData]() {
			return ThreadData.m_bReady.load(std::memory_order_acquire);
		},
									 1000));
		REQUIRE(::pthread_create(&hJoinThread, nullptr, LinuxJoinCancelCallBack, &JoinData) == 0);
		bJoinThreadCreated = true;
		REQUIRE(WaitForTestCondition([&JoinData]() {
			return JoinData.m_bStarted.load(std::memory_order_acquire);
		},
									 1000));
		REQUIRE(::pthread_cancel(hJoinThread) == 0);
		void* pJoinResult = nullptr;
		REQUIRE(::pthread_join(hJoinThread, &pJoinResult) == 0);
		bJoinThreadCreated = false;
		CHECK(pJoinResult == PTHREAD_CANCELED);
		CHECK(JoinData.m_bReturned.load(std::memory_order_acquire) == false);

		ThreadData.m_bStop.store(true, std::memory_order_release);
		CHECK(Thread.Join() == true);
		Cleanup.Release();
	}


	TEST_CASE("Forked child abandons inherited Thread handles") {
		LINUX_FORK_THREAD_DATA ForkData {};
		Detours::Parallel::Thread JoinThread(LinuxForkThreadCallBack, &ForkData);
		Detours::Parallel::Thread SuspendThread(LinuxForkThreadCallBack, &ForkData);
		Detours::Parallel::Thread StartThread(LinuxForkThreadCallBack, &ForkData);
		std::unique_ptr<Detours::Parallel::Thread> pDestructorThread =
			std::make_unique<Detours::Parallel::Thread>(LinuxForkThreadCallBack, &ForkData);
		REQUIRE(JoinThread.Start() == true);
		REQUIRE(SuspendThread.Start() == true);
		REQUIRE(StartThread.Start() == true);
		REQUIRE(pDestructorThread->Start() == true);
		auto ThreadCleanup = MakeScopeExit([&ForkData, &JoinThread, &SuspendThread, &StartThread, &pDestructorThread]() {
			ForkData.m_bStop.store(true, std::memory_order_release);
			JoinThread.Join();
			SuspendThread.Join();
			StartThread.Join();
			if (pDestructorThread) {
				pDestructorThread->Join();
			}
		});

		REQUIRE(WaitForTestCondition([&ForkData]() {
			return ForkData.m_unReady.load(std::memory_order_acquire) == 4;
		},
									 kLinuxMemoryHookWaitMilliseconds));

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			ForkData.m_bStop.store(true, std::memory_order_release);
			bool const bInheritedJoinRejected = !JoinThread.Join();
			bool const bClearedJoinSucceeded = JoinThread.Join();
			bool const bInheritedSuspendRejected = !SuspendThread.Suspend();
			bool const bClearedResumeRejected = !SuspendThread.Resume();
			bool const bRestarted = StartThread.Start();
			bool const bRestartJoined = bRestarted && StartThread.Join();
			pDestructorThread.reset();
			bool const bCallBackObserved = ForkData.m_unCalls.load(std::memory_order_acquire) == 5;
			bool const bSuccess = bInheritedJoinRejected && bClearedJoinSucceeded &&
								  bInheritedSuspendRejected && bClearedResumeRejected &&
								  bRestartJoined && bCallBackObserved;
			::_exit(bSuccess ? EXIT_SUCCESS : kLinuxParallelThreadForkFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}


	TEST_CASE("Thread retries suspension after a pending SIGUSR2 timeout") {
		LINUX_STALE_SUSPEND_DATA SuspendData {};
		Detours::Parallel::Thread Thread(LinuxStaleSuspendThreadCallBack, &SuspendData);
		REQUIRE(Thread.Start() == true);
		bool bSuspended = false;
		auto Cleanup = MakeScopeExit([&Thread, &SuspendData, &bSuspended]() {
			SuspendData.m_bUnblock.store(true, std::memory_order_release);
			SuspendData.m_bStop.store(true, std::memory_order_release);
			if (bSuspended && !RetryTestCleanup([&Thread]() {
					return Thread.Resume();
				})) {
				std::abort();
			}

			Thread.Join();
		});

		REQUIRE(WaitForTestCondition([&SuspendData]() {
			return SuspendData.m_bReady.load(std::memory_order_acquire);
		},
									 1000));
		REQUIRE(SuspendData.m_bSignalBlocked.load(std::memory_order_acquire) == true);
		CHECK(Thread.Suspend() == false);

		SuspendData.m_bUnblock.store(true, std::memory_order_release);
		REQUIRE(WaitForTestCondition([&SuspendData]() {
			return SuspendData.m_bUnblocked.load(std::memory_order_acquire) && (SuspendData.m_unIterations.load(std::memory_order_relaxed) != 0);
		},
									 1000));

		REQUIRE(Thread.Suspend() == true);
		bSuspended = true;
		std::size_t const unSuspendedIterations = SuspendData.m_unIterations.load(std::memory_order_relaxed);
		std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxSuspendObservationMilliseconds));
		CHECK(SuspendData.m_unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);
		REQUIRE(Thread.Resume() == true);
		bSuspended = false;
		REQUIRE(WaitForTestCondition([&SuspendData, unSuspendedIterations]() {
			return SuspendData.m_unIterations.load(std::memory_order_relaxed) > unSuspendedIterations;
		},
									 1000));

		SuspendData.m_bStop.store(true, std::memory_order_release);
		CHECK(Thread.Join() == true);
		Cleanup.Release();
	}

	TEST_CASE("Thread preserves nested suspend depth") {
		LINUX_THREAD_SUSPEND_DATA SuspendData {};
		Detours::Parallel::Thread Thread(LinuxThreadSuspendCallBack, &SuspendData);
		std::size_t unSuspendDepth = 0;
		auto Cleanup = MakeScopeExit([&Thread, &SuspendData, &unSuspendDepth]() {
			while (unSuspendDepth) {
				if (!RetryTestCleanup([&Thread]() {
						return Thread.Resume();
					})) {
					std::abort();
				}

				--unSuspendDepth;
			}

			SuspendData.m_bStop.store(true, std::memory_order_release);
			Thread.Join();
		});

		REQUIRE(Thread.Start() == true);
		REQUIRE(WaitForTestCondition([&SuspendData]() {
			return SuspendData.m_bReady.load(std::memory_order_acquire) &&
				   (SuspendData.m_unIterations.load(std::memory_order_relaxed) != 0);
		},
									 1000));
		CHECK(Thread.Resume() == false);
		REQUIRE(Thread.Suspend() == true);
		++unSuspendDepth;
		REQUIRE(Thread.Suspend() == true);
		++unSuspendDepth;

		std::size_t const unSuspendedIterations = SuspendData.m_unIterations.load(std::memory_order_relaxed);
		std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxSuspendObservationMilliseconds));
		CHECK(SuspendData.m_unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);

		REQUIRE(Thread.Resume() == true);
		--unSuspendDepth;
		std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxSuspendObservationMilliseconds));
		CHECK(SuspendData.m_unIterations.load(std::memory_order_relaxed) == unSuspendedIterations);

		REQUIRE(Thread.Resume() == true);
		--unSuspendDepth;
		CHECK(Thread.Resume() == false);
		REQUIRE(WaitForTestCondition([&SuspendData, unSuspendedIterations]() {
			return SuspendData.m_unIterations.load(std::memory_order_relaxed) > unSuspendedIterations;
		},
									 1000));

		SuspendData.m_bStop.store(true, std::memory_order_release);
		CHECK(Thread.Join() == true);
		Cleanup.Release();
	}

	TEST_CASE("Fiber validates setters and invokes callback") {
		std::atomic<unsigned int> unCalls = 0;
		Detours::Parallel::Fiber Fiber;
		CHECK(Fiber.SetCallBack(nullptr) == false);
		CHECK(Fiber.SetData(nullptr) == false);
		REQUIRE(Fiber.SetCallBack(LinuxThreadCallBack) == true);
		REQUIRE(Fiber.SetData(&unCalls) == true);
		CHECK(Fiber.GetCallBack() == LinuxThreadCallBack);
		CHECK(Fiber.GetData() == &unCalls);
		CHECK(Fiber.Switch() == true);
		CHECK(unCalls.load(std::memory_order_relaxed) == 1);
	}
} // TEST_SUITE("Detours::Parallel")

TEST_SUITE("Detours::Exception") {



	TEST_CASE("Exception dispatch preserves pthread forced unwind and reader cleanup") {
		pid_t const nChildProcessID = ::fork();
		REQUIRE(nChildProcessID >= 0);
		if (nChildProcessID == 0) {
			Detours::Exception::ExceptionListener Listener;
			if (!Listener.AddCallBack(LinuxExceptionForcedUnwindCallBack) || !Listener.EnableHandler()) {
				::_exit(kLinuxExceptionForcedUnwindFailureExitCode);
			}

			std::atomic<bool> bSignalReturned { false };
			Detours::Parallel::Thread Thread(LinuxExceptionForcedUnwindThreadCallBack, &bSignalReturned);
			bool const bStarted = Thread.Start();
			bool const bJoined = bStarted && Thread.Join();
			bool const bRemoved = Listener.RemoveCallBack(LinuxExceptionForcedUnwindCallBack);
			bool const bDisabled = Listener.DisableHandler();
			bool const bSucceeded = bStarted && bJoined && bRemoved && bDisabled &&
									!bSignalReturned.load(std::memory_order_acquire);
			::_exit(bSucceeded ? EXIT_SUCCESS : kLinuxExceptionForcedUnwindFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildProcessID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}




	TEST_CASE("SIGTRAP dispatch") {
		g_nLinuxExceptionCalls = 0;
		g_nLinuxExceptionContextObserved = 0;
		REQUIRE(Detours::Exception::g_ExceptionListener.EnableHandler() == true);
		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(LinuxExceptionCallBack) == true);
		auto CallBackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBack);
		});

		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxExceptionCalls == 1);
		CHECK(g_nLinuxExceptionContextObserved == 1);

		bool const bRemoved = Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBack);
		CHECK(bRemoved == true);
		if (bRemoved) {
			CallBackCleanup.Release();
		}
	}

	TEST_CASE("Signal dispatch preserves errno") {
		Detours::Exception::ExceptionListener Listener;
		REQUIRE(Listener.AddCallBack(LinuxErrnoExceptionCallBack) == true);
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});

		errno = EDOM;
		int const nRaiseResult = ::raise(SIGTRAP);
		int const nObservedError = errno;
		CHECK(nRaiseResult == 0);
		CHECK(nObservedError == EDOM);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	TEST_CASE("ExceptionListener rejects duplicates and short-circuits handled signals") {
		g_nLinuxFirstExceptionCalls = 0;
		g_nLinuxSecondExceptionCalls = 0;
		Detours::Exception::ExceptionListener Listener;
		CHECK(Listener.RefreshHandler() == false);
		REQUIRE(Listener.EnableHandler() == true);
		CHECK(Listener.RefreshHandler() == true);
		REQUIRE(Listener.AddCallBack(LinuxFirstExceptionCallBack) == true);
		CHECK(Listener.AddCallBack(LinuxFirstExceptionCallBack) == false);
		REQUIRE(Listener.AddCallBack(LinuxSecondExceptionCallBack) == true);

		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxFirstExceptionCalls == 1);
		CHECK(g_nLinuxSecondExceptionCalls == 0);

		REQUIRE(Listener.RemoveCallBack(LinuxFirstExceptionCallBack) == true);
		REQUIRE(Listener.AddCallBack(LinuxFirstExceptionCallBack) == true);
		g_nLinuxFirstExceptionCalls = 0;
		g_nLinuxSecondExceptionCalls = 0;
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxFirstExceptionCalls == 1);
		CHECK(g_nLinuxSecondExceptionCalls == 1);

		CHECK(Listener.RemoveCallBack(LinuxSecondExceptionCallBack) == true);
		CHECK(Listener.RemoveCallBack(LinuxFirstExceptionCallBack) == true);
		CHECK(Listener.DisableHandler() == true);
		CHECK(Listener.RefreshHandler() == false);
	}

	TEST_CASE("ExceptionListener rejects stale snapshots after repeated callback reactivation") {
		g_nLinuxFirstExceptionCalls = 0;
		g_nLinuxSecondExceptionCalls = 0;
		g_bLinuxBlockNextExceptionOrderDispatch.store(false, std::memory_order_relaxed);
		g_bLinuxExceptionOrderDispatchBlocked.store(false, std::memory_order_relaxed);
		g_bLinuxReleaseExceptionOrderDispatch.store(false, std::memory_order_relaxed);
		g_bLinuxCycleExceptionOrderCallBack.store(false, std::memory_order_relaxed);
		g_bLinuxExceptionOrderCycleSucceeded.store(false, std::memory_order_relaxed);

		Detours::Exception::ExceptionListener Listener;
		std::thread DispatchThread;
		g_pLinuxExceptionOrderListener = &Listener;
		auto Cleanup = MakeScopeExit([&Listener, &DispatchThread]() {
			g_bLinuxReleaseExceptionOrderDispatch.store(true, std::memory_order_release);
			if (DispatchThread.joinable()) {
				DispatchThread.join();
			}

			g_pLinuxExceptionOrderListener = nullptr;
			Listener.RemoveCallBack(LinuxBlockingExceptionOrderCallBack);
			Listener.RemoveCallBack(LinuxFirstExceptionCallBack);
			Listener.RemoveCallBack(LinuxSecondExceptionCallBack);
			Listener.RemoveCallBack(LinuxExceptionOrderFallback);
			Listener.DisableHandler();
		});

		REQUIRE(Listener.AddCallBack(LinuxBlockingExceptionOrderCallBack) == true);
		REQUIRE(Listener.AddCallBack(LinuxFirstExceptionCallBack) == true);
		REQUIRE(Listener.AddCallBack(LinuxSecondExceptionCallBack) == true);
		REQUIRE(Listener.AddCallBack(LinuxExceptionOrderFallback) == true);
		REQUIRE(Listener.EnableHandler() == true);

		g_bLinuxBlockNextExceptionOrderDispatch.store(true, std::memory_order_release);
		DispatchThread = std::thread([]() {
			::raise(SIGTRAP);
		});
		REQUIRE(WaitForTestCondition([]() {
			return g_bLinuxExceptionOrderDispatchBlocked.load(std::memory_order_acquire);
		},
									 1000));

		g_bLinuxCycleExceptionOrderCallBack.store(true, std::memory_order_release);
		REQUIRE(::raise(SIGTRAP) == 0);
		REQUIRE(g_bLinuxExceptionOrderCycleSucceeded.load(std::memory_order_acquire) == true);
		g_bLinuxReleaseExceptionOrderDispatch.store(true, std::memory_order_release);
		DispatchThread.join();

		CHECK(g_nLinuxFirstExceptionCalls == 1);
		CHECK(g_nLinuxSecondExceptionCalls == 1);
		g_pLinuxExceptionOrderListener = nullptr;
		CHECK(Listener.RemoveCallBack(LinuxBlockingExceptionOrderCallBack) == true);
		CHECK(Listener.RemoveCallBack(LinuxFirstExceptionCallBack) == true);
		CHECK(Listener.RemoveCallBack(LinuxSecondExceptionCallBack) == true);
		CHECK(Listener.RemoveCallBack(LinuxExceptionOrderFallback) == true);
		CHECK(Listener.DisableHandler() == true);
		Cleanup.Release();
	}

	TEST_CASE("ExceptionListener publishes callbacks only while enabled") {
		g_nLinuxConfiguredExceptionCalls = 0;
		g_nLinuxDestroyedExceptionCalls = 0;
		REQUIRE(Detours::Exception::g_ExceptionListener.EnableHandler() == true);

		Detours::Exception::ExceptionListener Listener;
		REQUIRE(Listener.AddCallBack(LinuxConfiguredExceptionCallBack) == true);
		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(LinuxExceptionCallBackFallback) == true);
		auto NeverEnabledFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBackFallback);
		});
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxConfiguredExceptionCalls == 0);
		REQUIRE(Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBackFallback) == true);
		NeverEnabledFallbackCleanup.Release();

		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxConfiguredExceptionCalls == 1);
		REQUIRE(Listener.DisableHandler() == true);
		ListenerCleanup.Release();

		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(LinuxExceptionCallBackFallback) == true);
		auto DisabledFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBackFallback);
		});
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxConfiguredExceptionCalls == 1);
		REQUIRE(Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxExceptionCallBackFallback) == true);
		DisabledFallbackCleanup.Release();

		REQUIRE(Listener.EnableHandler() == true);
		auto ReenabledListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxConfiguredExceptionCalls == 2);
		REQUIRE(Listener.DisableHandler() == true);
		ReenabledListenerCleanup.Release();

		{
			Detours::Exception::ExceptionListener DestroyedListener;
			REQUIRE(DestroyedListener.AddCallBack(LinuxDestroyedExceptionCallBack) == true);
			REQUIRE(DestroyedListener.EnableHandler() == true);
			REQUIRE(::raise(SIGTRAP) == 0);
			CHECK(g_nLinuxDestroyedExceptionCalls == 1);
		}

		REQUIRE(Detours::Exception::g_ExceptionListener.AddCallBack(LinuxDestroyedExceptionCallBackFallback) == true);
		auto DestroyedFallbackCleanup = MakeScopeExit([]() {
			Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxDestroyedExceptionCallBackFallback);
		});
		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_nLinuxDestroyedExceptionCalls == 1);
		bool const bFallbackRemoved =
			Detours::Exception::g_ExceptionListener.RemoveCallBack(LinuxDestroyedExceptionCallBackFallback);
		CHECK(bFallbackRemoved == true);
		if (bFallbackRemoved) {
			DestroyedFallbackCleanup.Release();
		}
	}

	TEST_CASE("ExceptionListener recovers active dispatch state after fork") {
		g_unLinuxExceptionForkCallBacksEntered.store(0, std::memory_order_relaxed);
		g_bLinuxExceptionForkRelease.store(false, std::memory_order_relaxed);
		g_nLinuxExceptionForkChildPID.store(0, std::memory_order_relaxed);

		Detours::Exception::ExceptionListener Listener;
		g_pLinuxExceptionForkListener = &Listener;
		auto ListenerPointerCleanup = MakeScopeExit([]() {
			g_pLinuxExceptionForkListener = nullptr;
		});
		REQUIRE(Listener.AddCallBack(LinuxExceptionForkCallBack) == true);
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			g_bLinuxExceptionForkRelease.store(true, std::memory_order_release);
			Listener.RemoveCallBack(LinuxExceptionForkCallBack);
			Listener.DisableHandler();
		});

		std::thread ForkDispatchThread([]() {
			g_nLinuxExceptionForkOwnerThreadID.store(
				static_cast<int>(::syscall(SYS_gettid)),
				std::memory_order_release);
			g_bLinuxExceptionForkChild = 0;
			::raise(SIGTRAP);
			if (g_bLinuxExceptionForkChild) {
				bool const bRemoved = g_pLinuxExceptionForkListener &&
									  g_pLinuxExceptionForkListener->RemoveCallBack(LinuxExceptionForkCallBack);
				bool const bDisabled = g_pLinuxExceptionForkListener &&
									   g_pLinuxExceptionForkListener->DisableHandler();
				::_exit((bRemoved && bDisabled) ? kLinuxSignalChainingSuccessExitCode : kLinuxSignalChainingFailureExitCode);
			}

			g_nLinuxExceptionForkOwnerThreadID.store(0, std::memory_order_release);
		});
		std::thread ConcurrentDispatchThread([]() {
			::raise(SIGTRAP);
		});
		auto DispatchCleanup = MakeScopeExit([&ForkDispatchThread, &ConcurrentDispatchThread]() {
			g_bLinuxExceptionForkRelease.store(true, std::memory_order_release);
			if (ForkDispatchThread.joinable()) {
				ForkDispatchThread.join();
			}

			if (ConcurrentDispatchThread.joinable()) {
				ConcurrentDispatchThread.join();
			}
		});

		bool const bChildStarted = WaitForTestCondition([]() {
			return g_nLinuxExceptionForkChildPID.load(std::memory_order_acquire) != 0;
		},
														kLinuxMemoryHookWaitMilliseconds);
		pid_t const nChildPID = static_cast<pid_t>(g_nLinuxExceptionForkChildPID.load(std::memory_order_acquire));
		int nStatus = 0;
		bool const bChildReaped = bChildStarted && (nChildPID > 0) &&
								  WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds);

		g_bLinuxExceptionForkRelease.store(true, std::memory_order_release);
		ForkDispatchThread.join();
		ConcurrentDispatchThread.join();
		DispatchCleanup.Release();

		REQUIRE(bChildStarted == true);
		REQUIRE(nChildPID > 0);
		REQUIRE(bChildReaped == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
		CHECK(Listener.RemoveCallBack(LinuxExceptionForkCallBack) == true);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	TEST_CASE("Fork refresh preserves an externally replaced signal action") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::ExceptionListener Listener;
			if (!Listener.AddCallBack(LinuxExceptionCallBackFallback) || !Listener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			struct sigaction ReplacementAction {};
			ReplacementAction.sa_sigaction = LinuxExternalReplacementSignalHandler;
			sigemptyset(&ReplacementAction.sa_mask);
			ReplacementAction.sa_flags = SA_SIGINFO;
			if (::sigaction(SIGILL, &ReplacementAction, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			pid_t const nRefreshChildPID = ::fork();
			if (nRefreshChildPID < 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (nRefreshChildPID == 0) {
				std::deque<Detours::Exception::fnExceptionCallBack> const deqCallBacks = Listener.GetCallBackSnapshot();
				struct sigaction CurrentAction {};
				bool const bReplacementPreserved = (::sigaction(SIGILL, nullptr, &CurrentAction) == 0) &&
												   ((CurrentAction.sa_flags & SA_SIGINFO) != 0) &&
												   (CurrentAction.sa_sigaction == LinuxExternalReplacementSignalHandler);
				::_exit((bReplacementPreserved && (deqCallBacks.size() == 1)) ? kLinuxSignalChainingSuccessExitCode : kLinuxSignalChainingFailureExitCode);
			}

			int nRefreshStatus = 0;
			bool const bRefreshChildReaped =
				WaitForChildProcess(nRefreshChildPID, &nRefreshStatus, kLinuxChildWaitMilliseconds);
			bool const bSuccess = bRefreshChildReaped && WIFEXITED(nRefreshStatus) &&
								  (WEXITSTATUS(nRefreshStatus) == kLinuxSignalChainingSuccessExitCode);
			::_exit(bSuccess ? kLinuxSignalChainingSuccessExitCode : kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}




	TEST_CASE("ExceptionListener supports nested signal self-removal") {
		g_unLinuxNestedExceptionCalls.store(0, std::memory_order_relaxed);
		g_unLinuxNestedExceptionFallbackCalls.store(0, std::memory_order_relaxed);
		g_bLinuxNestedExceptionRemovalSucceeded.store(false, std::memory_order_relaxed);

		Detours::Exception::ExceptionListener Listener;
		g_pLinuxNestedExceptionListener = &Listener;
		auto ListenerPointerCleanup = MakeScopeExit([]() {
			g_pLinuxNestedExceptionListener = nullptr;
		});
		REQUIRE(Listener.AddCallBack(LinuxNestedExceptionCallBack) == true);
		REQUIRE(Listener.AddCallBack(LinuxNestedExceptionFallback) == true);
		REQUIRE(Listener.EnableHandler() == true);
		auto ListenerCleanup = MakeScopeExit([&Listener]() {
			Listener.DisableHandler();
		});

		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_unLinuxNestedExceptionCalls.load(std::memory_order_relaxed) == 2);
		CHECK(g_bLinuxNestedExceptionRemovalSucceeded.load(std::memory_order_acquire) == true);
		CHECK(g_unLinuxNestedExceptionFallbackCalls.load(std::memory_order_relaxed) == 0);

		REQUIRE(::raise(SIGTRAP) == 0);
		CHECK(g_unLinuxNestedExceptionFallbackCalls.load(std::memory_order_relaxed) == 1);
		CHECK(Listener.DisableHandler() == true);
		ListenerCleanup.Release();
	}

	TEST_CASE("Concurrent first signal install publishes an exact predecessor") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_unLinuxConcurrentInstallCalls.store(0, std::memory_order_relaxed);
			g_bLinuxConcurrentInstallStop.store(false, std::memory_order_relaxed);

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxConcurrentInstallSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			if (::sigaction(SIGILL, &PreviousAction, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			std::thread Sender([]() {
				while (!g_bLinuxConcurrentInstallStop.load(std::memory_order_acquire)) {
					::raise(SIGILL);
				}
			});
			bool const bSenderStarted = WaitForTestCondition([]() {
				return g_unLinuxConcurrentInstallCalls.load(std::memory_order_acquire) != 0;
			},
															 1000);
			bool const bEnabled = bSenderStarted && Detours::Exception::g_ExceptionListener.EnableHandler();
			g_bLinuxConcurrentInstallStop.store(true, std::memory_order_release);
			Sender.join();
			bool const bCallObserved = g_unLinuxConcurrentInstallCalls.load(std::memory_order_relaxed) != 0;
			Detours::Exception::g_ExceptionListener.DisableHandler();
			bool const bSuccess = bSenderStarted && bEnabled && bCallObserved;
			::_exit(bSuccess ? kLinuxSignalChainingSuccessExitCode : kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("Partial signal install rolls back installed actions") {
		constexpr char kTestCase[] = "Partial signal install rolls back installed actions";
		if (!IsLinuxIsolatedTestProcess(kTestCase)) {
			REQUIRE(RunLinuxIsolatedTest(kTestCase) == true);
			return;
		}

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_nLinuxRollbackSignalCalls = 0;

			constexpr int kSignals[] = { SIGSEGV, SIGTRAP, SIGILL, SIGFPE, SIGBUS };
			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxRollbackSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			for (auto const nSignal : kSignals) {
				if (::sigaction(nSignal, &PreviousAction, nullptr) != 0) {
					::_exit(kLinuxSignalChainingFailureExitCode);
				}
			}

			if (!InstallLinuxSigactionFailureFilter(SIGBUS)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			constexpr int kRestoredSignals[] = { SIGSEGV, SIGTRAP, SIGILL, SIGFPE };
			for (auto const nSignal : kRestoredSignals) {
				struct sigaction RestoredAction {};
				if ((::sigaction(nSignal, nullptr, &RestoredAction) != 0) ||
					((RestoredAction.sa_flags & SA_SIGINFO) == 0) ||
					(RestoredAction.sa_sigaction != LinuxRollbackSignalHandler)) {
					::_exit(kLinuxSignalChainingFailureExitCode);
				}
			}

			if ((::raise(SIGILL) != 0) || (g_nLinuxRollbackSignalCalls != 1)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::_exit(kLinuxSignalChainingSuccessExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("Failed signal restore retains ownership for retry") {
		constexpr char kTestCase[] = "Failed signal restore retains ownership for retry";
		if (!IsLinuxIsolatedTestProcess(kTestCase)) {
			REQUIRE(RunLinuxIsolatedTest(kTestCase) == true);
			return;
		}

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_nLinuxRollbackSignalCalls = 0;

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxRollbackSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			if ((::sigaction(SIGSEGV, &PreviousAction, nullptr) != 0) ||
				!Detours::Exception::g_ExceptionListener.EnableHandler() ||
				!InstallLinuxSigactionRestoreFailureFilter(SIGSEGV)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (Detours::Exception::g_ExceptionListener.DisableHandler() ||
				(::raise(SIGSEGV) != 0) || (g_nLinuxRollbackSignalCalls != 1)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (!Detours::Exception::g_ExceptionListener.EnableHandler() ||
				(::raise(SIGSEGV) != 0) || (g_nLinuxRollbackSignalCalls != 2)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (Detours::Exception::g_ExceptionListener.DisableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::_exit(kLinuxSignalChainingSuccessExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("DisableHandler preserves an externally replaced signal action") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxRollbackSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			if ((::sigaction(SIGILL, &PreviousAction, nullptr) != 0) ||
				!Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			struct sigaction ReplacementAction {};
			ReplacementAction.sa_sigaction = LinuxExternalReplacementSignalHandler;
			sigemptyset(&ReplacementAction.sa_mask);
			ReplacementAction.sa_flags = SA_SIGINFO;
			if ((::sigaction(SIGILL, &ReplacementAction, nullptr) != 0) ||
				!Detours::Exception::g_ExceptionListener.DisableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			struct sigaction CurrentAction {};
			if ((::sigaction(SIGILL, nullptr, &CurrentAction) != 0) ||
				((CurrentAction.sa_flags & SA_SIGINFO) == 0) ||
				(CurrentAction.sa_sigaction != LinuxExternalReplacementSignalHandler)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::raise(SIGILL);
			::_exit(kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("Reset-on-entry state is isolated across install generations") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_nLinuxResetSignalCalls = 0;

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxResetSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO | SA_RESETHAND;
			for (std::size_t unGeneration = 0; unGeneration < 2; ++unGeneration) {
				if ((::sigaction(SIGILL, &PreviousAction, nullptr) != 0) ||
					!Detours::Exception::g_ExceptionListener.EnableHandler() ||
					(::raise(SIGILL) != 0) ||
					(g_nLinuxResetSignalCalls != static_cast<std::sig_atomic_t>(unGeneration + 1)) ||
					!Detours::Exception::g_ExceptionListener.DisableHandler()) {
					::_exit(kLinuxSignalChainingFailureExitCode);
				}
			}

			::_exit(kLinuxSignalChainingSuccessExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("Concurrent reset-on-entry dispatch resets exactly once") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_bLinuxResetRaceEntered.store(false, std::memory_order_relaxed);

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxResetRaceSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO | SA_RESETHAND;
			if ((::sigaction(SIGILL, &PreviousAction, nullptr) != 0) ||
				!Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			std::thread FirstDispatch([]() {
				::raise(SIGILL);
			});
			if (!WaitForTestCondition([]() {
					return g_bLinuxResetRaceEntered.load(std::memory_order_acquire);
				},
									  1000)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::raise(SIGILL);
			::_exit(kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFSIGNALED(nStatus));
		CHECK(WTERMSIG(nStatus) == SIGILL);
	}

	TEST_CASE("Previous signal action preserves mask and alternate stack") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();

			std::size_t const unAlternateStackSize = static_cast<std::size_t>(SIGSTKSZ) * 2;
			void* const pAlternateStack =
				::mmap(nullptr, unAlternateStackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (pAlternateStack == MAP_FAILED) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			g_pLinuxSignalAlternateStack = pAlternateStack;
			g_unLinuxSignalAlternateStackSize = unAlternateStackSize;
			stack_t AlternateStack {};
			AlternateStack.ss_sp = pAlternateStack;
			AlternateStack.ss_size = unAlternateStackSize;
			if (::sigaltstack(&AlternateStack, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxMaskedOnStackSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			sigaddset(&PreviousAction.sa_mask, SIGUSR1);
			PreviousAction.sa_flags = SA_SIGINFO | SA_ONSTACK;
			if (::sigaction(SIGILL, &PreviousAction, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (!Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::raise(SIGILL);
			::_exit(kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxSignalChainingSuccessExitCode);
	}

	TEST_CASE("Previous signal action preserves reset-on-entry") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();
			g_nLinuxResetSignalCalls = 0;

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxResetSignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO | SA_RESETHAND;
			if (::sigaction(SIGILL, &PreviousAction, nullptr) != 0) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if (!Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			if ((::raise(SIGILL) != 0) || (g_nLinuxResetSignalCalls != 1)) {
				::_exit(kLinuxSignalChainingFailureExitCode);
			}

			::raise(SIGILL);
			::_exit(kLinuxSignalChainingFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFSIGNALED(nStatus));
		CHECK(WTERMSIG(nStatus) == SIGILL);
	}
} // TEST_SUITE("Detours::Exception")

TEST_SUITE("Detours::rddisasm") {
	TEST_CASE("RdDecode") {
		Detours::rddisasm::INSTRUCTION ins {};
		unsigned char arrCode[16] {};
		arrCode[0] = 0xB0;
		arrCode[1] = 0x01;
#if defined(DETOURS_ARCH_X64)
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, arrCode, RD_DATA_64, RD_DATA_64)) == true);
#elif defined(DETOURS_ARCH_X86)
		CHECK(RD_SUCCESS(Detours::rddisasm::RdDecode(&ins, arrCode, RD_DATA_32, RD_DATA_32)) == true);
#endif
		CHECK(ins.Length == 2);
		CHECK(ins.Instruction == Detours::rddisasm::RD_INS_CLASS::RD_INS_MOV);
	}
}

TEST_SUITE("Detours::Hook") {




	TEST_CASE("VTableFunctionHook rejects the existing slot value") {
		void* pFunction = reinterpret_cast<void*>(LinuxInlineHookReplacement);
		Detours::Hook::VTableFunctionHook Hook(&pFunction, 0);
		CHECK(Hook.Hook(pFunction) == false);
		CHECK(Hook.IsHooked() == false);
		CHECK(pFunction == reinterpret_cast<void*>(LinuxInlineHookReplacement));
		CHECK(Hook.Release() == true);
	}

	TEST_CASE("InlineHook hooks and restores executable memory") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pTargetAddress = CreateLinuxHookTarget(kLinuxInlineOriginalValue);
		REQUIRE(pTargetAddress != nullptr);
		auto MappingCleanup = MakeScopeExit([pTargetAddress, unPageSize]() {
			::munmap(pTargetAddress, unPageSize);
		});

		fnLinuxHookTarget const pTarget = reinterpret_cast<fnLinuxHookTarget>(pTargetAddress);
		CHECK(pTarget() == static_cast<int>(kLinuxInlineOriginalValue));

		Detours::Hook::InlineHook InlineHook;
		REQUIRE(InlineHook.Set(pTargetAddress) == true);
		auto HookCleanup = MakeScopeExit([&InlineHook]() {
			InlineHook.UnHook();
			InlineHook.Release();
		});
		REQUIRE(InlineHook.Hook(reinterpret_cast<void*>(LinuxInlineHookReplacement), false) == true);
		CHECK(pTarget() == static_cast<int>(kLinuxInlineHookValue));
		CHECK(InlineHook.UnHook() == true);
		CHECK(pTarget() == static_cast<int>(kLinuxInlineOriginalValue));
		bool const bReleased = InlineHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

#if defined(__x86_64__) && defined(MAP_32BIT)
	TEST_CASE("InlineHook absolute jump preserves the System V red zone") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pTargetAddress = CreateLinuxRedZoneHookTarget();
		REQUIRE(pTargetAddress != nullptr);
		auto TargetCleanup = MakeScopeExit([pTargetAddress, unPageSize]() {
			::munmap(pTargetAddress, unPageSize);
		});
		void* const pReplacementAddress = CreateLinuxRedZoneHookReplacement();
		REQUIRE(pReplacementAddress != nullptr);
		auto ReplacementCleanup = MakeScopeExit([pReplacementAddress, unPageSize]() {
			::munmap(pReplacementAddress, unPageSize);
		});

		std::uintptr_t const unTargetAddress = reinterpret_cast<std::uintptr_t>(pTargetAddress) + kLinuxRedZoneHookOffset;
		std::uintptr_t const unReplacementAddress = reinterpret_cast<std::uintptr_t>(pReplacementAddress);
		std::uintptr_t const unDistance =
			(unTargetAddress >= unReplacementAddress) ? (unTargetAddress - unReplacementAddress) :
			(unReplacementAddress - unTargetAddress);
		REQUIRE(unDistance > kLinuxMaximumRelativeJumpDistance);

		fnLinuxHookTarget const pTarget = reinterpret_cast<fnLinuxHookTarget>(pTargetAddress);
		CHECK(pTarget() == static_cast<int>(kLinuxRedZoneValue));

		unsigned char* const pHookAddress = static_cast<unsigned char*>(pTargetAddress) + kLinuxRedZoneHookOffset;
		Detours::Hook::InlineHook InlineHook(pHookAddress);
		auto HookCleanup = MakeScopeExit([&InlineHook]() {
			InlineHook.UnHook();
			InlineHook.Release();
		});
		REQUIRE(InlineHook.Hook(pReplacementAddress, false) == true);
		CHECK(pHookAddress[0] == 0xFF);
		CHECK(pHookAddress[1] == 0x25);
		unsigned int unJumpDisplacement = 1;
		std::memcpy(&unJumpDisplacement, pHookAddress + 2, sizeof(unJumpDisplacement));
		CHECK(unJumpDisplacement == 0);
		std::uintptr_t unEncodedReplacementAddress = 0;
		std::memcpy(&unEncodedReplacementAddress, pHookAddress + kLinuxAbsoluteJumpAddressOffset, sizeof(unEncodedReplacementAddress));
		CHECK(unEncodedReplacementAddress == unReplacementAddress);
		CHECK(pTarget() == static_cast<int>(kLinuxRedZoneValue));
		CHECK(InlineHook.UnHook() == true);
		CHECK(pTarget() == static_cast<int>(kLinuxRedZoneValue));
		bool const bReleased = InlineHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}
#endif

	TEST_CASE("Inline hooks reject their target as the replacement") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pTargetAddress = CreateLinuxHookTarget(kLinuxInlineOriginalValue);
		REQUIRE(pTargetAddress != nullptr);
		auto MappingCleanup = MakeScopeExit([pTargetAddress, unPageSize]() {
			::munmap(pTargetAddress, unPageSize);
		});

		Detours::Hook::InlineHook InlineHook(pTargetAddress);
		CHECK(InlineHook.Hook(pTargetAddress, false) == false);
		CHECK(InlineHook.GetTrampoline() == nullptr);
		CHECK(InlineHook.Release() == true);

		Detours::Hook::InlineWrapperHook WrapperHook(pTargetAddress);
		CHECK(WrapperHook.Hook(pTargetAddress, false) == false);
		CHECK(WrapperHook.GetTrampoline() == nullptr);
		CHECK(WrapperHook.Release() == true);
		CHECK(reinterpret_cast<fnLinuxHookTarget>(pTargetAddress)() == static_cast<int>(kLinuxInlineOriginalValue));
	}

	TEST_CASE("RawHook calls trampoline and restores executable memory") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pTargetAddress = CreateLinuxHookTarget(kLinuxRawHookValue);
		REQUIRE(pTargetAddress != nullptr);
		auto MappingCleanup = MakeScopeExit([pTargetAddress, unPageSize]() {
			::munmap(pTargetAddress, unPageSize);
		});

		fnLinuxHookTarget const pTarget = reinterpret_cast<fnLinuxHookTarget>(pTargetAddress);
		CHECK(pTarget() == static_cast<int>(kLinuxRawHookValue));
		g_unLinuxRawHookCalls.store(0, std::memory_order_relaxed);
		REQUIRE(g_LinuxRawHook.Set(pTargetAddress) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_LinuxRawHook.UnHook();
			g_LinuxRawHook.Release();
		});
		REQUIRE(g_LinuxRawHook.Hook(LinuxRawHookCallBack, false, kLinuxRawReservedStackSize, false) == true);
		CHECK(pTarget() == static_cast<int>(kLinuxRawHookValue));
		CHECK(g_unLinuxRawHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_LinuxRawHook.UnHook() == true);
		CHECK(pTarget() == static_cast<int>(kLinuxRawHookValue));
		CHECK(g_unLinuxRawHookCalls.load(std::memory_order_relaxed) == 1);
		bool const bReleased = g_LinuxRawHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("Inline hooks reject an instruction truncated by a guard page") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));
		unsigned char* const pMemory = static_cast<unsigned char*>(::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE,
																		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		REQUIRE(pMemory != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMemory, unPageSize]() {
			::munmap(pMemory, unPageSize * 2);
		});
		pMemory[unPageSize - 1] = 0x0F;
		REQUIRE(::mprotect(pMemory, unPageSize, PROT_READ | PROT_EXEC) == 0);
		REQUIRE(::mprotect(pMemory + unPageSize, unPageSize, PROT_NONE) == 0);
		void* const pTruncatedInstruction = pMemory + unPageSize - 1;

		Detours::Hook::InlineHook InlineHook(pTruncatedInstruction);
		CHECK(InlineHook.Hook(reinterpret_cast<void*>(LinuxInlineHookReplacement), false) == false);
		CHECK(InlineHook.Release() == true);

		Detours::Hook::InlineWrapperHook WrapperHook(pTruncatedInstruction);
		CHECK(WrapperHook.Hook(reinterpret_cast<void*>(LinuxInlineHookReplacement), false) == false);
		CHECK(WrapperHook.Release() == true);
	}

	TEST_CASE("Failed inline relocation preserves shared trampoline execution") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize >= 256);
		unsigned char* const pMemory = static_cast<unsigned char*>(::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE,
																		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		REQUIRE(pMemory != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMemory, unPageSize]() {
			::munmap(pMemory, unPageSize);
		});
		std::memset(pMemory, kLinuxNoOperationOpcode, unPageSize);

		unsigned char* const pWorkingTarget = pMemory;
		pWorkingTarget[0] = kLinuxMoveImmediateOpcode;
		unsigned int const unOriginalValue = kLinuxInlineOriginalValue;
		std::memcpy(pWorkingTarget + kLinuxImmediateOffset, &unOriginalValue, sizeof(unOriginalValue));
		pWorkingTarget[kLinuxReturnCodeSize - 1] = kLinuxReturnOpcode;
		unsigned char* const pFailingTarget = pMemory + 64;
		pFailingTarget[0] = 0xEB;
		pFailingTarget[1] = 0x7E;
		REQUIRE(::mprotect(pMemory, unPageSize, PROT_READ | PROT_EXEC) == 0);

		Detours::Hook::InlineHook WorkingHook(pWorkingTarget);
		REQUIRE(WorkingHook.Hook(reinterpret_cast<void*>(LinuxInlineHookReplacement), false) == true);
		auto WorkingHookCleanup = MakeScopeExit([&WorkingHook]() {
			WorkingHook.UnHook();
			WorkingHook.Release();
		});
		void* const pTrampolineAddress = WorkingHook.GetTrampoline();
		REQUIRE(pTrampolineAddress != nullptr);

		Detours::Hook::InlineHook FailingHook(pFailingTarget);
		CHECK(FailingHook.Hook(reinterpret_cast<void*>(LinuxInlineHookReplacement), false) == false);
		CHECK(FailingHook.Release() == true);

		int nTrampolineProtection = PROT_NONE;
		std::uintptr_t const unTrampolineAddress =
			reinterpret_cast<std::uintptr_t>(pTrampolineAddress);
		void* const pTrampolinePageAddress = reinterpret_cast<void*>(
			unTrampolineAddress - (unTrampolineAddress % unPageSize));
		Detours::Memory::Page TrampolineProbe(pTrampolinePageAddress, false, false);
		REQUIRE(TrampolineProbe.GetProtection(&nTrampolineProtection) == true);
		REQUIRE(nTrampolineProtection == (PROT_READ | PROT_EXEC));
		CHECK(reinterpret_cast<fnLinuxHookTarget>(pWorkingTarget)() == static_cast<int>(kLinuxInlineHookValue));
		CHECK(reinterpret_cast<fnLinuxHookTarget>(pTrampolineAddress)() == static_cast<int>(kLinuxInlineOriginalValue));
		CHECK(WorkingHook.UnHook() == true);
		CHECK(WorkingHook.Release() == true);
		WorkingHookCleanup.Release();
	}

	TEST_CASE("RawHook validates synthetic redirect frames") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pTargetAddress = CreateLinuxHookTarget(kLinuxRawHookValue);
		REQUIRE(pTargetAddress != nullptr);
		auto MappingCleanup = MakeScopeExit([pTargetAddress, unPageSize]() {
			::munmap(pTargetAddress, unPageSize);
		});

		fnLinuxHookTarget const pTarget = reinterpret_cast<fnLinuxHookTarget>(pTargetAddress);
		CHECK(pTarget() == static_cast<int>(kLinuxRawHookValue));
		g_unLinuxRawRedirectCalls.store(0, std::memory_order_relaxed);

		Detours::Hook::RawHook TransitionHook;
		REQUIRE(TransitionHook.Set(pTargetAddress) == true);
		auto HookCleanup = MakeScopeExit([&TransitionHook]() {
			TransitionHook.UnHook();
			TransitionHook.Release();
		});

		SUBCASE("one synthetic redirect frame is executed") {
			REQUIRE(TransitionHook.Hook(LinuxRawSingleRedirectHookCallBack, false, kLinuxRawRedirectReservedStackSize, false) == true);
			CHECK(pTarget() == static_cast<int>(kLinuxRawRedirectValue));
			CHECK(g_unLinuxRawRedirectCalls.load(std::memory_order_relaxed) == 1);
		}

		SUBCASE("two synthetic redirect frames restore the original return path") {
			REQUIRE(TransitionHook.Hook(LinuxRawUnsupportedRedirectHookCallBack, false, kLinuxRawRedirectReservedStackSize, false) == true);
			CHECK(pTarget() == static_cast<int>(kLinuxRawFailSafeValue));
			CHECK(g_unLinuxRawRedirectCalls.load(std::memory_order_relaxed) == 0);
		}

		CHECK(TransitionHook.UnHook() == true);
		CHECK(pTarget() == static_cast<int>(kLinuxRawHookValue));
		bool const bReleased = TransitionHook.Release();
		CHECK(bReleased == true);
		if (bReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("RawHook accepts only documented return stack shapes") {
		CHECK(RunLinuxRawStackValidationScenario(LinuxRawStackGapBelowEntryHookCallBack) == true);
		CHECK(RunLinuxRawStackValidationScenario(LinuxRawStackAboveEntryHookCallBack) == true);
	}

	TEST_CASE("Two RawHooks coexist within hook storage capacity") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pFirstTargetAddress = CreateLinuxHookTarget(kLinuxFirstRawCapacityValue);
		REQUIRE(pFirstTargetAddress != nullptr);
		auto FirstMappingCleanup = MakeScopeExit([pFirstTargetAddress, unPageSize]() {
			::munmap(pFirstTargetAddress, unPageSize);
		});
		void* const pSecondTargetAddress = CreateLinuxHookTarget(kLinuxSecondRawCapacityValue);
		REQUIRE(pSecondTargetAddress != nullptr);
		auto SecondMappingCleanup = MakeScopeExit([pSecondTargetAddress, unPageSize]() {
			::munmap(pSecondTargetAddress, unPageSize);
		});

		g_unLinuxFirstCapacityRawHookCalls.store(0, std::memory_order_relaxed);
		g_unLinuxSecondCapacityRawHookCalls.store(0, std::memory_order_relaxed);
		REQUIRE(g_LinuxFirstCapacityRawHook.Set(pFirstTargetAddress) == true);
		auto HookCleanup = MakeScopeExit([]() {
			g_LinuxSecondCapacityRawHook.UnHook();
			g_LinuxSecondCapacityRawHook.Release();
			g_LinuxFirstCapacityRawHook.UnHook();
			g_LinuxFirstCapacityRawHook.Release();
		});
		REQUIRE(g_LinuxSecondCapacityRawHook.Set(pSecondTargetAddress) == true);

		REQUIRE(g_LinuxFirstCapacityRawHook.Hook(LinuxFirstCapacityRawHookCallBack, false, kLinuxRawReservedStackSize, false) == true);
		REQUIRE(g_LinuxSecondCapacityRawHook.Hook(LinuxSecondCapacityRawHookCallBack, false, kLinuxRawReservedStackSize, false) == true);

		fnLinuxHookTarget const pFirstTarget = reinterpret_cast<fnLinuxHookTarget>(pFirstTargetAddress);
		fnLinuxHookTarget const pSecondTarget = reinterpret_cast<fnLinuxHookTarget>(pSecondTargetAddress);
		CHECK(pFirstTarget() == static_cast<int>(kLinuxFirstRawCapacityValue));
		CHECK(pSecondTarget() == static_cast<int>(kLinuxSecondRawCapacityValue));
		CHECK(g_unLinuxFirstCapacityRawHookCalls.load(std::memory_order_relaxed) == 1);
		CHECK(g_unLinuxSecondCapacityRawHookCalls.load(std::memory_order_relaxed) == 1);

		bool const bSecondUnHooked = g_LinuxSecondCapacityRawHook.UnHook();
		bool const bSecondReleased = g_LinuxSecondCapacityRawHook.Release();
		bool const bFirstUnHooked = g_LinuxFirstCapacityRawHook.UnHook();
		bool const bFirstReleased = g_LinuxFirstCapacityRawHook.Release();
		CHECK(bSecondUnHooked == true);
		CHECK(bSecondReleased == true);
		CHECK(bFirstUnHooked == true);
		CHECK(bFirstReleased == true);
		if (bSecondUnHooked && bSecondReleased && bFirstUnHooked && bFirstReleased) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("VTableHook rolls back earlier entries when a later entry fails") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize >= sizeof(void*));
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		unsigned char* const pMapping = static_cast<unsigned char*>(::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		REQUIRE(pMapping != MAP_FAILED);
		bool bSecondPageMapped = true;
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize, &bSecondPageMapped]() {
			if (bSecondPageMapped) {
				::munmap(pMapping + unPageSize, unPageSize);
			}

			::munmap(pMapping, unPageSize);
		});

		void** const pVTable = reinterpret_cast<void**>(pMapping + unPageSize - sizeof(void*));
		pVTable[0] = reinterpret_cast<void*>(LinuxVTableRollbackOriginal);
		REQUIRE(::mprotect(pMapping, unPageSize, PROT_READ) == 0);
		REQUIRE(::munmap(pMapping + unPageSize, unPageSize) == 0);
		bSecondPageMapped = false;

		void* arrHookVTable[] = {
			reinterpret_cast<void*>(LinuxVTableRollbackReplacement),
			reinterpret_cast<void*>(LinuxVTableRollbackReplacement)
		};
		Detours::Hook::VTableHook VTableHook;
		REQUIRE(VTableHook.Set(pVTable, 2) == true);
		CHECK(VTableHook.Hook(arrHookVTable) == false);
		CHECK(pVTable[0] == reinterpret_cast<void*>(LinuxVTableRollbackOriginal));
		using fnVTableRollback = int (*)();
		CHECK(reinterpret_cast<fnVTableRollback>(pVTable[0])() == 17);
		CHECK(VTableHook.GetHookingFunctions().empty());

		int nProtection = PROT_NONE;
		Detours::Memory::Page ProtectionProbe(pMapping, false, false);
		REQUIRE(ProtectionProbe.GetPageAddress() == pMapping);
		REQUIRE(ProtectionProbe.GetProtection(&nProtection) == true);
		CHECK(nProtection == PROT_READ);
		CHECK(VTableHook.Release() == true);
	}

	TEST_CASE("InterruptHook handles vector zero") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize >= 8);
		unsigned char* const pCode = static_cast<unsigned char*>(::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		REQUIRE(pCode != reinterpret_cast<unsigned char*>(MAP_FAILED));
		auto MappingCleanup = MakeScopeExit([pCode, unPageSize]() {
			::munmap(pCode, unPageSize);
		});

		unsigned char const arrCode[] = { 0xCD, 0x00, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
		std::memcpy(pCode, arrCode, sizeof(arrCode));
		__builtin___clear_cache(reinterpret_cast<char*>(pCode), reinterpret_cast<char*>(pCode + sizeof(arrCode)));
		REQUIRE(::mprotect(pCode, unPageSize, PROT_READ | PROT_EXEC) == 0);

		g_nLinuxZeroInterruptCalls = 0;
		REQUIRE(Detours::Hook::HookInterrupt(LinuxZeroInterruptHook, 0) == true);
		auto HookCleanup = MakeScopeExit([]() {
			Detours::Hook::UnHookInterrupt(LinuxZeroInterruptHook);
		});

		using fnZeroInterrupt = int (*)();
		CHECK(reinterpret_cast<fnZeroInterrupt>(pCode)() == 42);
		CHECK(g_nLinuxZeroInterruptCalls == 1);
		bool const bUnHooked = Detours::Hook::UnHookInterrupt(LinuxZeroInterruptHook);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}


	TEST_CASE("InterruptHook rejects callback reuse for another vector") {
		REQUIRE(Detours::Hook::HookInterrupt(LinuxZeroInterruptHook, 0) == true);
		auto HookCleanup = MakeScopeExit([]() {
			Detours::Hook::UnHookInterrupt(LinuxZeroInterruptHook);
		});

		CHECK(Detours::Hook::HookInterrupt(LinuxZeroInterruptHook, 1) == false);
		bool const bUnHooked = Detours::Hook::UnHookInterrupt(LinuxZeroInterruptHook);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}
	}

	TEST_CASE("InterruptHook fork rebuilds child dispatch readers") {
		pid_t const nTestProcessID = ::fork();
		REQUIRE(nTestProcessID >= 0);
		if (nTestProcessID == 0) {
			std::size_t const unPageSize = GetTestPageSize();
			if (unPageSize < 8) {
				::_exit(kLinuxInterruptHookForkFailureExitCode);
			}

			unsigned char* const pCode = static_cast<unsigned char*>(
				::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
			if (pCode == reinterpret_cast<unsigned char*>(MAP_FAILED)) {
				::_exit(kLinuxInterruptHookForkFailureExitCode);
			}

			unsigned char const arrCode[] = { 0xCD, 0x00, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
			std::memcpy(pCode, arrCode, sizeof(arrCode));
			__builtin___clear_cache(reinterpret_cast<char*>(pCode), reinterpret_cast<char*>(pCode + sizeof(arrCode)));
			if (::mprotect(pCode, unPageSize, PROT_READ | PROT_EXEC) != 0) {
				::munmap(pCode, unPageSize);
				::_exit(kLinuxInterruptHookForkFailureExitCode);
			}

			g_unLinuxInterruptHookForkCallBacksEntered.store(0, std::memory_order_relaxed);
			g_nLinuxInterruptHookForkChildPID.store(0, std::memory_order_relaxed);
			g_bLinuxInterruptHookForkRelease.store(false, std::memory_order_relaxed);
			if (!Detours::Hook::HookInterrupt(LinuxInterruptHookForkCallBack, 0)) {
				::munmap(pCode, unPageSize);
				::_exit(kLinuxInterruptHookForkFailureExitCode);
			}

			std::atomic<int> nOwnerResult = 0;
			std::atomic<int> nConcurrentResult = 0;
			std::thread ConcurrentThread(InvokeLinuxInterruptHookFork, pCode, false, &nConcurrentResult);
			std::thread OwnerThread(InvokeLinuxInterruptHookFork, pCode, true, &nOwnerResult);
			ConcurrentThread.join();
			OwnerThread.join();

			pid_t const nHookChildPID = static_cast<pid_t>(g_nLinuxInterruptHookForkChildPID.load(std::memory_order_acquire));
			int nHookChildStatus = 0;
			bool const bChildCompleted = WaitForChildProcess(nHookChildPID, &nHookChildStatus, kLinuxChildWaitMilliseconds);
			bool const bUnHooked = Detours::Hook::UnHookInterrupt(LinuxInterruptHookForkCallBack);
			bool const bSuccess = (nOwnerResult.load(std::memory_order_acquire) == 42) &&
								  (nConcurrentResult.load(std::memory_order_acquire) == 42) &&
								  bChildCompleted && WIFEXITED(nHookChildStatus) &&
								  (WEXITSTATUS(nHookChildStatus) == 0) && bUnHooked;
			::munmap(pCode, unPageSize);
			::_exit(bSuccess ? 0 : kLinuxInterruptHookForkFailureExitCode);
		}

		int nTestStatus = 0;
		REQUIRE(WaitForChildProcess(nTestProcessID, &nTestStatus, kLinuxChildWaitMilliseconds * 2) == true);
		REQUIRE(WIFEXITED(nTestStatus));
		CHECK(WEXITSTATUS(nTestStatus) == 0);
	}

	TEST_CASE("Interrupt decoder does not read across a page boundary") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::g_ExceptionListener.DisableHandler();

			struct sigaction PreviousAction {};
			PreviousAction.sa_sigaction = LinuxBoundarySignalHandler;
			sigemptyset(&PreviousAction.sa_mask);
			PreviousAction.sa_flags = SA_SIGINFO;
			if (::sigaction(SIGSEGV, &PreviousAction, nullptr) != 0) {
				::_exit(80);
			}

			if (!Detours::Exception::g_ExceptionListener.EnableHandler()) {
				::_exit(81);
			}

			if (!Detours::Hook::HookInterrupt(LinuxBoundaryInterruptHook, 0)) {
				::_exit(82);
			}

			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize || (unPageSize > (std::numeric_limits<std::size_t>::max() / 2))) {
				::_exit(83);
			}

			unsigned char* const pMapping = static_cast<unsigned char*>(::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
			if (pMapping == reinterpret_cast<unsigned char*>(MAP_FAILED)) {
				::_exit(84);
			}

			unsigned char* const pInstruction = pMapping + unPageSize - 1;
			pInstruction[0] = 0xCD;
			__builtin___clear_cache(reinterpret_cast<char*>(pInstruction), reinterpret_cast<char*>(pInstruction + 1));
			if ((::mprotect(pMapping, unPageSize, PROT_READ | PROT_EXEC) != 0) ||
				(::mprotect(pMapping + unPageSize, unPageSize, PROT_NONE) != 0)) {
				::_exit(85);
			}

			using fnBoundaryInstruction = void (*)();
			reinterpret_cast<fnBoundaryInstruction>(pInstruction)();
			::_exit(86);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == kLinuxBoundarySignalExitCode);
	}

	TEST_CASE("HardwareHook invalidates inherited state and can be reinstalled after fork") {
		void* const pAddress = const_cast<unsigned int*>(&g_unLinuxHardwareHookForkValue);
		g_nLinuxHardwareHookForkCalls = 0;
		if (!Detours::Hook::HookHardware(
				0,
				Detours::Hook::REGISTER_DR0,
				LinuxHardwareHookForkCallBack,
				pAddress,
				Detours::Hook::TYPE_WRITE,
				sizeof(g_unLinuxHardwareHookForkValue))) {
			MESSAGE("The host does not permit perf-event hardware breakpoints.");
			return;
		}

		auto HookCleanup = MakeScopeExit([]() {
			Detours::Hook::UnHookHardware(0, Detours::Hook::REGISTER_DR0);
		});

		g_unLinuxHardwareHookForkValue = g_unLinuxHardwareHookForkValue + 1;
		REQUIRE(WaitForTestCondition([]() {
			return g_nLinuxHardwareHookForkCalls != 0;
		},
									 kLinuxMemoryHookWaitMilliseconds));
		std::sig_atomic_t const nParentCalls = g_nLinuxHardwareHookForkCalls;

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			bool const bInheritedUnHooked = Detours::Hook::UnHookHardware(0, Detours::Hook::REGISTER_DR0);
			g_nLinuxHardwareHookForkCalls = 0;
			bool const bReHooked = Detours::Hook::HookHardware(
				0,
				Detours::Hook::REGISTER_DR0,
				LinuxHardwareHookForkCallBack,
				pAddress,
				Detours::Hook::TYPE_WRITE,
				sizeof(g_unLinuxHardwareHookForkValue));
			if (bReHooked) {
				g_unLinuxHardwareHookForkValue = g_unLinuxHardwareHookForkValue + 1;
			}

			bool const bTriggered = bReHooked && WaitForTestCondition([]() {
										return g_nLinuxHardwareHookForkCalls != 0;
									},
																	  kLinuxMemoryHookWaitMilliseconds);
			bool const bUnHooked = bReHooked &&
								   Detours::Hook::UnHookHardware(0, Detours::Hook::REGISTER_DR0);
			::_exit((!bInheritedUnHooked && bReHooked && bTriggered && bUnHooked) ? EXIT_SUCCESS : kLinuxHardwareHookForkFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);

		g_unLinuxHardwareHookForkValue = g_unLinuxHardwareHookForkValue + 1;
		CHECK(WaitForTestCondition([nParentCalls]() {
				  return g_nLinuxHardwareHookForkCalls > nParentCalls;
			  },
								   kLinuxMemoryHookWaitMilliseconds) == true);
		REQUIRE(Detours::Hook::UnHookHardware(0, Detours::Hook::REGISTER_DR0) == true);
		HookCleanup.Release();
	}

	TEST_CASE("HardwareHook rejects a thread from another process") {
		pid_t const nScenarioPID = ::fork();
		REQUIRE(nScenarioPID >= 0);
		if (nScenarioPID == 0) {
			int arrReadyPipe[kLinuxPipeFileDescriptorCount] { -1, -1 };
			if (::pipe2(arrReadyPipe, O_CLOEXEC) != 0) {
				::_exit(EXIT_FAILURE);
			}

			pid_t const nOwnerPID = ::getpid();
			pid_t const nTargetPID = ::fork();
			if (nTargetPID < 0) {
				::_exit(EXIT_FAILURE);
			}

			if (nTargetPID == 0) {
				::close(arrReadyPipe[0]);
				if ((::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) || (::getppid() != nOwnerPID)) {
					::_exit(EXIT_FAILURE);
				}

				unsigned char const unReady = 1;
				ssize_t nWritten = 0;
				do {
					nWritten = ::write(arrReadyPipe[1], &unReady, sizeof(unReady));
				} while ((nWritten < 0) && (errno == EINTR));
				::close(arrReadyPipe[1]);
				if (nWritten != static_cast<ssize_t>(sizeof(unReady))) {
					::_exit(EXIT_FAILURE);
				}

				for (;;) {
					::pause();
				}
			}

			::close(arrReadyPipe[1]);
			unsigned char unReady = 0;
			ssize_t nRead = 0;
			do {
				nRead = ::read(arrReadyPipe[0], &unReady, sizeof(unReady));
			} while ((nRead < 0) && (errno == EINTR));
			::close(arrReadyPipe[0]);

			bool const bReady = (nRead == static_cast<ssize_t>(sizeof(unReady))) && (unReady == 1);
			bool const bHooked = bReady && Detours::Hook::HookHardware(
											   static_cast<unsigned int>(nTargetPID),
											   Detours::Hook::REGISTER_DR0,
											   LinuxHardwareHookForkCallBack,
											   const_cast<unsigned int*>(&g_unLinuxHardwareHookForkValue),
											   Detours::Hook::TYPE_WRITE,
											   sizeof(g_unLinuxHardwareHookForkValue));
			if (bHooked) {
				Detours::Hook::UnHookHardware(static_cast<unsigned int>(nTargetPID), Detours::Hook::REGISTER_DR0);
			}

			bool const bKilled = ::kill(nTargetPID, SIGKILL) == 0;
			int nTargetStatus = 0;
			pid_t nWaitResult = 0;
			do {
				nWaitResult = ::waitpid(nTargetPID, &nTargetStatus, 0);
			} while ((nWaitResult < 0) && (errno == EINTR));

			bool const bTargetReaped = (nWaitResult == nTargetPID) && WIFSIGNALED(nTargetStatus) &&
									   (WTERMSIG(nTargetStatus) == SIGKILL);
			::_exit(bReady && !bHooked && bKilled && bTargetReaped ? EXIT_SUCCESS : EXIT_FAILURE);
		}

		int nScenarioStatus = 0;
		REQUIRE(WaitForChildProcess(nScenarioPID, &nScenarioStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nScenarioStatus));
		CHECK(WEXITSTATUS(nScenarioStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("HardwareHook removes a record after its target thread exits") {
		pid_t const nScenarioPID = ::fork();
		REQUIRE(nScenarioPID >= 0);
		if (nScenarioPID == 0) {
			std::atomic<unsigned int> unTargetThreadID = 0;
			std::atomic<bool> bStopTarget = false;
			std::thread TargetThread([&unTargetThreadID, &bStopTarget]() {
				unTargetThreadID.store(static_cast<unsigned int>(::syscall(SYS_gettid)), std::memory_order_release);
				while (!bStopTarget.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
			});

			if (!WaitForTestCondition([&unTargetThreadID]() {
					return unTargetThreadID.load(std::memory_order_acquire) != 0;
				},
									  kLinuxMemoryHookWaitMilliseconds)) {
				::_exit(EXIT_FAILURE);
			}

			unsigned int const unThreadID = unTargetThreadID.load(std::memory_order_acquire);
			bool const bHooked = Detours::Hook::HookHardware(
				unThreadID,
				Detours::Hook::REGISTER_DR0,
				LinuxHardwareHookForkCallBack,
				const_cast<unsigned int*>(&g_unLinuxHardwareHookForkValue),
				Detours::Hook::TYPE_WRITE,
				sizeof(g_unLinuxHardwareHookForkValue));
			bStopTarget.store(true, std::memory_order_release);
			TargetThread.join();
			if (!bHooked) {
				::_exit(kLinuxHardwareHookUnavailableExitCode);
			}

			bool const bUnHooked = Detours::Hook::UnHookHardware(unThreadID, Detours::Hook::REGISTER_DR0);
			bool const bRecordRemoved = !Detours::Hook::UnHookHardware(unThreadID, Detours::Hook::REGISTER_DR0);
			::_exit(bUnHooked && bRecordRemoved ? EXIT_SUCCESS : EXIT_FAILURE);
		}

		int nScenarioStatus = 0;
		REQUIRE(WaitForChildProcess(nScenarioPID, &nScenarioStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nScenarioStatus));
		if (WEXITSTATUS(nScenarioStatus) == kLinuxHardwareHookUnavailableExitCode) {
			MESSAGE("The host does not permit per-thread hardware breakpoints.");
			return;
		}

		CHECK(WEXITSTATUS(nScenarioStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("MemoryHook callbacks preserve pthread forced unwind and release signal state") {
		for (auto const bPostCallBack : { false, true }) {
			pid_t const nChildPID = ::fork();
			REQUIRE(nChildPID >= 0);
			if (nChildPID == 0) {
				::_exit(RunLinuxMemoryHookForcedUnwindScenario(bPostCallBack)
							? EXIT_SUCCESS
							: kLinuxHookForcedUnwindFailureExitCode);
			}

			int nStatus = 0;
			REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
			REQUIRE(WIFEXITED(nStatus));
			CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
		}
	}

	TEST_CASE("InterruptHook callbacks preserve pthread forced unwind and release dispatch state") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			::_exit(RunLinuxInterruptHookForcedUnwindScenario()
						? EXIT_SUCCESS
						: kLinuxHookForcedUnwindFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("HardwareHook callbacks preserve pthread forced unwind and release dispatch state") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			::_exit(RunLinuxHardwareHookForcedUnwindScenario());
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		if (WEXITSTATUS(nStatus) == kLinuxHardwareHookForcedUnwindUnavailableExitCode) {
			MESSAGE("The host does not permit perf-event hardware breakpoints.");
			return;
		}

		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}


	TEST_CASE("InterruptHook requires an architecture-specific interrupt fixture" * doctest::skip(true)) {
	}
} // TEST_SUITE("Detours::Hook")

TEST_SUITE("Detours::Memory") {
	constexpr std::size_t kProcessScannerChunkSize = 1024 * 1024;

	typedef struct _TEST_PROCESS_SCAN_RESULT {
		_TEST_PROCESS_SCAN_RESULT();

		bool m_bCompleted;
		std::size_t m_unBytesScanned;
		std::size_t m_unReadFailures;
		std::vector<void*> m_vecMatches;
	} TEST_PROCESS_SCAN_RESULT, *PTEST_PROCESS_SCAN_RESULT;

	_TEST_PROCESS_SCAN_RESULT::_TEST_PROCESS_SCAN_RESULT() :
		m_bCompleted(false),
		m_unBytesScanned(0),
		m_unReadFailures(0),
		m_vecMatches()
	{
	}

	typedef struct _TEST_PROCESS_MEMORY_REGION {
		std::uintptr_t m_unBeginAddress;
		std::uintptr_t m_unEndAddress;
		bool m_bReadable;
	} TEST_PROCESS_MEMORY_REGION, *PTEST_PROCESS_MEMORY_REGION;

	static void CollectProcessScannerMatches(unsigned char const* pBuffer, std::size_t unBufferSize, unsigned char const* pData, std::size_t unDataSize, std::uintptr_t unBaseAddress, std::size_t unCandidateCount, std::vector<void*>& vecMatches) {
		if (!pBuffer || !pData || !unDataSize || (unBufferSize < unDataSize)) {
			return;
		}

		std::size_t const unAvailableCandidates = unBufferSize - unDataSize + 1;
		std::size_t const unCandidates = std::min(unCandidateCount, unAvailableCandidates);
		for (std::size_t unIndex = 0; unIndex < unCandidates; ++unIndex) {
			if (std::memcmp(pBuffer + unIndex, pData, unDataSize) == 0) {
				vecMatches.push_back(reinterpret_cast<void*>(unBaseAddress + static_cast<std::uintptr_t>(unIndex)));
			}
		}
	}

	static std::size_t CollectProcessScannerChunk(std::vector<unsigned char>& vecBuffer, std::size_t unCarrySize, std::size_t unBytesRead, unsigned char const* pData, std::size_t unDataSize, std::uintptr_t unReadAddress, std::vector<void*>& vecMatches) {
		if (!unBytesRead) {
			return unCarrySize;
		}

		std::size_t const unBufferSize = unCarrySize + unBytesRead;
		CollectProcessScannerMatches(vecBuffer.data(), unBufferSize, pData, unDataSize, unReadAddress - static_cast<std::uintptr_t>(unCarrySize), unBytesRead, vecMatches);

		std::size_t const unNewCarrySize = std::min(unDataSize - 1, unBufferSize);
		if (unNewCarrySize) {
			std::memmove(vecBuffer.data(), vecBuffer.data() + unBufferSize - unNewCarrySize, unNewCarrySize);
		}

		return unNewCarrySize;
	}

	static bool CollectProcessScannerRegionsInternal(std::vector<TEST_PROCESS_MEMORY_REGION>* pRegions) {
		if (!pRegions) {
			return false;
		}

		pRegions->clear();
		std::ifstream MapsStream("/proc/self/maps");
		if (!MapsStream.is_open()) {
			return false;
		}

		constexpr std::size_t kProtectionBufferSize = 5;
		std::string strLine;
		while (std::getline(MapsStream, strLine)) {
			unsigned long long unBeginAddress = 0;
			unsigned long long unEndAddress = 0;
			char szProtection[kProtectionBufferSize] {};
			if (std::sscanf(strLine.c_str(), "%llx-%llx %4s", &unBeginAddress, &unEndAddress, szProtection) != 3) {
				continue;
			}

			if ((unBeginAddress >= unEndAddress) ||
				(unBeginAddress > static_cast<unsigned long long>(std::numeric_limits<std::uintptr_t>::max())) ||
				(unEndAddress > static_cast<unsigned long long>(std::numeric_limits<std::uintptr_t>::max()))) {
				continue;
			}

			TEST_PROCESS_MEMORY_REGION Region {};
			Region.m_unBeginAddress = static_cast<std::uintptr_t>(unBeginAddress);
			Region.m_unEndAddress = static_cast<std::uintptr_t>(unEndAddress);
			Region.m_bReadable = szProtection[0] == 'r';
			pRegions->emplace_back(Region);
		}

		return !pRegions->empty();
	}

	static bool CollectProcessScannerRegions(std::vector<TEST_PROCESS_MEMORY_REGION>* pRegions) {
		if (!pRegions) {
			return false;
		}

		pRegions->clear();
		try {
			if (CollectProcessScannerRegionsInternal(pRegions)) {
				return true;
			}
		} catch (std::exception const&) {
		}

		pRegions->clear();
		return false;
	}

	class TestProcessScanner {
	public:
		bool Find(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress = nullptr, std::size_t unRangeSize = 0) const {
			if (!pResult) {
				return false;
			}

			*pResult = {};
			try {
				if (FindInternal(pData, unDataSize, pResult, pBeginAddress, unRangeSize)) {
					return true;
				}
			} catch (std::exception const&) {
			}

			*pResult = {};
			return false;
		}

	private:
		bool FindInternal(void const* pData, std::size_t unDataSize, PTEST_PROCESS_SCAN_RESULT pResult, void const* pBeginAddress, std::size_t unRangeSize) const {
			if (!pData || !unDataSize || (unDataSize > (std::numeric_limits<std::size_t>::max() - kProcessScannerChunkSize + 1))) {
				return false;
			}

			std::vector<TEST_PROCESS_MEMORY_REGION> vecRegions;
			if (!CollectProcessScannerRegions(&vecRegions)) {
				return false;
			}

			std::vector<unsigned char> vecData(unDataSize);
			std::memcpy(vecData.data(), pData, unDataSize);
			std::vector<unsigned char> vecBuffer(kProcessScannerChunkSize + unDataSize - 1);
			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize) {
				return false;
			}

			std::uintptr_t const unBeginAddress = pBeginAddress ? reinterpret_cast<std::uintptr_t>(pBeginAddress) : 0;
			std::uintptr_t unEndAddress = std::numeric_limits<std::uintptr_t>::max();
			if (unRangeSize) {
				unEndAddress =
					(static_cast<std::uintptr_t>(unRangeSize) > (std::numeric_limits<std::uintptr_t>::max() - unBeginAddress)) ?
					std::numeric_limits<std::uintptr_t>::max() : unBeginAddress + static_cast<std::uintptr_t>(unRangeSize);
			}

			if (unBeginAddress >= unEndAddress) {
				return false;
			}

			int const nMemoryFile = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
			if (nMemoryFile < 0) {
				return false;
			}

			auto MemoryFileCleanup = MakeScopeExit([nMemoryFile]() {
				::syscall(SYS_close, nMemoryFile);
			});

			std::size_t unCarrySize = 0;
			std::uintptr_t unNextAddress = unBeginAddress;
			for (auto const& Region : vecRegions) {
				if (Region.m_unEndAddress <= unBeginAddress) {
					continue;
				}

				if (Region.m_unBeginAddress >= unEndAddress) {
					break;
				}

				std::uintptr_t const unScanBegin = std::max(unBeginAddress, Region.m_unBeginAddress);
				std::uintptr_t const unScanEnd = std::min(unEndAddress, Region.m_unEndAddress);
				if (!Region.m_bReadable || (unScanBegin >= unScanEnd)) {
					unCarrySize = 0;
					unNextAddress = unScanEnd;
					continue;
				}

				if (unScanBegin != unNextAddress) {
					unCarrySize = 0;
				}

				std::uintptr_t unChunkAddress = unScanBegin;
				while (unChunkAddress < unScanEnd) {
					std::size_t const unReadSize = static_cast<std::size_t>(std::min(static_cast<std::uintptr_t>(kProcessScannerChunkSize), unScanEnd - unChunkAddress));
					if (unChunkAddress > static_cast<std::uintptr_t>(std::numeric_limits<off64_t>::max())) {
						++pResult->m_unReadFailures;
						unCarrySize = 0;
						break;
					}

					ssize_t nBytesRead = 0;
					do {
						nBytesRead = ::pread64(nMemoryFile, vecBuffer.data() + unCarrySize, unReadSize, static_cast<off64_t>(unChunkAddress));
					} while ((nBytesRead < 0) && (errno == EINTR));

					std::size_t const unProgress = (nBytesRead > 0) ? std::min(static_cast<std::size_t>(nBytesRead), unReadSize) : 0;
					pResult->m_unBytesScanned += unProgress;
					if (unProgress) {
						unCarrySize = CollectProcessScannerChunk(vecBuffer, unCarrySize, unProgress, vecData.data(), unDataSize, unChunkAddress, pResult->m_vecMatches);
					}

					if (unProgress != unReadSize) {
						++pResult->m_unReadFailures;
					}

					if (unProgress) {
						unChunkAddress += unProgress;
						unNextAddress = unChunkAddress;
						continue;
					}

					unCarrySize = 0;
					std::uintptr_t const unPageRemainder = static_cast<std::uintptr_t>(unPageSize) - (unChunkAddress % static_cast<std::uintptr_t>(unPageSize));
					unChunkAddress += std::min(unPageRemainder, unScanEnd - unChunkAddress);
					unNextAddress = unChunkAddress;
				}
			}

			pResult->m_bCompleted = true;
			return true;
		}
	};

	static bool CollectNoAccessTestMemoryRanges(std::vector<TestMemoryRange>* pRanges) {
		if (!pRanges) {
			return false;
		}

		pRanges->clear();
		try {
			std::ifstream MapsStream("/proc/self/maps");
			if (!MapsStream.is_open()) {
				return false;
			}

			constexpr std::size_t kProtectionBufferSize = 5;
			std::string strLine;
			while (std::getline(MapsStream, strLine)) {
				unsigned long long unBeginAddress = 0;
				unsigned long long unEndAddress = 0;
				char szProtection[kProtectionBufferSize] {};
				if (std::sscanf(strLine.c_str(), "%llx-%llx %4s", &unBeginAddress, &unEndAddress, szProtection) != 3) {
					continue;
				}

				if ((unBeginAddress >= unEndAddress) ||
					(unBeginAddress > static_cast<unsigned long long>(std::numeric_limits<std::uintptr_t>::max())) ||
					(unEndAddress > static_cast<unsigned long long>(std::numeric_limits<std::uintptr_t>::max()))) {
					continue;
				}

				if ((szProtection[0] == '-') && (szProtection[1] == '-') && (szProtection[2] == '-')) {
					pRanges->push_back({ static_cast<std::uintptr_t>(unBeginAddress), static_cast<std::uintptr_t>(unEndAddress) });
				}
			}
		} catch (std::exception const&) {
			pRanges->clear();
			return false;
		}

		return true;
	}

	static bool ChangeProtectedTestMemoryProtection(void* pAddress, std::size_t unSize, int nProtection) {
		std::size_t const unPageSize = GetTestPageSize();
		std::uintptr_t const unAddress = reinterpret_cast<std::uintptr_t>(pAddress);
		if (!pAddress || !unSize || !unPageSize || (static_cast<std::uintptr_t>(unSize) > (std::numeric_limits<std::uintptr_t>::max() - unAddress))) {
			return false;
		}

		std::uintptr_t const unAlignedAddress = unAddress - (unAddress % static_cast<std::uintptr_t>(unPageSize));
		std::uintptr_t unAlignedEnd = unAddress + static_cast<std::uintptr_t>(unSize);
		std::uintptr_t const unEndRemainder = unAlignedEnd % static_cast<std::uintptr_t>(unPageSize);
		if (unEndRemainder) {
			std::uintptr_t const unEndPadding = static_cast<std::uintptr_t>(unPageSize) - unEndRemainder;
			if (unEndPadding > (std::numeric_limits<std::uintptr_t>::max() - unAlignedEnd)) {
				return false;
			}

			unAlignedEnd += unEndPadding;
		}

		return ::mprotect(reinterpret_cast<void*>(unAlignedAddress), static_cast<std::size_t>(unAlignedEnd - unAlignedAddress), nProtection) == 0;
	}

	static bool CopyProtectedTestMemory(void* pAddress, std::size_t unSize, std::vector<unsigned char>* pData) {
		if (!pAddress || !unSize || !pData || !ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_READ)) {
			return false;
		}

		auto ProtectionCleanup = MakeScopeExit([pAddress, unSize]() {
			ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
		});

		pData->resize(unSize);
		std::memcpy(pData->data(), pAddress, unSize);
		bool const bRestored = ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
		if (bRestored) {
			ProtectionCleanup.Release();
		}

		return bRestored;
	}

	static bool TamperProtectedTestMemory(void* pAddress, std::size_t unSize) {
		if (!pAddress || !unSize || !ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_READ | PROT_WRITE)) {
			return false;
		}

		auto ProtectionCleanup = MakeScopeExit([pAddress, unSize]() {
			ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
		});

		unsigned char* const pData = static_cast<unsigned char*>(pAddress);
		pData[unSize - 1] = static_cast<unsigned char>(pData[unSize - 1] ^ 1);
		bool const bRestored = ChangeProtectedTestMemoryProtection(pAddress, unSize, PROT_NONE);
		if (bRestored) {
			ProtectionCleanup.Release();
		}

		return bRestored;
	}

	TEST_CASE("Shared memory remains visible across fork") {
		constexpr unsigned int kChildValue = 0xBEEFDEED;
		Detours::Memory::Shared Shared(sizeof(unsigned int));
		unsigned int* const pValue = static_cast<unsigned int*>(Shared.GetAddress());
		REQUIRE(pValue != nullptr);
		*pValue = 0;

		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			*pValue = kChildValue;
			::_exit(EXIT_SUCCESS);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		REQUIRE(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
		CHECK(*pValue == kChildValue);
	}

	TEST_CASE("Invalid memory wrappers reject protection operations") {
		int nProtection = PROT_NONE;
		Detours::Memory::Page InvalidPage(nullptr, false, false);
		CHECK(InvalidPage.GetPageAddress() == nullptr);
		CHECK(InvalidPage.GetOriginalProtection(&nProtection) == false);
		CHECK(InvalidPage.RestoreProtection() == false);

		Detours::Memory::Region InvalidRegion(nullptr, false);
		CHECK(InvalidRegion.GetRegionAddress() == nullptr);
		CHECK(InvalidRegion.GetOriginalProtection(&nProtection) == false);
		CHECK(InvalidRegion.ChangeProtection(PROT_READ) == false);
		CHECK(InvalidRegion.RestoreProtection() == false);

		Detours::Memory::Protection EmptyProtection(nullptr, 0, false);
		CHECK(EmptyProtection.Change(PROT_READ) == false);
		CHECK(EmptyProtection.Restore() == false);

		Detours::Memory::MemoryManager Manager;
		CHECK(Manager.GetPage(nullptr) == nullptr);
		CHECK(Manager.GetRegion(nullptr) == nullptr);

		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pUnmappedAddress = ::mmap(nullptr, unPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pUnmappedAddress != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pUnmappedAddress, unPageSize]() {
			::munmap(pUnmappedAddress, unPageSize);
		});
		bool const bUnmapped = ::munmap(pUnmappedAddress, unPageSize) == 0;
		if (bUnmapped) {
			MappingCleanup.Release();
		}

		REQUIRE(bUnmapped == true);
		CHECK(Manager.GetPage(pUnmappedAddress) == nullptr);
		CHECK(Manager.GetRegion(pUnmappedAddress) == nullptr);
	}

	TEST_CASE("Protected and Secure ranges roll back partially mapped external memory") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		void* const pMapping = ::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});
		Detours::Memory::Protection PartialProtection(pMapping, unPageSize * 2, false);
		REQUIRE(PartialProtection.Change(PROT_READ) == true);
		REQUIRE(::munmap(static_cast<unsigned char*>(pMapping) + unPageSize, unPageSize) == 0);
		CHECK(PartialProtection.Change(PROT_EXEC) == false);

		int nProtection = PROT_NONE;
		Detours::Memory::Page ProtectionProbe(pMapping, false, false);
		REQUIRE(ProtectionProbe.GetPageAddress() == pMapping);
		REQUIRE(ProtectionProbe.GetProtection(&nProtection) == true);
		REQUIRE(nProtection == PROT_READ);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		{
			Detours::Memory::ProtectedRange ProtectedRange(pMapping, unPageSize * 2);
			CHECK(ProtectedRange.GetRangeAddress() == nullptr);
			CHECK(ProtectedRange.GetRangeSize() == 0);
			CHECK(ProtectedRange.IsProtected() == false);

			Detours::Memory::SecureRange SecureRange(pMapping, unPageSize * 2);
			CHECK(SecureRange.GetRangeAddress() == nullptr);
			CHECK(SecureRange.GetRangeSize() == 0);
			CHECK(SecureRange.IsSecured() == false);
		}

		std::vector<TestMemoryRange> vecAfter;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfter) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(vecBefore, vecAfter, nullptr, 0, unPageSize, &vecNewPages) == true);
		CHECK(vecNewPages.empty());

		nProtection = PROT_NONE;
		REQUIRE(ProtectionProbe.GetProtection(&nProtection) == true);
		CHECK(nProtection == PROT_READ);
	}





	TEST_CASE("MemoryManager normalizes an interior page address") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		void* const pMapping = ::mmap(nullptr, unPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize * 2);
		});

		void* const pInteriorAddress = static_cast<unsigned char*>(pMapping) + unPageSize + 17;
		Detours::Memory::MemoryManager Manager;
		std::unique_ptr<Detours::Memory::Page> pPage = Manager.GetPage(pInteriorAddress);
		REQUIRE(pPage != nullptr);
		CHECK(pPage->GetPageAddress() == (static_cast<unsigned char*>(pMapping) + unPageSize));
		std::unique_ptr<Detours::Memory::Region> pRegion = Manager.GetRegion(pInteriorAddress);
		REQUIRE(pRegion != nullptr);
		CHECK(pRegion->GetRegionAddress() == pMapping);
	}

	TEST_CASE("MemoryHook reports read, write and post operations") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});

		volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
		*pValue = 5;
		ResetLinuxMemoryHookCounters();
		REQUIRE(Detours::Hook::HookMemory(LinuxMemoryHookCallBack, pMapping, sizeof(*pValue), LinuxPostMemoryHookCallBack) == true);
		auto HookCleanup = MakeScopeExit([pMapping]() {
			Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pMapping);
		});

		unsigned int const unReadValue = *pValue;
		CHECK(unReadValue == 5);
		*pValue = 9;
		CHECK(*pValue == 9);

		bool const bUnHooked = Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pMapping);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}

		unsigned int const unReadCalls = g_unLinuxMemoryReadCalls.load(std::memory_order_relaxed);
		unsigned int const unWriteCalls = g_unLinuxMemoryWriteCalls.load(std::memory_order_relaxed);
		unsigned int const unExecuteCalls = g_unLinuxMemoryExecuteCalls.load(std::memory_order_relaxed);
		unsigned int const unPostCalls = g_unLinuxMemoryPostCalls.load(std::memory_order_relaxed);
		CHECK(unReadCalls >= 2);
		CHECK(unWriteCalls >= 1);
		CHECK(unExecuteCalls == 0);
		CHECK(unPostCalls == (unReadCalls + unWriteCalls));
		CHECK(g_unLinuxMemoryInvalidCalls.load(std::memory_order_relaxed) == 0);
	}

	TEST_CASE("MemoryHook synchronous fault in pre callback fails closed") {
		constexpr char kTestCase[] =
			"MemoryHook synchronous fault in pre callback fails closed";
		if (!IsLinuxIsolatedTestProcess(kTestCase)) {
			REQUIRE(RunLinuxIsolatedTest(kTestCase) == true);
			return;
		}

		CHECK(RunLinuxMemoryHookCallBackSynchronousFaultChild(false) == true);
	}

	TEST_CASE("MemoryHook synchronous fault in completing post callback fails closed") {
		constexpr char kTestCase[] =
			"MemoryHook synchronous fault in completing post callback fails closed";
		if (!IsLinuxIsolatedTestProcess(kTestCase)) {
			REQUIRE(RunLinuxIsolatedTest(kTestCase) == true);
			return;
		}

		CHECK(RunLinuxMemoryHookCallBackSynchronousFaultChild(true) == true);
	}




	TEST_CASE("MemoryHook completes every record touched by one instruction") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
#if defined(DETOURS_ARCH_X64)
			using LinuxCrossPageValue = std::uint64_t;
#elif defined(DETOURS_ARCH_X86)
			using LinuxCrossPageValue = std::uint32_t;
#endif
			constexpr LinuxCrossPageValue kInitialValue = static_cast<LinuxCrossPageValue>(0x1020304050607080);
			constexpr LinuxCrossPageValue kAddend = 7;
			constexpr LinuxCrossPageValue kProbeValue = static_cast<LinuxCrossPageValue>(0x8877665544332211);

			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize || (unPageSize > (std::numeric_limits<std::size_t>::max() / 2))) {
				::_exit(kLinuxMultiRecordMemoryHookFailureExitCode);
			}

			void* const pMapping = ::mmap(
				nullptr,
				unPageSize * 2,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1,
				0);
			if (pMapping == MAP_FAILED) {
				::_exit(kLinuxMultiRecordMemoryHookFailureExitCode);
			}

			void* const pSecondPage = static_cast<unsigned char*>(pMapping) + unPageSize;
			void* const pValueAddress = static_cast<unsigned char*>(pSecondPage) - (sizeof(LinuxCrossPageValue) / 2);
			std::memcpy(pValueAddress, &kInitialValue, sizeof(kInitialValue));
			g_pLinuxMultiRecordFirstPage = pMapping;
			g_pLinuxMultiRecordSecondPage = pSecondPage;
			g_unLinuxMultiRecordFirstPreCalls.store(0, std::memory_order_relaxed);
			g_unLinuxMultiRecordSecondPreCalls.store(0, std::memory_order_relaxed);
			g_unLinuxMultiRecordFirstPostCalls.store(0, std::memory_order_relaxed);
			g_unLinuxMultiRecordSecondPostCalls.store(0, std::memory_order_relaxed);
			g_unLinuxMultiRecordInvalidCalls.store(0, std::memory_order_relaxed);

			bool const bFirstHooked = Detours::Hook::HookMemory(
				LinuxMultiRecordMemoryHookCallBack,
				pMapping,
				unPageSize,
				LinuxMultiRecordPostMemoryHookCallBack);
			bool const bSecondHooked = bFirstHooked && Detours::Hook::HookMemory(
														   LinuxMultiRecordMemoryHookCallBack,
														   pSecondPage,
														   unPageSize,
														   LinuxMultiRecordPostMemoryHookCallBack);
			if (!bSecondHooked) {
				if (bFirstHooked) {
					Detours::Hook::UnHookMemory(LinuxMultiRecordMemoryHookCallBack, pMapping);
				}

				::munmap(pMapping, unPageSize * 2);
				::_exit(kLinuxMultiRecordMemoryHookFailureExitCode);
			}

			LinuxCrossPageValue const unOriginalValue = LinuxCrossPageExchangeAdd(pValueAddress, kAddend);
			bool const bFirstUnHooked = Detours::Hook::UnHookMemory(LinuxMultiRecordMemoryHookCallBack, pMapping);
			bool const bSecondUnHooked = Detours::Hook::UnHookMemory(LinuxMultiRecordMemoryHookCallBack, pSecondPage);

			LinuxCrossPageValue unUpdatedValue = 0;
			std::memcpy(&unUpdatedValue, pValueAddress, sizeof(unUpdatedValue));
			std::memcpy(pValueAddress, &kProbeValue, sizeof(kProbeValue));
			LinuxCrossPageValue unReadBackValue = 0;
			std::memcpy(&unReadBackValue, pValueAddress, sizeof(unReadBackValue));

			bool const bSucceeded =
				bFirstUnHooked && bSecondUnHooked &&
				(unOriginalValue == kInitialValue) &&
				(unUpdatedValue == static_cast<LinuxCrossPageValue>(kInitialValue + kAddend)) &&
				(unReadBackValue == kProbeValue) &&
				(g_unLinuxMultiRecordFirstPreCalls.load(std::memory_order_relaxed) == 1) &&
				(g_unLinuxMultiRecordSecondPreCalls.load(std::memory_order_relaxed) == 1) &&
				(g_unLinuxMultiRecordFirstPostCalls.load(std::memory_order_relaxed) == 1) &&
				(g_unLinuxMultiRecordSecondPostCalls.load(std::memory_order_relaxed) == 1) &&
				(g_unLinuxMultiRecordInvalidCalls.load(std::memory_order_relaxed) == 0);
			bool const bUnmapped = ::munmap(pMapping, unPageSize * 2) == 0;
			::_exit((bSucceeded && bUnmapped) ? EXIT_SUCCESS : kLinuxMultiRecordMemoryHookFailureExitCode);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}


	TEST_CASE("MemoryHook cleanup retires missing and replaced mappings") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			void* const pAddress = ::mmap(
				nullptr,
				unPageSize,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1,
				0);
			if (pAddress == MAP_FAILED) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			if (!Detours::Hook::HookMemory(LinuxMemoryHookCallBack, pAddress, unPageSize) ||
				(::munmap(pAddress, unPageSize) != 0) ||
				!Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pAddress)) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			void* const pRemappedAddress = ::mmap(
				pAddress,
				unPageSize,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				-1,
				0);
			if ((pRemappedAddress != pAddress) ||
				!Detours::Hook::HookMemory(LinuxMemoryHookCallBack, pAddress, unPageSize) ||
				(::munmap(pAddress, unPageSize) != 0)) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			void* const pReplacementAddress = ::mmap(
				pAddress,
				unPageSize,
				PROT_READ,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				-1,
				0);
			if (pReplacementAddress != pAddress) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			bool const bReplacementReportedRestored = Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pAddress);
			int nReplacementProtection = PROT_NONE;
			Detours::Memory::Page ReplacementPage(pAddress, false, false);
			bool const bReplacementUnchanged = ReplacementPage.GetPageAddress() &&
											   ReplacementPage.GetProtection(&nReplacementProtection) &&
											   (nReplacementProtection == PROT_READ);
			if (bReplacementReportedRestored || !bReplacementUnchanged ||
				(::mprotect(pAddress, unPageSize, PROT_READ | PROT_WRITE) != 0) ||
				!Detours::Hook::HookMemory(LinuxMemoryHookCallBack, pAddress, unPageSize) ||
				!Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pAddress) ||
				(::munmap(pAddress, unPageSize) != 0)) {
				::_exit(kLinuxUnmappedMemoryHookFailureExitCode);
			}

			::_exit(EXIT_SUCCESS);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}



	TEST_CASE("MemoryHook fork from pre and post callbacks preserves child hook state") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		for (auto const bPostCallBack : { false, true }) {
			pid_t const nTestProcessID = ::fork();
			REQUIRE(nTestProcessID >= 0);
			if (nTestProcessID == 0) {
				std::size_t const unPageSize = GetTestPageSize();
				if (!unPageSize) {
					::_exit(kLinuxMemoryHookForkFailureExitCode);
				}

				void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				if (pMapping == MAP_FAILED) {
					::_exit(kLinuxMemoryHookForkFailureExitCode);
				}

				volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
				*pValue = bPostCallBack ? 19 : 17;
				g_nLinuxMemoryHookForkChildPID.store(0, std::memory_order_relaxed);
				g_bLinuxMemoryHookForkFromPostCallBack.store(bPostCallBack, std::memory_order_relaxed);
				g_bLinuxMemoryHookForkAttempted = 0;
				g_bLinuxMemoryHookForkChild = 0;
				if (!Detours::Hook::HookMemory(
						LinuxMemoryHookForkCallBack,
						pMapping,
						sizeof(*pValue),
						LinuxMemoryHookForkPostCallBack)) {
					::munmap(pMapping, unPageSize);
					::_exit(kLinuxMemoryHookForkFailureExitCode);
				}

				unsigned int const unValue = *pValue;
				if (g_bLinuxMemoryHookForkChild) {
					bool const bFirstUnHooked = Detours::Hook::UnHookMemory(LinuxMemoryHookForkCallBack, pMapping);
					bool const bReHooked = bFirstUnHooked && Detours::Hook::HookMemory(
																 LinuxMemoryHookForkCallBack,
																 pMapping,
																 sizeof(*pValue),
																 LinuxMemoryHookForkPostCallBack);
					unsigned int const unSecondValue = bReHooked ? *pValue : 0;
					bool const bSecondUnHooked = bReHooked && Detours::Hook::UnHookMemory(LinuxMemoryHookForkCallBack, pMapping);
					bool const bRegistrySucceeded = bSecondUnHooked && VerifyLinuxProtectedRegistryConcurrency();
					bool const bSuccess = (unValue == *pValue) && (unSecondValue == unValue) && bRegistrySucceeded;
					::munmap(pMapping, unPageSize);
					::_exit(bSuccess ? 0 : kLinuxMemoryHookForkFailureExitCode);
				}

				pid_t const nHookChildPID = static_cast<pid_t>(g_nLinuxMemoryHookForkChildPID.load(std::memory_order_acquire));
				int nHookChildStatus = 0;
				bool const bChildCompleted = WaitForChildProcess(nHookChildPID, &nHookChildStatus, kLinuxChildWaitMilliseconds);
				bool const bUnHooked = Detours::Hook::UnHookMemory(LinuxMemoryHookForkCallBack, pMapping);
				bool const bSuccess = (unValue == *pValue) && bChildCompleted && WIFEXITED(nHookChildStatus) &&
									  (WEXITSTATUS(nHookChildStatus) == 0) && bUnHooked;
				::munmap(pMapping, unPageSize);
				::_exit(bSuccess ? 0 : kLinuxMemoryHookForkFailureExitCode);
			}

			int nTestStatus = 0;
			REQUIRE(WaitForChildProcess(nTestProcessID, &nTestStatus, kLinuxChildWaitMilliseconds * 2) == true);
			REQUIRE(WIFEXITED(nTestStatus));
			CHECK(WEXITSTATUS(nTestStatus) == 0);
		}
	}

	TEST_CASE("fork quiescence lets a memory callback finish Protected lifecycle") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pMapping = ::mmap(
			nullptr,
			unPageSize,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1,
			0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});

		volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
		*pValue = 29;
		g_bLinuxMemoryHookProtectedLifecycleEntered.store(false, std::memory_order_relaxed);
		g_bLinuxMemoryHookProtectedLifecycleMayContinue.store(false, std::memory_order_relaxed);
		g_bLinuxMemoryHookProtectedLifecycleSucceeded.store(false, std::memory_order_relaxed);
		REQUIRE(Detours::Hook::HookMemory(LinuxMemoryHookProtectedLifecycleCallBack, pMapping, sizeof(*pValue)) == true);
		auto HookCleanup = MakeScopeExit([pMapping]() {
			Detours::Hook::UnHookMemory(LinuxMemoryHookProtectedLifecycleCallBack, pMapping);
		});

		std::atomic<bool> bForkStarted = false;
		unsigned int unReadValue = 0;
		std::thread AccessThread([pValue, &unReadValue]() {
			unReadValue = *pValue;
		});
		std::thread ReleaseThread([&bForkStarted]() {
			while (!bForkStarted.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxProtectedForkReleaseMilliseconds));
			g_bLinuxMemoryHookProtectedLifecycleMayContinue.store(true, std::memory_order_release);
		});
		auto ThreadsCleanup = MakeScopeExit([&AccessThread, &ReleaseThread]() {
			g_bLinuxMemoryHookProtectedLifecycleMayContinue.store(true, std::memory_order_release);
			if (ReleaseThread.joinable()) {
				ReleaseThread.join();
			}

			if (AccessThread.joinable()) {
				AccessThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([]() {
			return g_bLinuxMemoryHookProtectedLifecycleEntered.load(std::memory_order_acquire);
		},
									 kLinuxMemoryHookWaitMilliseconds));
		bForkStarted.store(true, std::memory_order_release);
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			::_exit(g_bLinuxMemoryHookProtectedLifecycleSucceeded.load(std::memory_order_acquire) ? EXIT_SUCCESS : kLinuxProtectedForkFailureExitCode);
		}

		AccessThread.join();
		ReleaseThread.join();
		ThreadsCleanup.Release();
		CHECK(unReadValue == 29);
		CHECK(g_bLinuxMemoryHookProtectedLifecycleSucceeded.load(std::memory_order_acquire) == true);

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
		REQUIRE(Detours::Hook::UnHookMemory(LinuxMemoryHookProtectedLifecycleCallBack, pMapping) == true);
		HookCleanup.Release();
	}

	TEST_CASE("MemoryHook concurrent unhook waits for signal quiescence") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});

		volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
		*pValue = 0;
		ResetLinuxMemoryHookCounters();
		REQUIRE(Detours::Hook::HookMemory(LinuxMemoryHookCallBack, pMapping, sizeof(*pValue), LinuxPostMemoryHookCallBack) == true);
		auto HookCleanup = MakeScopeExit([pMapping]() {
			Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pMapping);
		});

		std::atomic<bool> bStop = false;
		std::thread AccessThread([pValue, &bStop]() {
			while (!bStop.load(std::memory_order_acquire)) {
				*pValue = *pValue + 1;
			}
		});
		auto ThreadCleanup = MakeScopeExit([&AccessThread, &bStop]() {
			bStop.store(true, std::memory_order_release);
			if (AccessThread.joinable()) {
				AccessThread.join();
			}
		});

		CHECK(WaitForLinuxMemoryHookCalls(kLinuxMemoryHookMinimumCalls, kLinuxMemoryHookWaitMilliseconds) == true);
		bool const bUnHooked = Detours::Hook::UnHookMemory(LinuxMemoryHookCallBack, pMapping);
		CHECK(bUnHooked == true);
		if (bUnHooked) {
			HookCleanup.Release();
		}

		unsigned int const unCallsAfterUnHook = g_unLinuxMemoryReadCalls.load(std::memory_order_relaxed) + g_unLinuxMemoryWriteCalls.load(std::memory_order_relaxed);
		bStop.store(true, std::memory_order_release);
		AccessThread.join();
		ThreadCleanup.Release();
		CHECK((g_unLinuxMemoryReadCalls.load(std::memory_order_relaxed) + g_unLinuxMemoryWriteCalls.load(std::memory_order_relaxed)) == unCallsAfterUnHook);
		CHECK(g_unLinuxMemoryPostCalls.load(std::memory_order_relaxed) == unCallsAfterUnHook);
		CHECK(g_unLinuxMemoryInvalidCalls.load(std::memory_order_relaxed) == 0);
	}


	TEST_CASE("MemoryHook self-unhook completes the current event and suppresses future events") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			g_nLinuxSelfUnHookPreCalls = 0;
			g_nLinuxSelfUnHookPostCalls = 0;
			g_nLinuxSelfUnHookResult = 0;
			g_nLinuxSelfUnHookEventCount = 0;
			for (std::size_t unIndex = 0; unIndex < (sizeof(g_arrLinuxSelfUnHookEvents) / sizeof(g_arrLinuxSelfUnHookEvents[0])); ++unIndex) {
				g_arrLinuxSelfUnHookEvents[unIndex] = 0;
			}

			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize) {
				::_exit(90);
			}

			void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (pMapping == MAP_FAILED) {
				::_exit(91);
			}

			volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(pMapping);
			*pValue = 7;
			if (!Detours::Hook::HookMemory(LinuxSelfUnHookMemoryCallBack, pMapping, sizeof(*pValue), LinuxSelfUnHookPostMemoryCallBack)) {
				::_exit(92);
			}

			unsigned int const unFirstValue = *pValue;
			std::sig_atomic_t const nFirstPreCalls = g_nLinuxSelfUnHookPreCalls;
			std::sig_atomic_t const nFirstPostCalls = g_nLinuxSelfUnHookPostCalls;
			unsigned int const unSecondValue = *pValue;
			bool const bValid = (unFirstValue == 7) && (unSecondValue == 7) &&
								(g_nLinuxSelfUnHookResult == 1) &&
								(nFirstPreCalls == 1) && (nFirstPostCalls == 1) &&
								(g_nLinuxSelfUnHookPreCalls == nFirstPreCalls) &&
								(g_nLinuxSelfUnHookPostCalls == nFirstPostCalls) &&
								(g_nLinuxSelfUnHookEventCount == 3) &&
								(g_arrLinuxSelfUnHookEvents[0] == LinuxSelfUnHookPreBegin) &&
								(g_arrLinuxSelfUnHookEvents[1] == LinuxSelfUnHookPreReturned) &&
								(g_arrLinuxSelfUnHookEvents[2] == LinuxSelfUnHookPost);
			::_exit(bValid ? 0 : 93);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
	}

	TEST_CASE("MemoryHook self-unhook releases an owned virtual mapping without another mutation") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			g_nLinuxVirtualSelfUnHookResult = 0;
			std::size_t const unPageSize = GetTestPageSize();
			if (!unPageSize) {
				::_exit(94);
			}

			void* const pReservation = ::mmap(nullptr, unPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (pReservation == MAP_FAILED) {
				::_exit(95);
			}

			if (::munmap(pReservation, unPageSize) != 0) {
				::_exit(96);
			}

			if (!Detours::Hook::HookMemory(LinuxVirtualSelfUnHookMemoryCallBack, pReservation, sizeof(unsigned int), nullptr, true)) {
				::_exit(97);
			}

			TriggerLinuxVirtualMemoryRead(pReservation);

			bool bMappingReleased = false;
			auto const EndTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(kLinuxMemoryHookWaitMilliseconds);
			while (std::chrono::steady_clock::now() < EndTime) {
				unsigned char unResidency = 0;
				errno = 0;
				if ((::mincore(pReservation, unPageSize, &unResidency) != 0) && (errno == ENOMEM)) {
					bMappingReleased = true;
					break;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}

			::_exit((g_nLinuxVirtualSelfUnHookResult == 1) && bMappingReleased ? 0 : 98);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == 0);
	}

	TEST_CASE("Page, Region and Storage") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Page Page;
		REQUIRE(Page.GetPageAddress() != nullptr);
		CHECK(Page.GetPageCapacity() == unPageSize);
		CHECK(Page.GetProtection(nullptr) == false);
		CHECK(Page.GetOriginalProtection(nullptr) == false);
		CHECK(Page.Alloc(std::numeric_limits<std::size_t>::max(), 2) == nullptr);
		CHECK(Page.Alloc(1, 0, 1) == nullptr);
		volatile std::uint64_t* const pPageValue = static_cast<volatile std::uint64_t*>(Page.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pPageValue) != nullptr);
		CHECK(*pPageValue == 0);
		*pPageValue = 11;
		CHECK(*pPageValue == 11);
		CHECK(Page.DeAlloc(const_cast<std::uint64_t*>(pPageValue)) == true);
		CHECK(Page.IsPageEmpty() == true);

		std::size_t const unRegionCapacity = unPageSize * 2;
		Detours::Memory::Region Region(nullptr, unRegionCapacity);
		void* const pRegionAddress = Region.GetRegionAddress();
		REQUIRE(pRegionAddress != nullptr);
		CHECK(Region.GetProtection(nullptr) == false);
		CHECK(Region.GetOriginalProtection(nullptr) == false);
		CHECK((reinterpret_cast<std::uintptr_t>(pRegionAddress) % unPageSize) == 0);
		CHECK(Region.GetRegionCapacity() == unRegionCapacity);
		CHECK(Region.Alloc(std::numeric_limits<std::size_t>::max(), 2) == nullptr);
		CHECK(Region.Alloc(1, 0, 1) == nullptr);
		volatile std::uint64_t* const pRegionValue = static_cast<volatile std::uint64_t*>(Region.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pRegionValue) != nullptr);
		std::uintptr_t const unRegionBegin = reinterpret_cast<std::uintptr_t>(pRegionAddress);
		std::uintptr_t const unRegionEnd = unRegionBegin + static_cast<std::uintptr_t>(unRegionCapacity);
		std::uintptr_t const unRegionValueAddress = reinterpret_cast<std::uintptr_t>(pRegionValue);
		CHECK(unRegionValueAddress >= unRegionBegin);
		CHECK(unRegionValueAddress <= (unRegionEnd - sizeof(std::uint64_t)));
		CHECK(*pRegionValue == 0);
		*pRegionValue = 13;
		CHECK(*pRegionValue == 13);
		CHECK(Region.GetDataSize() == sizeof(std::uint64_t));
		CHECK(Region.DeAlloc(const_cast<std::uint64_t*>(pRegionValue)) == true);

		Detours::Memory::Storage Storage(128, unPageSize);
		volatile std::uint64_t* const pStorageValue = static_cast<volatile std::uint64_t*>(Storage.ZeroAlloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pStorageValue) != nullptr);
		CHECK(*pStorageValue == 0);
		*pStorageValue = 17;
		CHECK(*pStorageValue == 17);
		CHECK(Storage.DeAlloc(const_cast<std::uint64_t*>(pStorageValue)) == true);
		CHECK(Storage.IsStorageEmpty() == true);
		CHECK(Storage.DeAllocAll() == true);
	}

	TEST_CASE("Page and Region allocations stay near the desired address") {
		constexpr std::uintptr_t kMaximumRelativeJumpDistance = 0x7FFFFFFB;
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		Detours::Memory::Page ReferencePage;
		void* const pDesiredAddress = ReferencePage.GetPageAddress();
		REQUIRE(pDesiredAddress != nullptr);

		Detours::Memory::Page NearPage(pDesiredAddress);
		void* const pPageAddress = NearPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		std::uintptr_t const unDesiredAddress = reinterpret_cast<std::uintptr_t>(pDesiredAddress);
		std::uintptr_t const unPageAddress = reinterpret_cast<std::uintptr_t>(pPageAddress);
		CHECK(
			((unPageAddress > unDesiredAddress) ? (unPageAddress - unDesiredAddress) :
			 (unDesiredAddress - unPageAddress)) <= kMaximumRelativeJumpDistance);

		Detours::Memory::Region NearRegion(pDesiredAddress, unPageSize * 2);
		void* const pRegionAddress = NearRegion.GetRegionAddress();
		REQUIRE(pRegionAddress != nullptr);
		std::uintptr_t const unRegionAddress = reinterpret_cast<std::uintptr_t>(pRegionAddress);
		CHECK(
			((unRegionAddress > unDesiredAddress) ? (unRegionAddress - unDesiredAddress) :
			 (unDesiredAddress - unRegionAddress)) <= kMaximumRelativeJumpDistance);
	}

	TEST_CASE("Region spanning deallocation preflights every page") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 2));

		Detours::Memory::Region Region(nullptr, unPageSize * 2);
		void* const pSuccessfulAllocation = Region.Alloc(unPageSize + 1);
		REQUIRE(pSuccessfulAllocation != nullptr);
		CHECK(Region.GetDataSize() == (unPageSize + 1));
		CHECK(Region.DeAlloc(static_cast<unsigned char*>(pSuccessfulAllocation) + unPageSize) == false);
		CHECK(Region.GetDataSize() == (unPageSize + 1));
		CHECK(Region.DeAlloc(pSuccessfulAllocation) == true);
		CHECK(Region.IsRegionEmpty() == true);

		Detours::Memory::Storage Storage(unPageSize * 2, unPageSize * 2);
		void* const pStorageAllocation = Storage.Alloc(unPageSize + 1);
		REQUIRE(pStorageAllocation != nullptr);
		CHECK(Storage.GetDataSize() == (unPageSize + 1));
		CHECK(Storage.DeAlloc(static_cast<unsigned char*>(pStorageAllocation) + unPageSize) == false);
		CHECK(Storage.GetDataSize() == (unPageSize + 1));
		CHECK(Storage.DeAlloc(pStorageAllocation) == true);
		CHECK(Storage.IsStorageEmpty() == true);

		Detours::Memory::Page* pFirstPage = nullptr;
		void* const pAllocation = Region.Alloc(unPageSize + 1, 1, 1, &pFirstPage);
		REQUIRE(pAllocation != nullptr);
		REQUIRE(pFirstPage != nullptr);
		REQUIRE(pFirstPage->DeAlloc(pAllocation) == true);
		REQUIRE(Region.GetDataSize() == 1);
		CHECK(Region.DeAlloc(pAllocation) == false);
		CHECK(Region.GetDataSize() == 1);
		Region.DeAllocAll();
		CHECK(Region.IsRegionEmpty() == true);
	}

	TEST_CASE("Storage validates desired distance and aligned region capacity") {
		constexpr std::uintptr_t kMaximumRelativeJumpDistance = 0x7FFFFFFB;
		constexpr std::uintptr_t kFarDistance = 0x80010000;
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize > 8);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / 4));

		Detours::Memory::Storage Storage(unPageSize * 4, unPageSize);
		Detours::Memory::Region* pFirstRegion = nullptr;
		void* const pFirst = Storage.Alloc(1, 1, 1, nullptr, nullptr, &pFirstRegion);
		REQUIRE(pFirst != nullptr);
		REQUIRE(pFirstRegion != nullptr);
		void* const pDesiredAddress = pFirstRegion->GetRegionAddress();
		REQUIRE(pDesiredAddress != nullptr);

		void* const pAligned = Storage.Alloc(17, 32, 64, pDesiredAddress);
		REQUIRE(pAligned != nullptr);
		std::uintptr_t const unDesiredAddress = reinterpret_cast<std::uintptr_t>(pDesiredAddress);
		std::uintptr_t const unAlignedAddress = reinterpret_cast<std::uintptr_t>(pAligned);
		std::uintptr_t const unAlignedEnd = unAlignedAddress + 31;
		CHECK(
			((unAlignedAddress > unDesiredAddress) ? (unAlignedAddress - unDesiredAddress) :
			 (unDesiredAddress - unAlignedAddress)) <= kMaximumRelativeJumpDistance);
		CHECK(
			((unAlignedEnd > unDesiredAddress) ? (unAlignedEnd - unDesiredAddress) :
			 (unDesiredAddress - unAlignedEnd)) <= kMaximumRelativeJumpDistance);

		std::uintptr_t const unFarAddress =
			(unDesiredAddress <= (std::numeric_limits<std::uintptr_t>::max() - kFarDistance)) ?
			(unDesiredAddress + kFarDistance) : (unDesiredAddress - kFarDistance);
		Detours::Memory::Region* pFarRegion = nullptr;
		void* const pFar = Storage.Alloc(1, 1, 1, reinterpret_cast<void*>(unFarAddress), nullptr, &pFarRegion);
		if (pFar) {
			REQUIRE(pFarRegion != nullptr);
			CHECK(pFarRegion != pFirstRegion);
			std::uintptr_t const unFarAllocationAddress = reinterpret_cast<std::uintptr_t>(pFar);
			CHECK(
				((unFarAllocationAddress > unFarAddress) ? (unFarAllocationAddress - unFarAddress) :
				 (unFarAddress - unFarAllocationAddress)) <= kMaximumRelativeJumpDistance);
		}

		CHECK(Storage.DeAllocAll() == true);

		Detours::Memory::Storage AlignedStorage(unPageSize * 2, unPageSize);
		void* const pLargeAligned = AlignedStorage.Alloc(unPageSize - 6, unPageSize * 2, 1);
		REQUIRE(pLargeAligned != nullptr);
		CHECK(AlignedStorage.GetDataSize() == (unPageSize * 2));
		CHECK(AlignedStorage.DeAlloc(pLargeAligned) == true);
	}

	TEST_CASE("Storage releases empty Linux regions") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage SingleRegionStorage(unPageSize, unPageSize);
		Detours::Memory::Region* pSingleRegion = nullptr;
		void* const pSingleAllocation = SingleRegionStorage.Alloc(1, 1, 1, nullptr, nullptr, &pSingleRegion);
		REQUIRE(pSingleAllocation != nullptr);
		REQUIRE(pSingleRegion != nullptr);
		void* const pSingleRegionAddress = pSingleRegion->GetRegionAddress();
		REQUIRE(pSingleRegionAddress != nullptr);
		REQUIRE(SingleRegionStorage.DeAlloc(pSingleAllocation) == true);
		Detours::Memory::Page SingleRegionProbe(pSingleRegionAddress, false, false);
		CHECK(SingleRegionProbe.GetPageAddress() == nullptr);

		Detours::Memory::Storage MultipleRegionStorage(unPageSize * 2, unPageSize);
		Detours::Memory::Region* pFirstRegion = nullptr;
		Detours::Memory::Region* pSecondRegion = nullptr;
		REQUIRE(MultipleRegionStorage.Alloc(unPageSize, 1, 1, nullptr, nullptr, &pFirstRegion) != nullptr);
		REQUIRE(MultipleRegionStorage.Alloc(unPageSize, 1, 1, nullptr, nullptr, &pSecondRegion) != nullptr);
		REQUIRE(pFirstRegion != nullptr);
		REQUIRE(pSecondRegion != nullptr);
		void* const pFirstRegionAddress = pFirstRegion->GetRegionAddress();
		void* const pSecondRegionAddress = pSecondRegion->GetRegionAddress();
		REQUIRE(pFirstRegionAddress != nullptr);
		REQUIRE(pSecondRegionAddress != nullptr);
		REQUIRE(pFirstRegionAddress != pSecondRegionAddress);
		REQUIRE(MultipleRegionStorage.DeAllocAll() == true);
		Detours::Memory::Page FirstRegionProbe(pFirstRegionAddress, false, false);
		Detours::Memory::Page SecondRegionProbe(pSecondRegionAddress, false, false);
		CHECK(FirstRegionProbe.GetPageAddress() == nullptr);
		CHECK(SecondRegionProbe.GetPageAddress() == nullptr);
	}

	TEST_CASE("Allocators reject non-power-of-two alignment without changing state") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Page Page;
		REQUIRE(Page.GetPageAddress() != nullptr);
		CHECK(Page.Alloc(1, 3, 1) == nullptr);
		CHECK(Page.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(Page.GetDataSize() == 0);
		CHECK(Page.IsPageEmpty() == true);
		void* const pPageAllocation = Page.Alloc(Page.GetPageCapacity(), 1, 1);
		REQUIRE(pPageAllocation != nullptr);
		CHECK(Page.DeAlloc(pPageAllocation) == true);

		Detours::Memory::Region Region(nullptr, unPageSize);
		REQUIRE(Region.GetRegionAddress() != nullptr);
		Detours::Memory::Page* pRegionUsedPage = nullptr;
		CHECK(Region.Alloc(1, 3, 1, &pRegionUsedPage) == nullptr);
		CHECK(pRegionUsedPage == nullptr);
		CHECK(Region.ZeroAlloc(1, 1, 3, &pRegionUsedPage) == nullptr);
		CHECK(pRegionUsedPage == nullptr);
		CHECK(Region.GetDataSize() == 0);
		CHECK(Region.IsRegionEmpty() == true);
		void* const pRegionAllocation = Region.Alloc(Region.GetRegionCapacity(), 1, 1);
		REQUIRE(pRegionAllocation != nullptr);
		CHECK(Region.DeAlloc(pRegionAllocation) == true);

		Detours::Memory::Storage Storage(unPageSize, unPageSize);
		Detours::Memory::Page* pStorageUsedPage = nullptr;
		Detours::Memory::Region* pStorageUsedRegion = nullptr;
		CHECK(Storage.Alloc(1, 3, 1, nullptr, &pStorageUsedPage, &pStorageUsedRegion) == nullptr);
		CHECK(pStorageUsedPage == nullptr);
		CHECK(pStorageUsedRegion == nullptr);
		CHECK(Storage.ZeroAlloc(1, 1, 3, nullptr, &pStorageUsedPage, &pStorageUsedRegion) == nullptr);
		CHECK(pStorageUsedPage == nullptr);
		CHECK(pStorageUsedRegion == nullptr);
		CHECK(Storage.GetDataSize() == 0);
		CHECK(Storage.IsStorageEmpty() == true);
		void* const pStorageAllocation = Storage.Alloc(Storage.GetStorageCapacity(), 1, 1);
		REQUIRE(pStorageAllocation != nullptr);
		CHECK(Storage.DeAlloc(pStorageAllocation) == true);

		Detours::Memory::ProtectedPage ProtectedPage;
		REQUIRE(ProtectedPage.GetPageAddress() != nullptr);
		CHECK(ProtectedPage.Alloc(1, 3, 1) == nullptr);
		CHECK(ProtectedPage.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(ProtectedPage.GetDataSize() == 0);
		CHECK(ProtectedPage.IsPageEmpty() == true);
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);
		void* const pProtectedPageAllocation = ProtectedPage.Alloc(ProtectedPage.GetPageCapacity(), 1, 1);
		REQUIRE(pProtectedPageAllocation != nullptr);
		CHECK(ProtectedPage.DeAlloc(pProtectedPageAllocation) == true);

		Detours::Memory::ProtectedRange ProtectedRange(unPageSize);
		REQUIRE(ProtectedRange.GetRangeAddress() != nullptr);
		CHECK(ProtectedRange.Alloc(1, 3, 1) == nullptr);
		CHECK(ProtectedRange.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(ProtectedRange.GetDataSize() == 0);
		CHECK(ProtectedRange.IsRangeEmpty() == true);
		CHECK(ProtectedRange.IsProtected() == true);
		CHECK(ProtectedRange.IsCompromised() == false);
		void* const pProtectedRangeAllocation = ProtectedRange.Alloc(ProtectedRange.GetRangeSize(), 1, 1);
		REQUIRE(pProtectedRangeAllocation != nullptr);
		CHECK(ProtectedRange.DeAlloc(pProtectedRangeAllocation) == true);

		Detours::Memory::SecurePage SecurePage;
		REQUIRE(SecurePage.GetPageAddress() != nullptr);
		CHECK(SecurePage.Alloc(1, 3, 1) == nullptr);
		CHECK(SecurePage.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(SecurePage.GetDataSize() == 0);
		CHECK(SecurePage.IsPageEmpty() == true);
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);
		void* const pSecurePageAllocation = SecurePage.Alloc(SecurePage.GetPageCapacity(), 1, 1);
		REQUIRE(pSecurePageAllocation != nullptr);
		CHECK(SecurePage.DeAlloc(pSecurePageAllocation) == true);

		Detours::Memory::SecureRange SecureRange(unPageSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		CHECK(SecureRange.Alloc(1, 3, 1) == nullptr);
		CHECK(SecureRange.ZeroAlloc(1, 1, 3) == nullptr);
		CHECK(SecureRange.GetDataSize() == 0);
		CHECK(SecureRange.IsRangeEmpty() == true);
		CHECK(SecureRange.IsSecured() == true);
		CHECK(SecureRange.IsCompromised() == false);
		void* const pSecureRangeAllocation = SecureRange.Alloc(SecureRange.GetRangeSize(), 1, 1);
		REQUIRE(pSecureRangeAllocation != nullptr);
		CHECK(SecureRange.DeAlloc(pSecureRangeAllocation) == true);
	}

	TEST_CASE("Invalid Storage capacities are inert and rejected by MemoryManager") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage InvalidTotalStorage(std::numeric_limits<std::size_t>::max(), unPageSize);
		CHECK(InvalidTotalStorage.GetStorageCapacity() == 0);
		CHECK(InvalidTotalStorage.GetDataSize() == 0);
		CHECK(InvalidTotalStorage.IsStorageEmpty() == true);
		CHECK(InvalidTotalStorage.Alloc(1) == nullptr);
		CHECK(InvalidTotalStorage.ZeroAlloc(1) == nullptr);

		Detours::Memory::Storage InvalidRegionStorage(unPageSize, std::numeric_limits<std::size_t>::max());
		CHECK(InvalidRegionStorage.GetStorageCapacity() == 0);
		CHECK(InvalidRegionStorage.GetDataSize() == 0);
		CHECK(InvalidRegionStorage.IsStorageEmpty() == true);
		CHECK(InvalidRegionStorage.Alloc(1) == nullptr);

		Detours::Memory::Storage InvalidStorage(std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::size_t>::max());
		CHECK(InvalidStorage.GetStorageCapacity() == 0);
		CHECK(InvalidStorage.GetDataSize() == 0);
		CHECK(InvalidStorage.IsStorageEmpty() == true);
		CHECK(InvalidStorage.Alloc(1) == nullptr);

		Detours::Memory::MemoryManager Manager;
		CHECK(Manager.CreateStorage(std::numeric_limits<std::size_t>::max(), unPageSize) == nullptr);
		CHECK(Manager.CreateStorage(unPageSize, std::numeric_limits<std::size_t>::max()) == nullptr);
		CHECK(Manager.CreateStorage(std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::size_t>::max()) == nullptr);
		Detours::Memory::Storage* const pValidStorage = Manager.CreateStorage(unPageSize, unPageSize);
		REQUIRE(pValidStorage != nullptr);
		CHECK(Manager.DestroyStorage(pValidStorage) == true);
	}

	TEST_CASE("External Page and Region preserve mapping ownership") {
		constexpr std::size_t kExternalRegionPageCount = 2;
		constexpr std::size_t kMappingPageCount = 4;
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		REQUIRE(unPageSize <= (std::numeric_limits<std::size_t>::max() / kMappingPageCount));
		std::size_t const unMappingSize = unPageSize * kMappingPageCount;
		std::size_t const unExternalRegionSize = unPageSize * kExternalRegionPageCount;

		void* const pMapping = ::mmap(nullptr, unMappingSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unMappingSize]() {
			::munmap(pMapping, unMappingSize);
		});

		unsigned char* const pExternalMemory = static_cast<unsigned char*>(pMapping) + unPageSize;
		REQUIRE(::mprotect(pExternalMemory, unExternalRegionSize, PROT_READ | PROT_WRITE) == 0);

		{
			Detours::Memory::Page ExternalPage(pExternalMemory, false, false);
			REQUIRE(ExternalPage.GetPageAddress() == pExternalMemory);
			CHECK(ExternalPage.GetPageCapacity() == unPageSize);
			void* const pAllocation = ExternalPage.ZeroAlloc(sizeof(std::uint64_t));
			REQUIRE(pAllocation != nullptr);
			*static_cast<std::uint64_t*>(pAllocation) = 29;
			CHECK(*static_cast<std::uint64_t*>(pAllocation) == 29);
			CHECK(ExternalPage.DeAlloc(pAllocation) == true);
		}

		unsigned char arrResidency[kExternalRegionPageCount] {};
		REQUIRE(::mincore(pExternalMemory, unPageSize, arrResidency) == 0);
		pExternalMemory[0] = 0x5A;
		CHECK(pExternalMemory[0] == 0x5A);

		{
			Detours::Memory::Region ExternalRegion(pExternalMemory, false);
			REQUIRE(ExternalRegion.GetRegionAddress() == pExternalMemory);
			CHECK(ExternalRegion.GetRegionCapacity() == unExternalRegionSize);
			void* const pAllocation = ExternalRegion.ZeroAlloc(sizeof(std::uint64_t));
			REQUIRE(pAllocation != nullptr);
			std::uintptr_t const unAllocationAddress = reinterpret_cast<std::uintptr_t>(pAllocation);
			std::uintptr_t const unRegionBegin = reinterpret_cast<std::uintptr_t>(pExternalMemory);
			CHECK(unAllocationAddress >= unRegionBegin);
			CHECK(unAllocationAddress <= (unRegionBegin + unExternalRegionSize - sizeof(std::uint64_t)));
			*static_cast<std::uint64_t*>(pAllocation) = 31;
			CHECK(*static_cast<std::uint64_t*>(pAllocation) == 31);
			CHECK(ExternalRegion.DeAlloc(pAllocation) == true);
		}

		REQUIRE(::mincore(pExternalMemory, unExternalRegionSize, arrResidency) == 0);
		pExternalMemory[unExternalRegionSize - 1] = 0xA5;
		CHECK(pExternalMemory[unExternalRegionSize - 1] == 0xA5);

		bool const bUnmapped = ::munmap(pMapping, unMappingSize) == 0;
		CHECK(bUnmapped == true);
		if (bUnmapped) {
			MappingCleanup.Release();
		}
	}

	TEST_CASE("Region rejects capacity overflow") {
		Detours::Memory::Region OverflowRegion(nullptr, std::numeric_limits<std::size_t>::max());
		CHECK(OverflowRegion.GetRegionAddress() == nullptr);
		CHECK(OverflowRegion.GetRegionCapacity() == 0);
		CHECK(OverflowRegion.GetDataSize() == 0);
		CHECK(OverflowRegion.IsRegionEmpty() == true);
	}

	TEST_CASE("Storage enforces and reuses total capacity") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);

		Detours::Memory::Storage LimitedStorage(16, unPageSize);
		CHECK(LimitedStorage.GetStorageCapacity() == 16);
		void* const pLimitedAllocation = LimitedStorage.Alloc(16);
		REQUIRE(pLimitedAllocation != nullptr);
		CHECK(LimitedStorage.GetDataSize() == 16);
		CHECK(LimitedStorage.Alloc(1) == nullptr);
		CHECK(LimitedStorage.DeAlloc(pLimitedAllocation) == true);
		CHECK(LimitedStorage.GetStorageCapacity() == 16);

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

		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize > 1);

		void* const pMapping = ::mmap(nullptr, unPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		REQUIRE(pMapping != MAP_FAILED);
		auto MappingCleanup = MakeScopeExit([pMapping, unPageSize]() {
			::munmap(pMapping, unPageSize);
		});

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
		bool const bUnmapped = ::munmap(pMemory, unPageSize) == 0;
		CHECK(bUnmapped == true);
		if (bUnmapped) {
			MappingCleanup.Release();
		}
	}

	TEST_CASE("Failed external SecurePage hook installation preserves memory") {
		Detours::Memory::Page Page;
		unsigned char* const pPageAddress = static_cast<unsigned char*>(Page.GetPageAddress());
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		int nOriginalProtection = PROT_NONE;
		REQUIRE(Page.GetProtection(&nOriginalProtection) == true);
		std::vector<unsigned char> vecExpected(unPageCapacity);
		for (std::size_t unIndex = 0; unIndex < unPageCapacity; ++unIndex) {
			vecExpected[unIndex] = static_cast<unsigned char>((unIndex * 37) ^ 0xA5);
		}

		std::memcpy(pPageAddress, vecExpected.data(), vecExpected.size());

		REQUIRE(Detours::Hook::HookMemory(ProtectedMemoryRollbackHook, pPageAddress, unPageCapacity) == true);
		auto HookCleanup = MakeScopeExit([pPageAddress]() {
			Detours::Hook::UnHookMemory(ProtectedMemoryRollbackHook, pPageAddress);
		});
		{
			Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
			CHECK(SecurePage.GetPageAddress() == nullptr);
			CHECK(SecurePage.GetPageCapacity() == 0);
			CHECK(SecurePage.IsSecured() == false);
		}

		bool const bUnHooked = Detours::Hook::UnHookMemory(ProtectedMemoryRollbackHook, pPageAddress);
		REQUIRE(bUnHooked == true);
		HookCleanup.Release();

		int nRestoredProtection = PROT_NONE;
		REQUIRE(Page.GetProtection(&nRestoredProtection) == true);
		CHECK(nRestoredProtection == nOriginalProtection);
		CHECK(std::memcmp(pPageAddress, vecExpected.data(), vecExpected.size()) == 0);
	}

	TEST_CASE("Protected and Secure ranges reject wrapping external addresses") {
		std::size_t const unPageSize = GetTestPageSize();
		REQUIRE(unPageSize != 0);
		std::uintptr_t const unWrappingAddress =
			std::numeric_limits<std::uintptr_t>::max() -
			(std::numeric_limits<std::uintptr_t>::max() % static_cast<std::uintptr_t>(unPageSize));

		Detours::Memory::ProtectedRange ProtectedRange(reinterpret_cast<void*>(unWrappingAddress), unPageSize);
		CHECK(ProtectedRange.GetRangeAddress() == nullptr);
		CHECK(ProtectedRange.GetRangeSize() == 0);
		CHECK(ProtectedRange.IsProtected() == false);

		Detours::Memory::SecureRange SecureRange(reinterpret_cast<void*>(unWrappingAddress), unPageSize);
		CHECK(SecureRange.GetRangeAddress() == nullptr);
		CHECK(SecureRange.GetRangeSize() == 0);
		CHECK(SecureRange.IsSecured() == false);
	}

	TEST_CASE("ProtectedPage and process scanner") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		CHECK(ProtectedPage.GetPageCapacity() == GetTestPageSize());
		CHECK(ProtectedPage.IsProtected() == true);

		std::uint64_t const unValue = 0x123456789ABCDEF0;
		std::uint64_t unControl = unValue;
		volatile std::uint64_t* const pData = static_cast<volatile std::uint64_t*>(ProtectedPage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pData) != nullptr);
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

	TEST_CASE("SecurePage cannot hide a ProtectedPage compromise") {
		Detours::Memory::Page Page;
		Detours::Memory::ProtectedPage ProtectedPage(Page.GetPageAddress(), Page.GetPageCapacity());
		void* const pData = ProtectedPage.Alloc(sizeof(std::uint64_t));
		REQUIRE(pData != nullptr);
		*static_cast<volatile std::uint64_t*>(pData) = 0x1020304050607080;
		REQUIRE(TamperProtectedTestMemory(Page.GetPageAddress(), Page.GetPageCapacity()) == true);
		REQUIRE(ProtectedPage.IsCompromised() == true);

		Detours::Memory::SecurePage SecurePage(ProtectedPage.GetPageAddress(), ProtectedPage.GetPageCapacity());
		if (SecurePage.GetPageAddress()) {
			CHECK(ProtectedPage.IsCompromised() == true);
			CHECK(SecurePage.IsCompromised() == true);
		} else {
			CHECK(SecurePage.IsSecured() == false);
		}
	}

	TEST_CASE("SecurePage detects ciphertext tampering after metadata protection bypass") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
		REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
		volatile std::uint64_t* const pData = static_cast<volatile std::uint64_t*>(SecurePage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pData) != nullptr);
		*pData = 0x1020304050607080;
		REQUIRE(SecurePage.IsCompromised() == false);

		std::vector<TestMemoryRange> vecAfter;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfter) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(vecBefore, vecAfter, pPageAddress, unPageCapacity, unPageCapacity, &vecNewPages) == true);
		REQUIRE(vecNewPages.size() == 1);
		void* const pMetadataAddress = vecNewPages.front();

		REQUIRE(ChangeProtectedTestMemoryProtection(pPageAddress, unPageCapacity, PROT_READ | PROT_WRITE) == true);
		auto PageProtectionCleanup = MakeScopeExit([pPageAddress, unPageCapacity]() {
			ChangeProtectedTestMemoryProtection(pPageAddress, unPageCapacity, PROT_NONE);
		});
		REQUIRE(ChangeProtectedTestMemoryProtection(pMetadataAddress, unPageCapacity, PROT_READ | PROT_WRITE) == true);
		auto MetadataProtectionCleanup = MakeScopeExit([pMetadataAddress, unPageCapacity]() {
			ChangeProtectedTestMemoryProtection(pMetadataAddress, unPageCapacity, PROT_NONE);
		});

		unsigned char* const pCiphertext = static_cast<unsigned char*>(pPageAddress);
		pCiphertext[0] = static_cast<unsigned char>(pCiphertext[0] ^ 1);
		CHECK(SecurePage.IsCompromised() == true);
		CHECK(SecurePage.IsSecured() == false);

		std::vector<TestMemoryRange> vecRestored;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecRestored) == true);
		bool const bPageHidden = IsTestMemoryAddressNoAccess(vecRestored, pPageAddress);
		bool const bMetadataHidden = IsTestMemoryAddressNoAccess(vecRestored, pMetadataAddress);
		CHECK(bPageHidden == true);
		CHECK(bMetadataHidden == true);
		if (bPageHidden) {
			PageProtectionCleanup.Release();
		}

		if (bMetadataHidden) {
			MetadataProtectionCleanup.Release();
		}
	}

	TEST_CASE("SecurePage teardown completes after ciphertext tampering") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		int nOriginalProtection = PROT_NONE;
		REQUIRE(Page.GetProtection(&nOriginalProtection) == true);

		Detours::Memory::SecurePage SecurePage(pPageAddress, Page.GetPageCapacity());
		void* const pData = SecurePage.Alloc(sizeof(std::uint64_t));
		REQUIRE(pData != nullptr);
		*static_cast<volatile std::uint64_t*>(pData) = 0x1020304050607080;
		REQUIRE(TamperProtectedTestMemory(pPageAddress, Page.GetPageCapacity()) == true);
		CHECK(SecurePage.IsCompromised() == true);
		REQUIRE(SecurePage.Release() == true);
		CHECK(SecurePage.GetPageAddress() == nullptr);

		int nRestoredProtection = PROT_NONE;
		REQUIRE(Page.GetProtection(&nRestoredProtection) == true);
		REQUIRE(nRestoredProtection == nOriginalProtection);
		volatile unsigned int* const pDirectValue = static_cast<volatile unsigned int*>(pPageAddress);
		*pDirectValue = 0x5A5AA5A5;
		CHECK(*pDirectValue == 0x5A5AA5A5);
	}

	TEST_CASE("ProtectedPage externally synchronized access restores protection") {
		Detours::Memory::ProtectedPage ProtectedPage;
		void* const pPageAddress = ProtectedPage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		volatile unsigned int* const pValue =
			static_cast<volatile unsigned int*>(ProtectedPage.ZeroAlloc(sizeof(unsigned int) * kProtectedStressThreadCount));
		REQUIRE(const_cast<unsigned int*>(pValue) != nullptr);

		ProtectedStressResult const Result = RunProtectedMemoryStress(pValue);
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kProtectedStressThreadCount * kProtectedStressIterations));
		CHECK(ProtectedPage.IsProtected() == true);
		CHECK(ProtectedPage.IsCompromised() == false);

		int nProtection = 0;
		Detours::Memory::Page ProtectionProbe(pPageAddress, false, false);
		REQUIRE(ProtectionProbe.GetPageAddress() == pPageAddress);
		REQUIRE(ProtectionProbe.GetProtection(&nProtection) == true);
		CHECK(nProtection == PROT_NONE);
	}

	TEST_CASE("SecurePage externally synchronized access restores protection") {
		Detours::Memory::SecurePage SecurePage;
		void* const pPageAddress = SecurePage.GetPageAddress();
		REQUIRE(pPageAddress != nullptr);
		volatile unsigned int* const pValue = static_cast<volatile unsigned int*>(SecurePage.ZeroAlloc(sizeof(unsigned int) * kProtectedStressThreadCount));
		REQUIRE(const_cast<unsigned int*>(pValue) != nullptr);

		ProtectedStressResult const Result = RunProtectedMemoryStress(pValue);
		CHECK(Result.m_unFailures == 0);
		CHECK(Result.m_unValue == (kProtectedStressThreadCount * kProtectedStressIterations));
		CHECK(SecurePage.IsSecured() == true);
		CHECK(SecurePage.IsCompromised() == false);

		int nProtection = 0;
		Detours::Memory::Page ProtectionProbe(pPageAddress, false, false);
		REQUIRE(ProtectionProbe.GetPageAddress() == pPageAddress);
		REQUIRE(ProtectionProbe.GetProtection(&nProtection) == true);
		CHECK(nProtection == PROT_NONE);
	}



















	TEST_CASE("Protected and Secure layers share one hidden shadow page") {
		{
			Detours::Memory::SecurePage WarmupPage;
			REQUIRE(WarmupPage.GetPageAddress() != nullptr);
			REQUIRE(WarmupPage.Release() == true);
		}

		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity != 0);

		std::vector<TestMemoryRange> vecBefore;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecBefore) == true);
		Detours::Memory::ProtectedPage ProtectedPage(pPageAddress, unPageCapacity);
		REQUIRE(ProtectedPage.GetPageAddress() == pPageAddress);

		std::vector<TestMemoryRange> vecAfterProtected;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterProtected) == true);
		std::vector<void*> vecNewPages;
		REQUIRE(CollectNewNoAccessTestPages(
					vecBefore,
					vecAfterProtected,
					pPageAddress,
					unPageCapacity,
					unPageCapacity,
					&vecNewPages) == true);
		REQUIRE(vecNewPages.size() == 1);
		void* const pShadowAddress = vecNewPages.front();
		CHECK(IsTestMemoryAddressNoAccess(vecAfterProtected, pPageAddress) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterProtected, pShadowAddress) == true);

		Detours::Memory::SecurePage SecurePage(pPageAddress, unPageCapacity);
		REQUIRE(SecurePage.GetPageAddress() == pPageAddress);
		std::vector<TestMemoryRange> vecAfterSecure;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterSecure) == true);
		vecNewPages.clear();
		REQUIRE(CollectNewNoAccessTestPages(
					vecAfterProtected,
					vecAfterSecure,
					pPageAddress,
					unPageCapacity,
					unPageCapacity,
					&vecNewPages) == true);
		CHECK(vecNewPages.empty());
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecure, pShadowAddress) == true);

		REQUIRE(ProtectedPage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		TestMemoryProtection flProtection = kProtectedMemoryInvalidTestProtection;
		REQUIRE(SecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		volatile std::uint64_t* const pValue =
			static_cast<volatile std::uint64_t*>(SecurePage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pValue) != nullptr);
		*pValue = 0x1020304050607080;

		std::vector<unsigned char> vecFirstCiphertext;
		REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecFirstCiphertext) == true);
		REQUIRE(SecurePage.Release() == true);
		std::vector<TestMemoryRange> vecAfterSecureRelease;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterSecureRelease) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecureRelease, pPageAddress) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterSecureRelease, pShadowAddress) == true);

		Detours::Memory::SecurePage ReplacementSecurePage(pPageAddress, unPageCapacity);
		REQUIRE(ReplacementSecurePage.GetPageAddress() == pPageAddress);
		REQUIRE(ReplacementSecurePage.GetProtection(&flProtection) == true);
		CHECK(flProtection == kProtectedMemoryReadWriteTestProtection);
		std::vector<unsigned char> vecSecondCiphertext;
		REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecSecondCiphertext) == true);
		CHECK(vecFirstCiphertext != vecSecondCiphertext);
		REQUIRE(ReplacementSecurePage.Release() == true);
		REQUIRE(ProtectedPage.Release() == true);

		std::vector<TestMemoryRange> vecAfterRelease;
		REQUIRE(CollectNoAccessTestMemoryRanges(&vecAfterRelease) == true);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterRelease, pPageAddress) == false);
		CHECK(IsTestMemoryAddressNoAccess(vecAfterRelease, pShadowAddress) == false);
	}


	TEST_CASE("SecurePage and ProtectedPage composition") {
		Detours::Memory::Page Page;
		void* const pPageAddress = Page.GetPageAddress();
		std::size_t const unPageCapacity = Page.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);

		void* pValueAddress = nullptr;
		std::uint64_t const unValue = 0x0FEDCBA987654321;
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
			unsigned char const* const pValueBytes = reinterpret_cast<unsigned char const*>(&unValue);
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



	TEST_CASE("fork remains live during SecurePage lifecycle churn") {
		std::atomic<bool> bStop = false;
		std::atomic<bool> bSucceeded = true;
		std::atomic<unsigned int> unIterations = 0;
		std::thread LifecycleThread(
			ChurnLinuxProtectedMemoryForFork,
			&bStop,
			&bSucceeded,
			&unIterations);
		auto LifecycleCleanup = MakeScopeExit([&bStop, &LifecycleThread]() {
			bStop.store(true, std::memory_order_release);
			if (LifecycleThread.joinable()) {
				LifecycleThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&unIterations]() {
			return unIterations.load(std::memory_order_acquire) != 0;
		},
									 kLinuxMemoryHookWaitMilliseconds));

		for (std::size_t unIteration = 0; unIteration < kLinuxProtectedForkIterationCount; ++unIteration) {
			pid_t const nChildPID = ::fork();
			REQUIRE(nChildPID >= 0);
			if (nChildPID == 0) {
				Detours::Memory::SecurePage ChildPage;
				bool const bChildSucceeded = ChildPage.GetPageAddress() && ChildPage.Release();
				::_exit(bChildSucceeded ? EXIT_SUCCESS : kLinuxProtectedForkFailureExitCode);
			}

			int nStatus = 0;
			REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
			REQUIRE(WIFEXITED(nStatus));
			CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
		}

		bStop.store(true, std::memory_order_release);
		LifecycleThread.join();
		LifecycleCleanup.Release();
		CHECK(bSucceeded.load(std::memory_order_acquire) == true);
	}

	TEST_CASE("SecurePage rekeys after fork before resealing") {
		Detours::Memory::SecurePage SecurePage;
		void* const pPageAddress = SecurePage.GetPageAddress();
		std::size_t const unPageCapacity = SecurePage.GetPageCapacity();
		REQUIRE(pPageAddress != nullptr);
		REQUIRE(unPageCapacity >= sizeof(std::uint64_t));
		volatile std::uint64_t* const pValue = static_cast<volatile std::uint64_t*>(SecurePage.Alloc(sizeof(std::uint64_t)));
		REQUIRE(const_cast<std::uint64_t*>(pValue) != nullptr);
		*pValue = 0x0102030405060708;
		std::uintptr_t const unValueOffset = reinterpret_cast<std::uintptr_t>(pValue) - reinterpret_cast<std::uintptr_t>(pPageAddress);
		REQUIRE(unValueOffset <= (unPageCapacity - sizeof(std::uint64_t)));

		int nPipeFileDescriptors[kLinuxPipeFileDescriptorCount] = { -1, -1 };
		REQUIRE(::pipe(nPipeFileDescriptors) == 0);
		auto PipeCleanup = MakeScopeExit([&nPipeFileDescriptors]() {
			if (nPipeFileDescriptors[0] >= 0) {
				::close(nPipeFileDescriptors[0]);
			}

			if (nPipeFileDescriptors[1] >= 0) {
				::close(nPipeFileDescriptors[1]);
			}
		});

		constexpr std::uint64_t kParentPlaintext = 0x1122334455667788;
		constexpr std::uint64_t kChildPlaintext = 0x8877665544332211;
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			::close(nPipeFileDescriptors[0]);
			if (!SecurePage.IsSecured()) {
				::_exit(kLinuxSecureForkFailureExitCode);
			}

			*pValue = kChildPlaintext;
			std::vector<unsigned char> vecChildCiphertext;
			if (!CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecChildCiphertext) ||
				!WriteTestFileDescriptor(nPipeFileDescriptors[1], vecChildCiphertext.data() + unValueOffset, sizeof(kChildPlaintext))) {
				::_exit(kLinuxSecureForkFailureExitCode);
			}

			::_exit(EXIT_SUCCESS);
		}

		auto ChildCleanup = MakeScopeExit([nChildPID]() {
			int nStatus = 0;
			pid_t nWaitResult = 0;
			do {
				nWaitResult = ::waitpid(nChildPID, &nStatus, WNOHANG);
			} while ((nWaitResult < 0) && (errno == EINTR));
			if (nWaitResult == 0) {
				::kill(nChildPID, SIGKILL);
				while ((::waitpid(nChildPID, &nStatus, 0) < 0) && (errno == EINTR)) {
				}
			}
		});

		::close(nPipeFileDescriptors[1]);
		nPipeFileDescriptors[1] = -1;
		*pValue = kParentPlaintext;
		std::vector<unsigned char> vecParentCiphertext;
		REQUIRE(CopyProtectedTestMemory(pPageAddress, unPageCapacity, &vecParentCiphertext) == true);

		int nStatus = 0;
		bool const bChildReaped = WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds);
		if (bChildReaped) {
			ChildCleanup.Release();
		}

		REQUIRE(bChildReaped == true);
		REQUIRE(WIFEXITED(nStatus));
		REQUIRE(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
		unsigned char arrChildCiphertext[sizeof(kChildPlaintext)] {};
		REQUIRE(ReadTestFileDescriptor(nPipeFileDescriptors[0], arrChildCiphertext, sizeof(arrChildCiphertext)) == true);

		unsigned char const* const pParentPlaintext = reinterpret_cast<unsigned char const*>(&kParentPlaintext);
		unsigned char const* const pChildPlaintext = reinterpret_cast<unsigned char const*>(&kChildPlaintext);
		bool bReusedKeyStream = true;
		for (std::size_t unIndex = 0; unIndex < sizeof(kParentPlaintext); ++unIndex) {
			unsigned char const unCiphertextDifference =
				static_cast<unsigned char>(vecParentCiphertext[unValueOffset + unIndex] ^ arrChildCiphertext[unIndex]);
			unsigned char const unPlaintextDifference =
				static_cast<unsigned char>(pParentPlaintext[unIndex] ^ pChildPlaintext[unIndex]);
			if (unCiphertextDifference != unPlaintextDifference) {
				bReusedKeyStream = false;
				break;
			}
		}

		CHECK(bReusedKeyStream == false);
	}

	TEST_CASE("fork seals SecurePage during the fault single-step window") {
#if !defined(__x86_64__)
		WARN("The deterministic protected syscall fixture requires Linux x86-64.");
		return;
#else
		Detours::Memory::SecurePage SecurePage;
		volatile unsigned char* const pCode = static_cast<volatile unsigned char*>(SecurePage.Alloc(3));
		REQUIRE(const_cast<unsigned char*>(pCode) != nullptr);
		pCode[0] = kLinuxSystemCallFirstOpcode;
		pCode[1] = kLinuxSystemCallSecondOpcode;
		pCode[2] = kLinuxReturnOpcode;
		REQUIRE(SecurePage.IsSecured() == true);

		int nPipeFileDescriptors[kLinuxPipeFileDescriptorCount] = { -1, -1 };
		REQUIRE(::pipe(nPipeFileDescriptors) == 0);
		auto PipeCleanup = MakeScopeExit([&nPipeFileDescriptors]() {
			if (nPipeFileDescriptors[0] >= 0) {
				::close(nPipeFileDescriptors[0]);
			}

			if (nPipeFileDescriptors[1] >= 0) {
				::close(nPipeFileDescriptors[1]);
			}
		});

		std::atomic<bool> bForkStarted = false;
		unsigned char unReadByte = 0;
		long nReadResult = -1;
		std::thread ReadThread([&]() {
			nReadResult = CallProtectedReadSystemCall(
				const_cast<unsigned char*>(pCode), nPipeFileDescriptors[0], &unReadByte, sizeof(unReadByte));
		});
		std::thread ReleaseThread([&]() {
			while (!bForkStarted.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(kLinuxProtectedForkReleaseMilliseconds));
			unsigned char const unReleaseByte = 0xA5;
			WriteTestFileDescriptor(nPipeFileDescriptors[1], &unReleaseByte, sizeof(unReleaseByte));
		});
		auto ThreadsCleanup = MakeScopeExit([&]() {
			bForkStarted.store(true, std::memory_order_release);
			unsigned char const unReleaseByte = 0;
			WriteTestFileDescriptor(nPipeFileDescriptors[1], &unReleaseByte, sizeof(unReleaseByte));
			if (ReleaseThread.joinable()) {
				ReleaseThread.join();
			}

			if (ReadThread.joinable()) {
				ReadThread.join();
			}
		});

		REQUIRE(WaitForTestCondition([&SecurePage]() {
			return !SecurePage.IsSecured();
		},
									 kLinuxMemoryHookWaitMilliseconds));

		bForkStarted.store(true, std::memory_order_release);
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			if (!SecurePage.IsSecured()) {
				::_exit(kLinuxProtectedForkFailureExitCode);
			}

			unsigned char const unFirstOpcode = pCode[0];
			if ((unFirstOpcode != kLinuxSystemCallFirstOpcode) || !SecurePage.IsSecured()) {
				::_exit(kLinuxProtectedForkFailureExitCode);
			}

			::_exit(EXIT_SUCCESS);
		}

		ReadThread.join();
		ReleaseThread.join();
		ThreadsCleanup.Release();
		CHECK(nReadResult == 1);
		CHECK(unReadByte == 0xA5);
		CHECK(SecurePage.IsSecured() == true);

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
#endif
	}






	TEST_CASE("asynchronous SIGSEGV cannot impersonate a SecurePage fault") {
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			Detours::Exception::ExceptionListener SignalListener;
			if (!SignalListener.AddCallBack(LinuxAsyncFaultSignalCallBack) ||
				!SignalListener.EnableHandler()) {
				::_exit(kLinuxDeferredSignalInformationFailureExitCode);
			}

			Detours::Memory::SecurePage SecurePage;
			void* const pPageAddress = SecurePage.GetPageAddress();
			if (!pPageAddress || !SecurePage.IsSecured()) {
				::_exit(kLinuxDeferredSignalInformationFailureExitCode);
			}

			g_nLinuxAsyncFaultSignalCalls = 0;
			siginfo_t SignalInformation {};
			SignalInformation.si_signo = SIGSEGV;
			SignalInformation.si_code = SI_QUEUE;
			SignalInformation.si_pid = ::getpid();
			SignalInformation.si_uid = ::getuid();
			SignalInformation.si_addr = pPageAddress;
			if ((::syscall(
					 SYS_rt_tgsigqueueinfo,
					 ::getpid(),
					 ::syscall(SYS_gettid),
					 SIGSEGV,
					 &SignalInformation) != 0) ||
				(g_nLinuxAsyncFaultSignalCalls != 1) ||
				!SecurePage.IsSecured() ||
				SecurePage.IsCompromised()) {
				::_exit(kLinuxDeferredSignalInformationFailureExitCode);
			}

			::_exit(EXIT_SUCCESS);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
	}

	TEST_CASE("SecurePage rejects execution of raw rt_sigprocmask") {
#if !defined(__x86_64__)
		MESSAGE("The raw signal-mask syscall fixture requires Linux x86-64.");
		return;
#else
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			RunLinuxProtectedUnsafeInstructionScenario(LinuxProtectedUnsafeInstructionFixture::SIGNAL_MASK_SYSTEM_CALL);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
#endif
	}

	TEST_CASE("SecurePage rejects execution of raw fork") {
#if !defined(__x86_64__)
		MESSAGE("The raw fork syscall fixture requires Linux x86-64.");
		return;
#else
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			RunLinuxProtectedUnsafeInstructionScenario(LinuxProtectedUnsafeInstructionFixture::FORK_SYSTEM_CALL);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
#endif
	}

	TEST_CASE("SecurePage rejects execution of MOV SS") {
#if !defined(__x86_64__)
		MESSAGE("The MOV SS fixture requires Linux x86-64.");
		return;
#else
		pid_t const nChildPID = ::fork();
		REQUIRE(nChildPID >= 0);
		if (nChildPID == 0) {
			RunLinuxProtectedUnsafeInstructionScenario(LinuxProtectedUnsafeInstructionFixture::MOVE_STACK_SEGMENT);
		}

		int nStatus = 0;
		REQUIRE(WaitForChildProcess(nChildPID, &nStatus, kLinuxChildWaitMilliseconds) == true);
		REQUIRE(WIFEXITED(nStatus));
		CHECK(WEXITSTATUS(nStatus) == EXIT_SUCCESS);
#endif
	}

	TEST_CASE("SecureRange and ProtectedRange composition") {
		std::size_t const unRangeSize = GetTestPageSize() + 37;
		REQUIRE(unRangeSize > 37);

		Detours::Memory::SecureRange SecureRange(unRangeSize);
		REQUIRE(SecureRange.GetRangeAddress() != nullptr);
		Detours::Memory::ProtectedRange ProtectedRange(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize());
		REQUIRE(ProtectedRange.GetRangeAddress() == SecureRange.GetRangeAddress());
		CHECK(SecureRange.IsSecured() == true);
		CHECK(ProtectedRange.IsProtected() == true);

		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(ProtectedRange.Alloc(unRangeSize));
		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);
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
		constexpr unsigned char kCode[] = { 0xB8, 0x2A, 0, 0, 0, 0xC3 };
		Detours::Memory::SecurePage SecurePage;
		int nProtection = PROT_NONE;
		REQUIRE(SecurePage.GetProtection(&nProtection) == true);
		CHECK(nProtection == kProtectedMemoryDefaultTestProtection);
		REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadWriteTestProtection) == true);
		volatile unsigned char* const pCode =
			static_cast<volatile unsigned char*>(SecurePage.Alloc(sizeof(kCode)));
		REQUIRE(const_cast<unsigned char*>(pCode) != nullptr);

		for (std::size_t unIndex = 0; unIndex < sizeof(kCode); ++unIndex) {
			pCode[unIndex] = kCode[unIndex];
		}

		unsigned char* const pExecutableCode = const_cast<unsigned char*>(pCode);
		__builtin___clear_cache(
			reinterpret_cast<char*>(pExecutableCode),
			reinterpret_cast<char*>(pExecutableCode + sizeof(kCode)));

		REQUIRE(SecurePage.SetProtection(kProtectedMemoryReadExecuteTestProtection) == true);
		REQUIRE(SecurePage.GetProtection(&nProtection) == true);
		CHECK(nProtection == kProtectedMemoryReadExecuteTestProtection);
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
		REQUIRE(const_cast<std::uint64_t*>(pProtectedValue) != nullptr);
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
		REQUIRE(const_cast<std::uint64_t*>(pSecureValue) != nullptr);
		*pSecureValue = 23;
		CHECK(*pSecureValue == 23);
		CHECK(pSecureStorage->IsSecured() == true);
		CHECK(pSecureStorage->IsCompromised() == false);
		CHECK(SecureManager.DestroyStorage(pSecureStorage) == true);
		CHECK(SecureManager.DestroyPage(pSecurePage) == true);
	}

	TEST_CASE("SecureRange detects encrypted tail tampering") {
		constexpr std::size_t kRangeSize = 37;
		Detours::Memory::SecureRange SecureRange(kRangeSize);
		volatile unsigned char* const pData = static_cast<volatile unsigned char*>(SecureRange.Alloc(kRangeSize));
		REQUIRE(const_cast<unsigned char*>(pData) != nullptr);

		for (std::size_t unIndex = 0; unIndex < kRangeSize; ++unIndex) {
			pData[unIndex] = static_cast<unsigned char>(unIndex + 1);
		}

		CHECK(SecureRange.IsCompromised() == false);
		REQUIRE(TamperProtectedTestMemory(SecureRange.GetRangeAddress(), SecureRange.GetRangeSize()) == true);
		CHECK(SecureRange.IsCompromised() == true);
	}
} // TEST_SUITE("Detours::Memory")

#endif

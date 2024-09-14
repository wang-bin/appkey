/*
 * Copyright (c) 2019-2024 WangBin <wbsecg1 at gmail.com>
 * This file is part of MDK
 * MDK SDK: https://github.com/wang-bin/mdk-sdk
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * This code is public domain.
 */

#ifndef EDDSA_STATIC
# define EDDSA_STATIC
#endif
#include "app.h"
#include "key_pub.h"
#include "base/log.h"
#include "cppcompat/cstdlib.hpp"
extern "C" const char *getprogname(); //stdlib.h. apple, bsd, android21
#if !(_WIN32+0)
_Pragma("weak getprogname"); // android 21+
#endif
//__progname: qnx, glibc, bionic libc. set in __init_misc
#if defined(__linux__) // || defined(__QNX__) || defined(__QNXNTO__)
extern "C" const char *__progname; // bionic libc. no __progname_full and alias
#endif
// android: getprogname() and __progname is package name via android.app.Application.GetPackageName(), because no main executable
#ifdef _GNU_SOURCE
#include <errno.h> // program_invocation_short_name, gnu extension
//weak_alias (__progname_full, program_invocation_name)
//weak_alias (__progname, program_invocation_short_name)
#endif
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#if (__APPLE__+0)
#include <CoreFoundation/CFBundle.h>
#endif
#include <algorithm>
#include <cassert>
#include <cstring>

#include <chrono>
#include <ctime>
#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <iomanip>

#if (__linux__+0) && (__GLIBCXX__+0)
#define USE_STRPTIME 1
#include <time.h>
#endif
#include "cryptograph/eddsa.h"
using namespace std;
////#include <sys/prctl.h>

//prctl(PR_SET_NAME, name);  //linux gnu
// _POSIX_VERSION (unistd.h)

/*! Stringify \a x. */
#define _TOSTR(x)   #x
/*! Stringify \a x, perform macro expansion. */
#define TOSTR(x)  _TOSTR(x)

static const char kIdJoin[] = "/";

MDK_NS_BEGIN
namespace App {

void* gUserAddr = nullptr;

using namespace chrono;
static auto buildTime()
{
    std::tm t0 = {};
    std::istringstream ss(string(__DATE__).append(" ").append(__TIME__));
#ifdef USE_STRPTIME
    if (!strptime(ss.str().data(), "%b %e %Y %H:%M:%S", &t0)) {
#else
    ss.imbue(std::locale::classic()); // other locales abort in wine
    ss >> std::get_time(&t0, "%b %e %Y %H:%M:%S");
    if (ss.fail()) {
#endif
        std::clog << LogLevel::Warning << "Parse date failed: " << ss.str() << std::endl;
        return system_clock::now();
    }
    return system_clock::from_time_t(std::mktime(&t0));
}

int64_t timeAfterBuild()
{
    static const auto build = buildTime();
    return duration_cast<seconds>(system_clock::now() - build).count();
}

static uint32_t gCP = 65001; // CP_UTF8
void setCodePage(uint32_t cp)
{
    gCP = cp;
}

#if (_WIN32+0)
static string convert_codepage(const wchar_t* wstr, size_t wlen)
{
    const auto len = WideCharToMultiByte(gCP, 0, (LPCWSTR)wstr, wlen, nullptr, 0, nullptr, nullptr);
    string str(len, 0);
    WideCharToMultiByte(gCP, 0, (LPCWSTR)wstr, wlen, (LPSTR)str.c_str(), len, nullptr, nullptr);
    return str;
}

static HMODULE get_user_module(int level = 0)
{
    if (level == 0 || !gUserAddr)
        return nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(gUserAddr, &mbi, sizeof(mbi)); // or desktop GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)address, &hModule))
    return (HMODULE)mbi.AllocationBase;
}
#endif

std::string path_from_addr(void* addr)
{
    if (!addr)
        return {};
#if (_WIN32+0)
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(gUserAddr, &mbi, sizeof(mbi)); // or desktop GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)address, &hModule))
    string p;
    DWORD len = 0;
    do {
        p.resize(p.size() + MAX_PATH);
        //len = GetModuleFileNameW((HMODULE)mbi.AllocationBase, &wp[0], std::size(wp));
        len = GetModuleFileNameA((HMODULE)mbi.AllocationBase, &p[0], p.size());
    } while (len >= p.size());
    p.resize(len);
    //return convert_codepage(wp.data(), len);
    return p;
#elif defined(RTLD_DEFAULT) // check (0+__USE_GNU+__ELF__)? weak dlinfo? // mac, mingw, cygwin has no dlinfo
_Pragma("weak dladdr") // dladdr is not always supported. android since 8(arm)/9(x86)
    Dl_info info;
    if (dladdr && dladdr(addr, &info))
        return info.dli_fname;
#endif
    return {};
}

string Name(int level = 0)
{
    if (level == 0) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__BIONIC__)
    if (getprogname)
        return getprogname();
#endif
#if defined(_GNU_SOURCE) && !defined(__BIONIC__)
    return program_invocation_short_name;
#endif
#if defined(__linux__) // android<21
    return __progname;
#endif
    }
    auto mp = path_from_addr(gUserAddr);
#ifdef _WIN32
    auto d = mp.rfind('\\');
#else
    auto d = mp.rfind('/');
#endif
    clog << "user module: " << mp << endl;
    if (d != string::npos)
        mp = mp.substr(d + 1);
    d = mp.rfind('.');
    if (d != string::npos)
        mp = mp.substr(0, d);
    return mp;
}

string id(int level)
{
#if defined(__APPLE__)
    auto b = CFBundleGetMainBundle();
    auto cfid = CFBundleGetIdentifier(b); // or use app folder name(player.app), which MUST be unique1
    auto id = CFStringGetCStringPtr(cfid, kCFStringEncodingUTF8);
    if (id)
        return id;
#endif
#ifdef _WIN32
# if !(MDK_WINRT+0)
    TCHAR exe[MAX_PATH]{};
    GetModuleFileName(get_user_module(level), &exe[0], sizeof(exe));
    DWORD h = 0;
    auto sz = GetFileVersionInfoSize(&exe[0], &h);
    if (!sz)
        return Name(level);
    auto data = malloc(sz);
    if (!GetFileVersionInfo(&exe[0], h, sz, data)) {
        free(data);
        return Name(level);
    }
    wchar_t* buf = nullptr;
    UINT bufLen = 0;
    string product, company;
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;
    UINT cbTranslate = 0;
    VerQueryValue(data, TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&lpTranslate, &cbTranslate);
    // Read the file description for each language and code page.
    for (int i = 0; i < cbTranslate/sizeof(LANGANDCODEPAGE); i++) {
        wstring sub(64, 0);
        swprintf_s(&sub[0], sub.size(), L"\\StringFileInfo\\%04x%04x\\ProductName", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
        if (VerQueryValueW(data, sub.data(), (LPVOID*)&buf, &bufLen))
            product = convert_codepage(buf, bufLen - 1); // bufLen: including terminal 0
        swprintf_s(&sub[0], sub.size(), L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
        if (VerQueryValueW(data, sub.data(), (LPVOID*)&buf, &bufLen))
            company = convert_codepage(buf, bufLen - 1);
        if (!product.empty() || !company.empty())
            break;
    }
    free(data);
    return product + kIdJoin + company;
# endif
    // TODO: GetFileVersionInfo() query company name
#endif
    return Name(level);
}

static bool skipLicense()
{
#if defined(RTLD_DEFAULT)
_Pragma("weak dladdr") // dladdr is not always supported
    static Dl_info dli;
    if (dladdr && dladdr(&dli, &dli)) { // dladdr(global_sth_address_in_image, ...)
// i'm glad to be a linux system lib
        if (strstr(dli.dli_fname, "/usr/lib/") == dli.dli_fname)
            return true;
    }
#endif
    return false;
}

static bool expired()
{
    const auto dt = timeAfterBuild();
    return dt > 3600*24*44 || dt < 0; // < 0: system time can not be earlier than build time
}

enum class OS : uint16_t {
    Unknown = 0,
    macOS = 1,
    iOS = 1 << 1, // including maccatalyst
    tvOS = 1 << 2,
    visionOS = 1 << 10,
    Apple = macOS | iOS | tvOS | visionOS,
    Win32 = 1 << 3,
    UWP = 1 << 4,
    Windows = Win32 | UWP,
    Android = 1 << 5,
    Linux = 1 << 6,
    RaspberryPi = 1 << 7,
    Sunxi = 1 << 8,
    Sailfish = 1 << 9,
    // BSD
    All = 0xffff,
};

enum class ARCH : uint16_t {
    Unknown = 0,
    ARM = 1,
    AArch64 = 1 << 1,
    I386 = 1 << 2,
    X86_64 = 1 << 3,
    X86 = I386 | X86_64,
    RISCV = 1 << 4,
    WebAssembly = 1 << 5,
    Mips = 1 << 6,
    PowerPC = 1 << 7,
    Sparc = 1 << 8,
    SystemZ = 1 << 9,
    Alpha = 1 << 15,
    All = 0xffff,
};

enum class Restriction : uint16_t {
    None = 0,
    GPL = 1,
    OpenSource = 1 << 1,
    Nonprofit = 1 << 2,
    Education = 1 << 3,
    Sponsor = 1 << 4,
    Test = 1 << 6,
};
} // namespace App

template<> struct is_flag<App::OS> : std::true_type {};
template<> struct is_flag<App::ARCH> : std::true_type {};
template<> struct is_flag<App::Restriction> : std::true_type {};

namespace App {
static OS os_from_names(const string& S)
{
    string s(S);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    OS os = OS::Unknown;
    if (s.find("mac") != string::npos)
        os |= OS::macOS;
    if (s.find("ios") != string::npos)
        os |= OS::iOS;
    if (s.find("tvos") != string::npos)
        os |= OS::tvOS;
    if (s.find("apple") != string::npos)
        os |= OS::Apple;
    if (s.find("win32") != string::npos)
        os |= OS::Win32;
    if (s.find("uwp") != string::npos)
        os |= OS::UWP;
    if (s.find("windows") != string::npos)
        os |= OS::Windows;
    if (s.find("android") != string::npos)
        os |= OS::Android;
    if (s.find("linux") != string::npos)
        os |= OS::Linux;
    if (s.find("rpi") != string::npos)
        os |= OS::RaspberryPi;
    if (s.find("sunxi") != string::npos)
        os |= OS::Sunxi;
    if (s.find("sailfish") != string::npos)
        os |= OS::Sailfish;
    if (s.find("all") != string::npos)
        os |= OS::All;
    return os;
}

static ARCH arch_from_names(const string& S)
{
    string s(S);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    ARCH arch = ARCH::Unknown;
    if (s.find("arm") != string::npos)
        arch |= ARCH::ARM;
    if (s.find("aarch64") != string::npos)
        arch |= ARCH::AArch64;
    if (s.find("i386") != string::npos)
        arch |= ARCH::I386;
    if (s.find("x86_64") != string::npos)
        arch |= ARCH::X86_64;
    if (s.find("x64") != string::npos)
        arch |= ARCH::X86_64;
    if (s.find("x86") != string::npos)
        arch |= ARCH::X86;
    if (s.find("riscv") != string::npos)
        arch |= ARCH::RISCV;
    if (s.find("web") != string::npos)
        arch |= ARCH::WebAssembly;
    if (s.find("mips") != string::npos)
        arch |= ARCH::Mips;
    if (s.find("pc") != string::npos)
        arch |= ARCH::PowerPC;
    if (s.find("sparc") != string::npos)
        arch |= ARCH::Sparc;
    if (s.find("systemz") != string::npos)
        arch |= ARCH::SystemZ;
    if (s.find("alpha") != string::npos)
        arch |= ARCH::Alpha;
    if (s.find("all") != string::npos)
        arch |= ARCH::All;
    return arch;
}

Restriction restriction_from_names(const string& S)
{
    string s(S);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    Restriction r = Restriction::None;
    if (s.find("gpl") != string::npos)
        r |= Restriction::GPL;
    if (s.find("open") != string::npos)
        r |= Restriction::OpenSource;
    if (s.find("nonprofit") != string::npos)
        r |= Restriction::Nonprofit;
    if (s.find("edu") != string::npos)
        r |= Restriction::Education;
    if (s.find("sponsor") != string::npos)
        r |= Restriction::Sponsor;
    if (s.find("test") != string::npos)
        r |= Restriction::Test;
    return r;
}

void data_from_hex_str(const char* s, size_t len, vector<uint8_t>& v)
{
    v.resize(len/2);
    for (int i = 0; i < len/2; ++i) {
        char x[3] = {s[2*i], s[2*i+1], 0};
        v[i] = std::stoi(x, nullptr, 16);
    }
}

static vector<uint8_t> sig_from_key_hex(const char* key)
{
    vector<uint8_t> sig;
    sig.reserve(ED25519_SIG_LEN);
    data_from_hex_str(key, ED25519_SIG_LEN*2, sig);
    return sig;
}

// sig[64] and data[64] pair
// key_hex = sig + (sig^data)
static bool sig_data_from_key_hex(const string& key, vector<uint8_t>& sig, vector<uint8_t>& data)
{
    if (key.size() < ED25519_SIG_LEN*4) {
        std::clog << LogLevel::Error << "wrong key size. must >= " << ED25519_SIG_LEN*4 << std::endl;
        return false;
    }
    sig = sig_from_key_hex(&key[0]);
    data = sig_from_key_hex(&key[ED25519_SIG_LEN*2]);
    //stringstream sigs;
    //stringstream datas;
    for (int i = 0; i < sig.size(); ++i) {
        data[i] ^= sig[i];
        //sigs << int(sig[i]);
        //datas << int(data[i]);
    }
    //cout << "verify sig int:\n" << sigs.str() << std::endl;
    //cout << "verify data origin int:\n" << datas.str() << std::endl;
    return true;
}

static bool data_from_key_verify(const string& key, const uint8_t pub[ED25519_KEY_LEN], vector<uint8_t>& data)
{
    vector<uint8_t> sig;
    if (!sig_data_from_key_hex(key, sig, data))
        return false;
    if (ed25519_verify(sig.data(), pub, data.data(), data.size())) {
        std::clog << LogLevel::Info << TOSTR(MDK_NS) " verify key signature ok" << std::endl;
        return true;
    }
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " failed to verify key signature" << std::endl;
    return false;
}

struct KeyData { // MUST be unique layout on all platforms!
    OS os = OS::All;
    ARCH arch = ARCH::All;
    int16_t major = INT16_MAX;
    int16_t minor = INT16_MAX;
    int64_t time = INT64_MAX; // seconds
    Restriction restriction = Restriction::None;
    uint8_t appid[46];
};
static_assert(sizeof(KeyData) == ED25519_SIG_LEN, "bad KeyData size");

static bool verify_data_os(const KeyData& data, OS test = OS::Unknown)
{
    const auto os = data.os;
    if (test != OS::Unknown) {
        std::clog << TOSTR(MDK_NS) " verify test os: " << int(test) << "/" << int(data.os) << std::endl;
        if ((os & test) == test)
            return true;
    }
    else if (test_flag(os &
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
    OS::macOS
#elif defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
    OS::iOS
#elif defined(__ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__)
    OS::tvOS
#elif (TARGET_OS_VISION + 0)
    OS::visionOS
#elif defined(__ANDROID__)
    OS::Android
#elif defined(_WIN32)
# if defined(MDK_WINRT)
    OS::UWP
# else
    OS::Win32
# endif
#elif defined(OS_RPI)
    OS::RaspberryPi
#elif defined(OS_SUNXI)
    OS::Sunxi
#elif defined(__linux__)
    OS::Linux
#else
    OS::Unknown
#endif
    ))
        return true;
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key does not support current OS" << std::endl;
    return false;
}

static bool verify_data_arch(const KeyData& data, ARCH test = ARCH::Unknown)
{
    const auto arch = data.arch;
    if (test != ARCH::Unknown) {
        std::clog << TOSTR(MDK_NS) " verify test arch: " << int(test) << "/" << int(data.arch) << std::endl;
        if ((arch & test) == test)
            return true;
    }
    else if (test_flag(arch &
#if (__aarch64__+0) || /*vc*/defined(_M_ARM64)
        ARCH::AArch64
#elif (__ARM_ARCH+0) || (_M_ARM+0)
        ARCH::ARM
#elif defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || /*vc*/defined(_M_X64) || defined(_M_AMD64)
        ARCH::X86_64
#elif defined(__i386) || defined(__i386__) || /*vc*/defined(_M_IX86)
        ARCH::I386
#else
        ARCH::Unknown
#endif
    ))
        return true;
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key does not support current cpu" << std::endl;
    return false;
}

static bool verify_data_restriction(const KeyData& data, Restriction test = Restriction::None)
{
    const auto r = data.restriction;
    if (test != Restriction::None) {
        std::clog << TOSTR(MDK_NS) " verify test restriction: " << int(test) << "/" << int(r) << std::endl;
        if ((r & test) == test)
            return true;
    } else {
        string rs;
        if (test_flag(r & Restriction::GPL))
            rs += "GPL, ";
        if (test_flag(r & Restriction::OpenSource))
            rs += "OpenSource, ";
        if (test_flag(r & Restriction::Nonprofit))
            rs += "Nonprofit, ";
        if (test_flag(r & Restriction::Sponsor))
            rs += "Sponsor, ";
        if (test_flag(r & Restriction::Education))
            rs += "Education, ";
        if (test_flag(r & Restriction::Test))
            rs += "Test, ";
        if (!rs.empty())
            std::clog << LogLevel::Info << TOSTR(MDK_NS) " license key restrictions: " << rs << std::endl;
        return true;
    }
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key is restricted" << std::endl;
    return false;
}

static bool verify_data_time(const KeyData& data, int64_t test = -1)
{
    clog << "key time: " << data.time << endl;
    if (data.time < 0)
        return true;
    if (test >= 0) {
        std::clog << "verify test time: " << test << "/" << data.time << std::endl;
        if (test < data.time)
            return true;
    } else {
        auto now = chrono::system_clock::now().time_since_epoch();
#if 1//DEBUG
        std::clog << LogLevel::Info << TOSTR(MDK_NS) " license key will expire in " << data.time - chrono::duration_cast<chrono::seconds>(now).count() << " seconds" << std::endl;
#endif
        static const bool earlier_than_build = timeAfterBuild() < 0;
        if (earlier_than_build) {
            std::clog << LogLevel::Error << "System time is earlier than " TOSTR(MDK_NS) " was built" << std::endl;
            return false;
        }
        if (chrono::duration_cast<chrono::seconds>(now).count() < data.time)
            return true;
    }
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key is expired" << std::endl;
    return false;
}


static bool verify_data_version(const KeyData& data, int16_t test_major = -1, int16_t test_minor = -1)
{
    if (data.major < 0 || data.minor < 0)
        return true;
    if (test_major >= 0 && test_minor >= 0) {
        std::clog << "verify test version: " << test_major << "." << test_minor << "/" << data.major << "." << data.minor << std::endl;
        if (((test_major << 16) | test_minor) <= ((data.major << 16) | data.minor))
            return true;
    } else {
        std::clog << LogLevel::Info << TOSTR(MDK_NS) " license key for sdk version <= " << data.major << "." << data.minor << std::endl;
        if (((MDK_MAJOR << 16) | MDK_MINOR) <= ((data.major << 16) | data.minor))
            return true;
    }
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key does not support current sdk version: > " << data.major << "." << data.minor << std::endl;
    return false;
}

static bool verify_data_appid(const KeyData& data, const string& test = string())
{
    int len = data.appid[0];
    if (len == 0)
        return true;
    string AppId;
    AppId.resize(len);
    memcpy(&AppId[0], &data.appid[1], len);
    auto appid = AppId;
    // TODO: os != linux
    std::transform(appid.begin(), appid.end(), appid.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    auto name = Name();
    auto name2 = Name(1);
    if (AppId.find(kIdJoin) != string::npos || AppId.find('.') != string::npos) {
        name = id();
        name2 = id(1);
    }
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    std::transform(name2.begin(), name2.end(), name2.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    if (!test.empty()) {
        std::clog << "verify test appid: " << test << "/" << appid << std::endl;
        if (test == appid)
            return true;
    } else {
        std::clog << LogLevel::Info << TOSTR(MDK_NS) " license key for app: " << AppId << std::endl;
        if (len < sizeof(data.appid) - 1) {
            if (name == appid || name2 == appid || name2 == "lib" + appid)
                return true;
        } else {
            if (name.find(appid) == 0 || name2.find(appid))
                return true;
        }
    }
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " license key does not support current app: " << name << "|" << name2 << std::endl;
    return false;
}

bool verify_key(const string& key, const uint8_t pub[ED25519_KEY_LEN])
{
    vector<uint8_t> data;
    if (!data_from_key_verify(key, pub, data))
        return false;
    KeyData kd;
    assert(sizeof(kd) == data.size());
    memcpy(&kd, data.data(), sizeof(kd));
    bool ok = verify_data_os(kd);
    ok &= verify_data_arch(kd);
    ok &= verify_data_restriction(kd);
    ok &= verify_data_time(kd);
    ok &= verify_data_version(kd);
    clog << "check version" << endl;
    ok &= verify_data_appid(kd);
    return ok;
}

bool verify_key(const std::string& key, const uint8_t pub[32], const std::string& osnames, const std::string& archnames, const std::string& restrictions, int64_t seconds, int16_t major, int16_t minor, const std::string& appid)
{
    vector<uint8_t> data;
    if (!data_from_key_verify(key, pub, data))
        return false;
    KeyData kd;
    assert(sizeof(kd) == data.size());
    memcpy(&kd, data.data(), sizeof(kd));
    bool ok = verify_data_os(kd, os_from_names(osnames));
    ok &= verify_data_arch(kd, arch_from_names(archnames));
    ok &= verify_data_restriction(kd, restriction_from_names(restrictions));
    ok &= verify_data_time(kd, seconds);
    ok &= verify_data_version(kd, major, minor);
    ok &= verify_data_appid(kd, appid);
    return ok;
}

static KeyData gen_data(const string& osnames, const string& archnames, const std::string& restrictions, int64_t seconds, int16_t major, int16_t minor, const string& appid)
{
    KeyData kd;
    kd.os = os_from_names(osnames);
    kd.arch = arch_from_names(archnames);
    kd.restriction = restriction_from_names(restrictions);
    kd.major = major;
    kd.minor = minor;
    kd.time = seconds;

    string id = appid;
    if (sizeof(kd.appid) - 1 < id.size()) {
        std::clog << LogLevel::Error << "appid is too long, must <= " << sizeof(kd.appid) - 1 << std::endl;
        id.resize(sizeof(kd.appid) - 1);
    }
    auto appid_len = uint8_t(id.size());
    kd.appid[0] = appid_len;
    clog << "appid[0]: " << (int)kd.appid[0] << endl;
    memcpy(&kd.appid[1], &id[0], id.size());
    auto offset = 1 + id.size();
    // append random data to ensure data is unique. free to modify
    std::srand(std::time(nullptr)%UINT_MAX);
    for (size_t i = offset; i <= sizeof(kd.appid) -sizeof(int); i+=sizeof(int)) {
        auto idata = reinterpret_cast<int*>(&kd.appid[i]);
        *idata = std::rand();
    }
    return kd;
}

void gen_pub(const uint8_t priv[ED25519_KEY_LEN], uint8_t pub[ED25519_KEY_LEN])
{
    ed25519_genpub(pub, priv);
}

string gen_key(const uint8_t priv[ED25519_KEY_LEN], const uint8_t pub[ED25519_KEY_LEN], const string& osnames, const string& archnames, const std::string& restrictions, int64_t seconds, int16_t major, int16_t minor, const string& appid)
{
    vector<uint8_t> key(2*ED25519_SIG_LEN);
    auto kd = gen_data(osnames, archnames, restrictions, seconds, major, minor, appid);
    ed25519_sign(&key[0], priv, pub, (const uint8_t*)&kd, sizeof(kd));
    auto data = &key[ED25519_SIG_LEN];
    memcpy(data, &kd, sizeof(kd));
    //std::cout << "data origin int:\n";
    for (int i = 0; i < ED25519_SIG_LEN; ++i) {
        //std::cout << int(data[i]);
        data[i] ^= key[i];
    }
    //std::cout << "key int:\n";
    std::stringstream ss;
    for (const auto& k : key) {
        ss << std::uppercase << std::setw(2) << std::setfill('0')<< std::hex << (int)k;
        //std::cout << int(k);
    }
    //std::cout << std::endl;
    return ss.str();
}


void setUserAddress(void* addr)
{
    gUserAddr = addr;
}

bool checkLicense(const char* key)
{
    static int licensed = -1;
    if (licensed > 0 && !key)
        return true;
    if (skipLicense())
        return true;
    if (!key)
        key = std::getenv("MDK_KEY");
    if (!key) {
        if (!expired())
            return licensed != 0; // license == 0 means expired or a wrong key was set
    } else {
        //clog << "verify key: " << key << endl;
    // DO NOT print key in log! Print details instead
        if (verify_key(key, kKeyPub)) {
            licensed = 1;
            return true;
        }
    }
    std::clog << LogLevel::Error << "Bad " TOSTR(MDK_NS) " license!" << std::endl;
    std::clog << LogLevel::Error << TOSTR(MDK_NS) " SDK is outdated. Get a new free sdk from https://sourceforge.net/projects/mdk-sdk/files, or purchase a license.\n"
    "paypal: https://www.paypal.me/ibingow/500 or https://www.qtav.org/donate.html\n" << std::endl << std::flush;
    licensed = 0;
    return false;
}

} // namespace App
MDK_NS_END

/*
 * Copyright (c) 2019-2021 WangBin <wbsecg1 at gmail.com>
 * This file is part of MDK
 * MDK SDK: https://github.com/wang-bin/mdk-sdk
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * This code is public domain.
 */
#if __has_include("key_private.h")
# include "key_private.h"
#else
constexpr const char* private_default = "SET YOUR PRIVATE KEY DATA HERE";
#endif

#include "base/app.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>
#include <memory>
#include <iostream>
#include <cstdlib> // putenv
#if _WIN32
#define putenv _putenv // putenv_s(name, value).  for getenv(), can not use SetEnvironmentVariable
#endif
using namespace MDK_NS;
using namespace std;

#define ED25519_KEY_LEN 32
#define ED25519_SIG_LEN 64
#define APP_KEY_LEN (ED25519_SIG_LEN*2)

int main(int argc, const char** argv)
{
    auto now = chrono::system_clock::now().time_since_epoch();
    cout << chrono::duration_cast<chrono::seconds>(now).count() << std::endl;

    uint8_t pub[ED25519_KEY_LEN]{};
    uint8_t sec[ED25519_KEY_LEN]{};
    string key;
    memcpy(sec, private_default, std::min<int>(sizeof(sec), strlen(private_default)));

    bool verify = false;
    bool gen = false;
    int64_t seconds = -1;
    const char* os = "all";
    const char* arch = "all";
    const char* restriction = "none";
    string appid;
    int major = -1;
    int minor = -1;

    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "-gen") == 0) { // gen pub/priv pair and key
            gen = true;
        } else if (strcmp(argv[i], "-pub") == 0) {
            auto p = argv[++i];
            assert(strlen(p) >= ED25519_KEY_LEN);
            for (int j = 0; j < ED25519_KEY_LEN; j++) {
                char h[3] = {p[2*j], p[2*j+1], 0};
                pub[j] = (uint8_t)std::stoi(h, nullptr, 16);
            }
        } else if (strcmp(argv[i], "-sec") == 0) {
            memset(sec, 0, sizeof(sec));
            auto p = argv[++i];
            memcpy(sec, p, strlen(p));
        } else if (strcmp(argv[i], "-verify") == 0) {
            verify = true;
        } else if (strcmp(argv[i], "-key") == 0) {
            key = argv[++i];
        } else if (strcmp(argv[i], "-years") == 0) {
            seconds = std::atoi(argv[++i])*12*30*24*3600;
        } else if (strcmp(argv[i], "-months") == 0) {
            seconds = std::atoi(argv[++i])*30*24*3600;
        } else if (strcmp(argv[i], "-days") == 0) {
            seconds = std::atoi(argv[++i])*24*3600;
        } else if (strcmp(argv[i], "-seconds") == 0) {
            seconds = std::atoi(argv[++i]);
        } else if (strcmp(argv[i], "-os") == 0) {
            os = argv[++i];
        } else if (strcmp(argv[i], "-arch") == 0) {
            arch = argv[++i];
        } else if (strcmp(argv[i], "-restriction") == 0) {
            restriction = argv[++i];
        } else if (strcmp(argv[i], "-major") == 0) {
            major = std::atoi(argv[++i]);
        } else if (strcmp(argv[i], "-minor") == 0) {
            minor = std::atoi(argv[++i]);
        } else if (strcmp(argv[i], "-appid") == 0) { //
            appid = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            printf(R"(
options:
    -gen: gen license key
    -pub: set pub key. used to verify a license key. ignored if -gen is set
    -verify: verify key
    -years: expire years
    -days: expire days
    -seconds: expire seconds
    -os: target os or combinations. can be win32, windows, uwp, mac, ios, tvos, apple, android, linux, rpi, sunxi, sailfish, all
    -arch: target cpu. can be arm, aarch64, i386, x86, x86_64, x64, all
    -restriction: can be glp, opensource, nonprofit, edu, sponsor, test
    -major: max major version
    -minor: max minor version
    -appid: windows is exe name, or "$ProductName/$CompanyName" from rc; apple & android is app bundle id. otherwise is filename.
)");
        }
    }

    if (seconds >= 0)
        seconds += chrono::duration_cast<chrono::seconds>(now).count();
    if (gen) {
// write to keypair.h
        App::gen_pub(sec, pub);
        auto fp = std::fopen("key.h", "w");
        fprintf(fp, "static const uint8_t kKeyPub[] = {");
        printf("pub:\n");
        for (auto i : pub) {
            printf("%02X", i);
            fprintf(fp, "%#02X, ", i);
        }
        printf("\n");
        fprintf(fp, "};");
        std::cout << "key input:\n" << key << std::endl;
        key = App::gen_key(sec, pub, os, arch, restriction, seconds, major, minor, appid);
        std::cout << "key generated:\n" << key << std::endl;
    }
    if (verify) {
        auto ret = App::verify_key(key, pub, os, arch, restriction, seconds, major, minor, appid);
        std::cout << "key verify result: " << ret << std::endl;
        auto env = std::string("MDK_KEY=").append(key);
        putenv((char*)env.data());
        App::checkLicense();
    }
    return 0;
}
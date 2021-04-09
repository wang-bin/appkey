#pragma once
// FIXME: why clang-cl for 64bit gives wrong result?
#define USE_64BIT	0 //((_WIN64+0) || (__LP64__+0) || (__x86_64+0) || (AMD64+0) || (_M_AMD64+0))

#define BIT(X) X & 0x01
#define MODPOW32(x) ((x) & 4294967295)
#define MOD32(x) ((x) & 31)
#define ROTR32(x, n) ((x >> MOD32(n)) | ((x << (32 - MOD32(n))) & 4294967295))

#ifndef MSVC_COMPILER_LOCAL_MACRO
#define MSVC_COMPILER_LOCAL_MACRO (_MSC_VER && !__INTEL_COMPILER)
#endif

#ifndef GPP_COMPILER_LOCAL_MACRO
#define GPP_COMPILER_LOCAL_MACRO __GNUC__
#endif

#include <stdio.h>
#include <iostream>
#include <fstream>

#include <immintrin.h>

#if MSVC_COMPILER_LOCAL_MACRO
#include <intrin.h>
#endif

#include <random>

#include <stdlib.h>
#include <vector>
#include <string.h>
#include <chrono>
#include <bitset>
#include <string>
#include <unordered_map>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <functional>
#include <queue>

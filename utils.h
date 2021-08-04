#define BIT(X) X & 0x01
#define MODPOW32(x) ((x) & 4294967295)
#define MOD32(x) ((x) & 31)
#define ROTR32(x, n) ((x >> MOD32(n)) | ((x << (32 - MOD32(n))) & 4294967295))

/**
 * Regarding Ciphertext class, current implementation is threadsafe (without manual synchronization)
 * only when manipulating ciphertexts with no common internal node
 * (they were obtained from totally different ciphertexts, and no operation was performed between them)
 * Setting this macro to true enables support for these cases, 
 * although this might slow down (by a constant amount) all operations on all ciphertexts
 * NOTE: deepcopies are not considered related (they can be safely used in a multithreading context in any case)
**/
#define MULTITHREADING_EXTENDED_SUPPORT true

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
#include <unordered_set>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <functional>
#include <queue>

#define BIT(X) X & 0x01

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
//#include <avx2intrin.h>
//#include <avxintrin.h>

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

#include <condition_variable>
#include <mutex>
#include <thread>
#include <functional>
#include <queue>

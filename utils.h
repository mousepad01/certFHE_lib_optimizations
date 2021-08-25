#ifndef UTILS_H
#define UTILS_H

/**
 * Macros used for (de)serialization identification
 * ID restrictions:
 *		CCC: first 3 bits 000
 *		CADD: first 3 bits 001
 *		CMUL: first 3 bits 010
 *		Ciphertext: first 3 bits 011
 *		SecretKey: first 3 bits 100
 *		Permutation: first 3 bits 101
**/
#define CERTFHE_CCC_ID(X) ((X) & 0b000)
#define CERTFHE_CADD_ID(X) ((X) & 0b001)
#define CERTFHE_CMUL_ID(X) ((X) & 0b010)
#define CERTFHE_CTXT_ID(X) ((X) & 0b011)
#define CERTFHE_SK_ID(X) ((X) & 0b100)
#define CERTFHE_PERM_ID(X) ((X) & 0b101)

/**
 * Regarding Ciphertext class, current implementation is threadsafe (without manual synchronization)
 * only when manipulating ciphertexts with no common internal node
 * (they were obtained from totally different ciphertexts, and no operation was performed between them)
 * Setting this macro to true enables support for these cases, 
 * although this might slow down (by a significant amount) all operations on all ciphertexts
 * NOTE: deepcopies are not considered related (they can be safely used in a multithreading context in any case)
 * NOTE: when operating on ciphertext with only CCC as nodes, implementation IS THREADSAFE
**/
#define CERTFHE_MULTITHREADING_EXTENDED_SUPPORT true

#define CERTFHE_MSVC_COMPILER_MACRO (_MSC_VER && !__INTEL_COMPILER)

#define CERTFHE_GNU_COMPILER_MACRO __GNUC__

/**
 * MACRO to ENABLE/DISABLE use of GPU found inside CUDA_interface.h
**/
#include "CUDA_interface.h"

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstdarg>

#include <immintrin.h>

#if CERTFHE_MSVC_COMPILER_MACRO
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

#endif

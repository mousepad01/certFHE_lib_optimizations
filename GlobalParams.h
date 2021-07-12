#ifndef GLOBAL_PARAMS_H
#define GLOBAL_PARAMS_H

#include "utils.h"
#include "Plaintext.h"
#include "Ciphertext.h"
#include "SecretKey.h"
#include "Context.h"
#include "Permutation.h"
#include "Helpers.h"
#include "Timer.h"

namespace certFHE {

	/*
	 * Class for multithreading threshold values
	 * and their management
	 */
	class MTValues {

		static const int AUTOSELECT_TEST_CNT = 4;  // number of tests, to be averaged
		static const int ROUND_PER_TEST_CNT = 50;  // number of counted operations per test

		static void __cpy_m_threshold_autoselect(const Context & context);
		static void __dec_m_threshold_autoselect(const Context & context);
		static void __mul_m_threshold_autoselect(const Context & context);
		static void __add_m_threshold_autoselect(const Context & context);
		static void __perm_m_threshold_autoselect(const Context & context);

	public:

		static uint64_t cpy_m_threshold; // threshold for using multithreading for copying
		static uint64_t dec_m_threshold; // threshold for using multithreading for decryption
		static uint64_t mul_m_threshold; // ...
		static uint64_t add_m_threshold;
		static uint64_t perm_m_threshold;

		static void cpy_m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "cpy_m_thrsh_cache.bin");
		static void dec_m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "dec_m_thrsh_cache.bin");
		static void mul_m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "mul_m_thrsh_cache.bin");
		static void add_m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "add_m_thrsh_cache.bin");
		static void perm_m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "perm_m_thrsh_cache.bin");
		static void m_threshold_autoselect(const Context & context, bool cache_in_file = true, string cache_file_name = "m_thrsh_cache.bin");
	};

	/*
	 * Class for permutation parameters
	 * and their management
	 */
	class PMValues {

		static const int AUTOSELECT_TEST_CNT = 3;  // number of tests, to be averaged
		static const int ROUND_PER_TEST_CNT = 1000;  // number of counted operations per test

		static void __perm_gen_threshold_autoselect();

	public:

		static int inv_factor;  // number of inversions (relative to perm size) to apply when creating a permutation
		static int perm_gen_threshold;  // threshold used for selecting permutation generation algorithm

		// for each permutation size, for each number of inversions, the chi square value 
		static double ** inv_factor_stats(const double ROUND_CNT = 1000, const double MAX_PERM_SIZE = 1200,
											const double MAX_INV_FACTOR_SIZE = 7);  
		
		static void perm_gen_threshold_autoselect(bool cache_in_file = true, string cache_file_name = "perm_gen_thrsh_cache.bin");
	};

}

#endif
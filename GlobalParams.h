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

	class OPValues {

	public:

		static uint64_t max_ccc_deflen_size;
		static bool remove_duplicates_onadd;
		static bool remove_duplicates_onmul;
	};

	/*
	 * Class for multithreading threshold values
	 * and their management
	 */
	class MTValues {

		static const uint64_t AUTOSELECT_TEST_CNT = 4;  // number of tests, to be averaged
		static const uint64_t ROUND_PER_TEST_CNT = 50;  // number of counted operations per test

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

		static void cpy_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "cpy_m_thrsh_cache.bin");
		static void dec_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "dec_m_thrsh_cache.bin");
		static void mul_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "mul_m_thrsh_cache.bin");
		static void add_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "add_m_thrsh_cache.bin");
		static void perm_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "perm_m_thrsh_cache.bin");
		static void m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "m_thrsh_cache.bin");
	};

}

#endif
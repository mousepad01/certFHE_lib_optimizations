#ifndef GLOBAL_PARAMS_H
#define GLOBAL_PARAMS_H

#include "utils.h"

namespace certFHE {

	class Context;

	class OPValues {

		static std::mutex opvalues_mutex;

	public:

		/**
		 * (guaranteed) Maximum size in deflen chunks for a contiguous ciphertext chunk
		 * If max_cadd_merge_size or max_cmul_merge_size is SMALLER THAN THIS LIMIT
		 * max_ccc_deflen_size might not be reached
		**/
		static uint64_t max_ccc_deflen_size;

		/**
		 * Upper defchunk len limit for a CADD node, under which it tries to merge upstream nodes
		 * It is useful when doing lots of operations, and the corresponding DAG has lots of nodes
		 * The merging will not take place and the depth will grow,
		 * in favor of not trying to (unsuccessfully) merge lots of nodes already in the DAG with new ones
		**/
		static uint64_t max_cadd_merge_size;

		/**
		 * Upper defchunk len limit for a CMUL node, under which it tries to merge upstream nodes
		 * Same logic as max_cadd_merge_size
		**/
		static uint64_t max_cmul_merge_size;

		/**
		 * If true and IF THE ALGORITHM ENCOUNTERS a chunk with deflen 1, it will multiply no matter what
		 * This implies that if there is somehow a node with deflen 1
		 * that does not take part in a merging call, it will remain unchanged even if the option is selected
		**/
		static bool always_default_multiplication;

		/**
		 * If true, removes duplicates when adding two CADD nodes (a + a = 0)
		 * If there are somehow two duplicates, but they do not meet inside a merging operations
		 * they will not be reduced, even if this option is selected
		**/
		static bool remove_duplicates_onadd;

		/**
		 * If true, removes duplicates when multiplying two CMUL nodes (a * a = a)
		 * Same warning as for remove_duplicates_onadd
		**/
		static bool remove_duplicates_onmul;

		/**
		 * If true, upstream_shortening is called after every recursive upstream_merging call inside CADD class
		 * Might be useful in lots of situations, but might consume A LOT of time in some particular cases
		**/
		static bool shorten_on_recursive_cadd_merging;

		/**
		 * If true, upstream_shortening is called after every recursive upstream_merging call inside CMUL class
		 * Same observation as for shorten_on_recursive_cadd_merging
		**/
		static bool shorten_on_recursive_cmul_merging;
	};

	/*
	 * Class for multithreading threshold values
	 * and their management
	 */
	class MTValues {

		static std::mutex mtvalues_mutex;

		static const uint64_t AUTOSELECT_TEST_CNT = 4;  // number of tests, to be averaged
		static const uint64_t ROUND_PER_TEST_CNT = 50;  // number of counted operations per test

		static void __cpy_m_threshold_autoselect(const Context & context);
		static void __dec_m_threshold_autoselect(const Context & context);
		static void __mul_m_threshold_autoselect(const Context & context);
		static void __add_m_threshold_autoselect(const Context & context);
		static void __perm_m_threshold_autoselect(const Context & context);

	public:

		static uint64_t cpy_m_threshold;  // minimum threshold for using multithreading for CCC chunk copying
		static uint64_t dec_m_threshold;  // minimum threshold for using multithreading for CCC chunk decryption
		static uint64_t mul_m_threshold;  // minimum threshold for using multithreading for CCC chunk multiplication
		static uint64_t add_m_threshold;  // minimum threshold for using multithreading for CCC chunk addition
		static uint64_t perm_m_threshold; // minimum threshold for using multithreading for CCC chunk permutation

		static void cpy_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "cpy_m_thrsh_cache.bin");
		static void dec_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "dec_m_thrsh_cache.bin");
		static void mul_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "mul_m_thrsh_cache.bin");
		static void add_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "add_m_thrsh_cache.bin");
		static void perm_m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "perm_m_thrsh_cache.bin");
		static void m_threshold_autoselect(const Context & context, bool cache_in_file = true, std::string cache_file_name = "m_thrsh_cache.bin");
	};

}

#endif
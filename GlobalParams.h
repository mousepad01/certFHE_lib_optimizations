#ifndef GLOBAL_PARAMS_H
#define GLOBAL_PARAMS_H

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

	public:

		static uint64_t cpy_m_threshold; // threshold for using multithreading for copying
		static uint64_t dec_m_threshold; // threshold for using multithreading for decryption
		static uint64_t mul_m_threshold; // ...
		static uint64_t add_m_threshold;
		static uint64_t perm_m_threshold;

		static void cpy_m_threshold_autoselect(const Context & context);
		static void dec_m_threshold_autoselect(const Context & context);
		static void mul_m_threshold_autoselect(const Context & context);
		static void add_m_threshold_autoselect(const Context & context);
		static void perm_m_threshold_autoselect(const Context & context);
	};

}

#endif
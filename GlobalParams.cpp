#include "GlobalParams.h"

namespace certFHE {

	uint64_t MTValues::cpy_m_threshold = 0;
	uint64_t MTValues::dec_m_threshold = 0;
	uint64_t MTValues::mul_m_threshold = 0;
	uint64_t MTValues::add_m_threshold = 0;
	uint64_t MTValues::perm_m_threshold = 0;

	void MTValues::cpy_m_threshold_autoselect(const Context & context) {

		const int MAX_L_LOG = 15;
		const int MAX_L = 1 << MAX_L_LOG;

		const int deflen = context.getDefaultN();

		double observed_multithreading[MAX_L_LOG];
		double observed_sequential[MAX_L_LOG];

		memset(observed_multithreading, 0, MAX_L_LOG * sizeof(uint64_t));
		memset(observed_sequential, 0, MAX_L_LOG * sizeof(uint64_t));

		uint64_t * src = new uint64_t[MAX_L * deflen];
		uint64_t * dest = new uint64_t[MAX_L * deflen];

		for (int ts = 0; ts < AUTOSELECT_TEST_CNT; ts++) {

			for (int i = 0; i < MAX_L * deflen; i++)
				src[i] = (rand() << 48) | (rand() << 16); 

			for (int pow = 4; pow < MAX_L_LOG; pow++) {

				Timer timer("copy_m_threshold_autoselect_timer");
				timer.start();

				for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) 
					Helper::u64_multithread_cpy(src, dest, (1 << pow) * deflen);
					
				observed_multithreading[pow] += timer.stop();
			}

			for (int pow = 4; pow < MAX_L_LOG; pow++) {

				Timer timer("copy_m_threshold_autoselect_timer");
				timer.start();

				for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

					int maxpos = (1 << pow) * deflen;

					for (int pos = 0; pos < maxpos; pos++)
						dest[pos] = src[pos];
				}

				observed_sequential[pow] += timer.stop();
			}
		}

		for (int threshold_log = 4; threshold_log < MAX_L_LOG; threshold_log++)
			std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

		int threshold_log;
		for (threshold_log = 4; threshold_log < MAX_L_LOG; threshold_log++)

			if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
				break;

		MTValues::cpy_m_threshold = 1 << threshold_log;
	}

	void MTValues::dec_m_threshold_autoselect(const Context & context) {

	}

	void MTValues::mul_m_threshold_autoselect(const Context & context) {

	}

	void MTValues::add_m_threshold_autoselect(const Context & context) {

	}

	void MTValues::perm_m_threshold_autoselect(const Context & context) {

	}

}


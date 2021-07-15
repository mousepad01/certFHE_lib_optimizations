#include "GlobalParams.h"

using namespace certFHE;

#pragma region MTValues definitions

uint64_t MTValues::cpy_m_threshold = 0;
uint64_t MTValues::dec_m_threshold = 0;
uint64_t MTValues::mul_m_threshold = 0;
uint64_t MTValues::add_m_threshold = 0;
uint64_t MTValues::perm_m_threshold = 0;

void MTValues::__cpy_m_threshold_autoselect(const Context & context) {

	const int MAX_L_LOG = 15;
	const int MAX_L = 1 << MAX_L_LOG;

	double observed_multithreading[MAX_L_LOG];
	double observed_sequential[MAX_L_LOG];

	memset(observed_multithreading, 0, MAX_L_LOG * sizeof(uint64_t));
	memset(observed_sequential, 0, MAX_L_LOG * sizeof(uint64_t));

	const int deflen = context.getDefaultN();

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

	//for (int threshold_log = 4; threshold_log < MAX_L_LOG; threshold_log++)
		//std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

	int threshold_log;
	for (threshold_log = 4; threshold_log < MAX_L_LOG; threshold_log++)

		if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
			break;

	MTValues::cpy_m_threshold = 1 << threshold_log;
}
	
void MTValues::__dec_m_threshold_autoselect(const Context & context) {

	const int MAX_L_LOG = 15;

	double observed_multithreading[MAX_L_LOG];
	double observed_sequential[MAX_L_LOG];

	memset(observed_multithreading, 0, MAX_L_LOG * sizeof(double));
	memset(observed_sequential, 0, MAX_L_LOG * sizeof(double));

	SecretKey sk(context);

	for (int ts = 0; ts < AUTOSELECT_TEST_CNT; ts++) {

		MTValues::dec_m_threshold = 0;

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		for (int pow = 1; pow < MAX_L_LOG; pow += 1) {

			ctxt += ctxt;

			Plaintext pt;

			Timer timer;
			timer.start();

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++)
				pt = sk.decrypt(ctxt);

			observed_multithreading[pow] += timer.stop();
		}

		MTValues::dec_m_threshold = -1; // 0xFF FF FF FF FF FF FF FF

		p = Plaintext(rand() % 2);
		ctxt = sk.encrypt(p);

		for (int pow = 1; pow < MAX_L_LOG; pow += 1) {

			ctxt += ctxt;

			Plaintext pt;

			Timer timer;
			timer.start();

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++)
				pt = sk.decrypt(ctxt);

			observed_sequential[pow] += timer.stop();
		}
	}

	//for (int threshold_log = 1; threshold_log < MAX_L_LOG; threshold_log++)
		//std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

	int threshold_log;
	for (threshold_log = 1; threshold_log < MAX_L_LOG; threshold_log++)

		if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
			break;

	MTValues::dec_m_threshold = 1 << threshold_log;
}

void MTValues::__mul_m_threshold_autoselect(const Context & context) {

	const int MAX_L_LOG = 14;

	double observed_multithreading[MAX_L_LOG];
	double observed_sequential[MAX_L_LOG];

	memset(observed_multithreading, 0, MAX_L_LOG * sizeof(uint64_t));
	memset(observed_sequential, 0, MAX_L_LOG * sizeof(uint64_t));

	SecretKey sk(context);

	for (int ts = 0; ts < AUTOSELECT_TEST_CNT; ts++) {

		int first_len = 2;

		Ciphertext ctxt1, ctxt2;

		MTValues::mul_m_threshold = 0;

		for (int i = 0; i < first_len; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = sk.encrypt(p);

			if (i == 0) {

				ctxt1 = c;
				ctxt2 = c;
			}
			else {

				ctxt1 += c;
				ctxt2 += c;
			}
		}

		for (int pow = 2; pow < MAX_L_LOG; pow++) {

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt1);

				Timer timer;
				timer.start();

				aux_c *= ctxt2;

				observed_multithreading[pow] += timer.stop();
			}

			ctxt1 *= ctxt2;
		}

		MTValues::mul_m_threshold = -1; // 0xFF FF FF FF FF FF FF FF

		for (int i = 0; i < first_len; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = sk.encrypt(p);

			if (i == 0) {

				ctxt1 = c;
				ctxt2 = c;
			}
			else {

				ctxt1 += c;
				ctxt2 += c;
			}
		}

		for (int pow = 2; pow < MAX_L_LOG; pow++) {

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt1);

				Timer timer;
				timer.start();

				aux_c *= ctxt2;

				observed_sequential[pow] += timer.stop();
			}

			ctxt1 *= ctxt2;
		}
	}

	//for (int threshold_log = 2; threshold_log < MAX_L_LOG; threshold_log++)
		//std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

	int threshold_log;
	for (threshold_log = 2; threshold_log < MAX_L_LOG; threshold_log++)

		if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
			break;

	MTValues::mul_m_threshold = 1 << threshold_log;
}

void MTValues::__add_m_threshold_autoselect(const Context & context) {

	const int MAX_L_LOG = 16;

	double observed_multithreading[MAX_L_LOG];
	double observed_sequential[MAX_L_LOG];

	memset(observed_multithreading, 0, MAX_L_LOG * sizeof(uint64_t));
	memset(observed_sequential, 0, MAX_L_LOG * sizeof(uint64_t));

	SecretKey sk(context);

	for (int ts = 0; ts < AUTOSELECT_TEST_CNT; ts++) {

		int first_len = 64;

		Ciphertext ctxt;

		MTValues::add_m_threshold = 0;

		for (int i = 0; i < first_len; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = sk.encrypt(p);

			if (i == 0)
				ctxt = c;

			else
				ctxt += c;
		}

		for (int pow = 6; pow < MAX_L_LOG; pow += 2) {

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt);

				Timer timer;
				timer.start();

				aux_c += ctxt;

				observed_multithreading[pow] += timer.stop();
			}

			ctxt += ctxt;
			ctxt += ctxt;
		}

		MTValues::add_m_threshold = -1; // 0xFF FF FF FF FF FF FF FF

		for (int i = 0; i < first_len; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = sk.encrypt(p);

			if (i == 0)
				ctxt = c;

			else
				ctxt += c;
		}

		for (int pow = 6; pow < MAX_L_LOG; pow += 2) {

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt);

				Timer timer;
				timer.start();

				aux_c += ctxt;

				observed_sequential[pow] += timer.stop();
			}

			ctxt += ctxt;
			ctxt += ctxt;
		}
	}

	//for (int threshold_log = 6; threshold_log < MAX_L_LOG; threshold_log += 2)
		//std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

	int threshold_log;
	for (threshold_log = 6; threshold_log < MAX_L_LOG; threshold_log += 2)

		if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
			break;

	MTValues::add_m_threshold = 1 << threshold_log;
}

void MTValues::__perm_m_threshold_autoselect(const Context & context) {

	const int MAX_L_LOG = 7;

	double observed_multithreading[MAX_L_LOG];
	double observed_sequential[MAX_L_LOG];

	memset(observed_multithreading, 0, MAX_L_LOG * sizeof(uint64_t));
	memset(observed_sequential, 0, MAX_L_LOG * sizeof(uint64_t));

	SecretKey sk(context);

	for (int ts = 0; ts < AUTOSELECT_TEST_CNT; ts++) {

		MTValues::perm_m_threshold = 0;

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Permutation perm(context);

		for (int pow = 1; pow < MAX_L_LOG; pow += 1) {

			ctxt += ctxt;

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt);

				Timer timer;
				timer.start();

				aux_c.applyPermutation_inplace(perm);

				observed_multithreading[pow] += timer.stop();
			}
		}

		MTValues::perm_m_threshold = -1;

		p = Plaintext(rand() % 2);
		ctxt = sk.encrypt(p);

		for (int pow = 1; pow < MAX_L_LOG; pow += 1) {

			ctxt += ctxt;

			for (int rnd = 0; rnd < ROUND_PER_TEST_CNT; rnd++) {

				Ciphertext aux_c(ctxt);

				Timer timer;
				timer.start();

				aux_c.applyPermutation_inplace(perm);

				observed_sequential[pow] += timer.stop();
			}
		}

	}

	//for (int threshold_log = 1; threshold_log < MAX_L_LOG; threshold_log++)
		//std::cout << observed_multithreading[threshold_log] << " " << observed_sequential[threshold_log] << '\n';

	int threshold_log;
	for (threshold_log = 1; threshold_log < MAX_L_LOG; threshold_log++)

		if (observed_multithreading[threshold_log] <= observed_sequential[threshold_log])
			break;

	MTValues::perm_m_threshold = 1 << threshold_log;
}

void MTValues::cpy_m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t cpy_m_thrsh_cached;
			cache.read((char *)&cpy_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::cpy_m_threshold = cpy_m_thrsh_cached;
				return;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__cpy_m_threshold_autoselect(context);
			new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else
		__cpy_m_threshold_autoselect(context);

}

void MTValues::dec_m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t dec_m_thrsh_cached;
			cache.read((char *)&dec_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::dec_m_threshold = dec_m_thrsh_cached;
				return;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__dec_m_threshold_autoselect(context);
			new_cache.write((char *)&MTValues::dec_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else
		__dec_m_threshold_autoselect(context);
}

void MTValues::mul_m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t mul_m_thrsh_cached;
			cache.read((char *)&mul_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::mul_m_threshold = mul_m_thrsh_cached;
				return;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__mul_m_threshold_autoselect(context);
			new_cache.write((char *)&MTValues::mul_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else
		__mul_m_threshold_autoselect(context);
}

void MTValues::add_m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t add_m_thrsh_cached;
			cache.read((char *)&add_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::add_m_threshold = add_m_thrsh_cached;
				return;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__add_m_threshold_autoselect(context);
			new_cache.write((char *)&MTValues::add_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else
		__add_m_threshold_autoselect(context);
}

void MTValues::perm_m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t perm_m_thrsh_cached;
			cache.read((char *)&perm_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::perm_m_threshold = perm_m_thrsh_cached;
				return;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__perm_m_threshold_autoselect(context);
			new_cache.write((char *)&MTValues::perm_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else
		__perm_m_threshold_autoselect(context);
}

void MTValues::m_threshold_autoselect(const Context & context, bool cache_in_file, string cache_file_name) {

	if (cache_in_file) {

		std::fstream cache(cache_file_name, std::ios::binary | std::ios::out | std::ios::in);

		if (cache.is_open()) {

			uint64_t cpy_m_thrsh_cached;
			uint64_t dec_m_thrsh_cached;
			uint64_t mul_m_thrsh_cached;
			uint64_t add_m_thrsh_cached;
			uint64_t perm_m_thrsh_cached;

			cache.read((char *)&cpy_m_thrsh_cached, sizeof(uint64_t));
			cache.read((char *)&dec_m_thrsh_cached, sizeof(uint64_t));
			cache.read((char *)&mul_m_thrsh_cached, sizeof(uint64_t));
			cache.read((char *)&add_m_thrsh_cached, sizeof(uint64_t));
			cache.read((char *)&perm_m_thrsh_cached, sizeof(uint64_t));

			if (cache) {

				MTValues::cpy_m_threshold = cpy_m_thrsh_cached;
				MTValues::dec_m_threshold = dec_m_thrsh_cached;
				MTValues::mul_m_threshold = mul_m_thrsh_cached;
				MTValues::add_m_threshold = add_m_thrsh_cached;
				MTValues::perm_m_threshold = perm_m_thrsh_cached;
			}
			else {

				std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

				__cpy_m_threshold_autoselect(context);
				__dec_m_threshold_autoselect(context);
				__mul_m_threshold_autoselect(context);
				__add_m_threshold_autoselect(context);
				__perm_m_threshold_autoselect(context);

				new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));
				new_cache.write((char *)&MTValues::dec_m_threshold, sizeof(uint64_t));
				new_cache.write((char *)&MTValues::mul_m_threshold, sizeof(uint64_t));
				new_cache.write((char *)&MTValues::add_m_threshold, sizeof(uint64_t));
				new_cache.write((char *)&MTValues::perm_m_threshold, sizeof(uint64_t));

				new_cache.close();
			}

			cache.close();
		}
		else {

			std::fstream new_cache(cache_file_name, std::ios::out | std::ios::binary);

			__cpy_m_threshold_autoselect(context);
			__dec_m_threshold_autoselect(context);
			__mul_m_threshold_autoselect(context);
			__add_m_threshold_autoselect(context);
			__perm_m_threshold_autoselect(context);

			new_cache.write((char *)&MTValues::cpy_m_threshold, sizeof(uint64_t));
			new_cache.write((char *)&MTValues::dec_m_threshold, sizeof(uint64_t));
			new_cache.write((char *)&MTValues::mul_m_threshold, sizeof(uint64_t));
			new_cache.write((char *)&MTValues::add_m_threshold, sizeof(uint64_t));
			new_cache.write((char *)&MTValues::perm_m_threshold, sizeof(uint64_t));

			new_cache.close();
		}
	}
	else {

		__cpy_m_threshold_autoselect(context);
		__dec_m_threshold_autoselect(context);
		__mul_m_threshold_autoselect(context);
		__add_m_threshold_autoselect(context);
		__perm_m_threshold_autoselect(context);
	}
}

#pragma endregion


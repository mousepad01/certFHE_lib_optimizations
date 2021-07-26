#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <string>
#include <stdlib.h>
#include <string>
#include <fstream>

#include "certFHE.h"
#include "Threadpool.hpp"

static std::string STATS_PATH = "C:\\Users\\intern.andreis\\Desktop\\certfhe_stats\\DAG_implementation";

using namespace certFHE;

class Timervar{

    uint64_t t;

public:

    void start_timer(){
        t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    uint64_t stop_timer(){

        uint64_t old_t = t;
        t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        
        return t - old_t;
    }
};


void test_res_correct() {

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::m_threshold_autoselect(context, false);

	const int TEST_COUNT = 100; // sansa fals pozitiv: 2^(-TEST_COUNT)

	for (int tst = 0; tst < TEST_COUNT; tst++) {  // decriptare deflen

		int r = rand() % 2;
		Plaintext p(r);

		Ciphertext c = sk.encrypt(p);

		if (r != (sk.decrypt(c).getValue() & 0x01))
			std::cout << "DEFLEN DECRYPTION FAIL " << r << " " << (sk.decrypt(c).getValue() & 0x01) << '\n';
	}

	for (int tst = 0; tst < TEST_COUNT; tst++) {  // copiere lungime > deflen, adunare, decriptare

		Plaintext paux(1);
		int pauxn = 1;
		Ciphertext caux = sk.encrypt(paux);

		for (int i = 0; i < 100; i++) {

			int r = rand() % 2;
			Plaintext p(r);

			Ciphertext c = sk.encrypt(p);
			caux += c;

			pauxn ^= r;
		}

		Ciphertext caux_c;
		caux_c = caux;

		Ciphertext caux_c2(caux);

		if (((sk.decrypt(caux).getValue() & 0x01) != pauxn) || 
			((sk.decrypt(caux_c).getValue() & 0x01) != pauxn) ||
			((sk.decrypt(caux_c2).getValue() & 0x01) != pauxn))

			std::cout << "COPY FAIL\n";
	}

	for (int tst = 0; tst < TEST_COUNT; tst++) { // adunare, inmultire, permutare, decriptare

		Plaintext p0(0);
		Plaintext p1(1);

		Ciphertext c0 = sk.encrypt(p0);
		Ciphertext c1 = sk.encrypt(p1);

		int c00 = 0;
		int c11 = 1;

		for (int i = 0; i < 1000; i++) {

			int r = rand() % 2;
			c00 += r;
			c00 %= 2;

			Plaintext p(r);
			Ciphertext c = sk.encrypt(p);

			c0 += c;
		}

		for (int i = 0; i < 17; i++) {

			int r = rand() % 2;
			c11 += r;
			c11 %= 2;

			Plaintext p(r);
			Ciphertext c = sk.encrypt(p);

			c1 += c;
		}

		c1 *= c0;
		c11 *= c00;

		Permutation perm(context);
		SecretKey psk = sk.applyPermutation(perm);

		Ciphertext pc0 = c0.applyPermutation(perm);
		Ciphertext pc1 = c1.applyPermutation(perm);

		if ((((psk.decrypt(pc0).getValue() & 0x01) == c00) && ((psk.decrypt(pc1).getValue() & 0x01) == c11)) == false)
			std::cout << "ADDITION / MULTIPLICATION / PERMUTATION FAIL \n";
		//else
			//std::cout << "OK\n";

	}
	std::cout << "\nTESTS DONE\n\n";
}


void only_dec_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\add_mul_decr_multithreading_stats\\only_decryption\\only_dec_with_all_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			sk.decrypt(ctxt);

			uint64_t ti = t.stop_timer();

			f << "decrypting len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
	}
}


void dec_mul_add_test_time(const int test_count, const int FIRST_LEN = 15, const int SECOND_LEN = 25,
	const int THIRD_LEN = 2, const int ROUND_CNT = 5) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\DAG_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;
		int trd_len_cpy = THIRD_LEN;

		Timervar t;

		t.start_timer();

		uint64_t ti = t.stop_timer();
		f << "TEST\n";
		t.stop_timer();

		Plaintext p1(rand() % 2);
		Ciphertext ctxt1 = seckey.encrypt(p1);

		Plaintext p2(rand() % 2);
		Ciphertext ctxt2 = seckey.encrypt(p2);

		Plaintext p3(rand() % 2);
		Ciphertext ctxt3 = seckey.encrypt(p3);

		for (int i = 1; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			ctxt1 += c;
		}
		
		for (int i = 1; i < snd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			ctxt2 += c;
		}

		for (int i = 1; i < trd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			ctxt3 += c;
		}

		t.stop_timer();
		
		for (int i = 0; i < ROUND_CNT; i++) {

			ctxt1 *= ctxt3;
			//ctxt2 *= ctxt3;

			//ctxt1 += ctxt2;

			uint64_t ti = t.stop_timer();
			f << "round with len1=" << first_len_cpy << " len2=" << snd_len_cpy << " len3="
				<< trd_len_cpy << " time_cost=" << ti << " miliseconds\n";
			t.stop_timer();

			first_len_cpy *= trd_len_cpy;
			snd_len_cpy *= trd_len_cpy;

			first_len_cpy += snd_len_cpy;

			t.stop_timer();
			seckey.decrypt(ctxt1);

			ti = t.stop_timer();
			f << "decrypting len=" << first_len_cpy << " in time_cost=" << ti << " miliseconds\n";
		}

		f.flush();
	}
}


void only_perm_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\only_perm\\no_bitlen_only_perm_all_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Permutation perm(context);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			Ciphertext pctxt = ctxt.applyPermutation(perm);

			uint64_t ti = t.stop_timer();

			f << "permuting len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
	}
}


void only_cpy_test_time(const int test_count, const int C_MAX_LEN) {

	std::fstream f;
	f.open(STATS_PATH + "\\only_cpy\\stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Timervar t;
		t.start_timer();

		Plaintext paux(1);
		Ciphertext caux = sk.encrypt(paux);

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			caux += caux;

			t.stop_timer();

			Ciphertext caux_c;
			caux_c = caux;

			Ciphertext caux_c2(caux);

			uint64_t ti = t.stop_timer();

			f << "copy and assignment with len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
	}
}


void conditional_multithreading_cpy_test_time(const int test_count, const int MAX_L) {

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_cpy\\aabwith_threshold_all_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST " << 0 << "\n";

		Plaintext paux(1);
		Ciphertext caux = sk.encrypt(paux);

		for (int i = 1; i < 16; i *= 2)
			caux += caux;

		Timervar t;
		t.start_timer();

		MTValues::cpy_m_threshold = 0;

		for (int l = 16; l < MAX_L; l *= 2) {

			t.stop_timer();

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext caux_c;
				caux_c = caux;

				Ciphertext caux_c2(caux);
			}

			uint64_t ti2 = t.stop_timer();

			f << "copy and assignment with len=" << l << " time_cost=" << ti2 << '\n';

			caux += caux;
		}
		f.flush();

		f << "TEST " << 1000000000 << "\n";

		caux = sk.encrypt(paux);

		for (int i = 1; i < 16; i *= 2)
			caux += caux;

		t.stop_timer();

		MTValues::cpy_m_threshold = 1000000000;

		for (int l = 16; l < MAX_L; l *= 2) {

			t.stop_timer();

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext caux_c;
				caux_c = caux;

				Ciphertext caux_c2(caux);
			}

			uint64_t ti2 = t.stop_timer();

			f << "copy and assignment with len=" << l << " time_cost=" << ti2 << '\n';

			caux += caux;
		}
		f.flush();
	}
}

void only_cpy_autoselect_test_time(const int test_count, const int C_MAX_LEN) {

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_cpy\\autoselect_sequential_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::cpy_m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Timervar t;
		t.start_timer();

		Plaintext paux(1);
		Ciphertext caux = sk.encrypt(paux);

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			caux += caux;

			t.stop_timer();

			for (int rnd = 0; rnd < 200; rnd++) {

				Ciphertext caux_c;
				caux_c = caux;

				Ciphertext caux_c2(caux);
			}
			
			uint64_t ti = t.stop_timer();

			f << "copy and assignment with len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
		f.flush();
	}
}

void only_dec_autoselect_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_dec\\no_autoselect_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	//MTValues::dec_m_threshold_autoselect(context);
	MTValues::dec_m_threshold = 0;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			for(int rnd = 0; rnd < 200; rnd++)
				sk.decrypt(ctxt);

			uint64_t ti = t.stop_timer();

			f << "decrypting len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
	}
}

void only_mul_autoselect_test_time(const int test_count, const int FIRST_LEN = 3, 
									const int SECOND_LEN = 5, const int MUL_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_mul\\no_autoselect_sequential_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	//MTValues::mul_m_threshold_autoselect(context);
	MTValues::mul_m_threshold = -1;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;

		Timervar t;

		t.start_timer();

		Ciphertext ctxt1;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		Ciphertext ctxt2;

		for (int i = 0; i < snd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt2 = c;
			else
				ctxt2 += c;
		}

		for (int i = 0; i < MUL_CNT; i++) {

			uint64_t acc = 0;

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext aux_c(ctxt1);

				t.stop_timer();

				aux_c *= ctxt2;

				acc += t.stop_timer();
			}

			ctxt1 *= ctxt2;

			f << "mul between len1=" << first_len_cpy << " and len2=" << snd_len_cpy << " time_cost="
				<< acc << " miliseconds\n";

			first_len_cpy *= snd_len_cpy;
		}

		f.flush();
	}

}

void only_add_autoselect_test_time(const int test_count, const int FIRST_LEN = 3, const int ADD_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_add\\autoselect_pow4_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	MTValues::add_m_threshold_autoselect(context);
	std::cout << MTValues::add_m_threshold << '\n';
	//MTValues::add_m_threshold = -1;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		int first_len_cpy = FIRST_LEN;

		Timervar t;

		t.start_timer();

		Ciphertext ctxt1;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		for (int i = 0; i < ADD_CNT; i++) {

			uint64_t acc = 0;

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext aux_c(ctxt1);

				t.stop_timer();

				aux_c += ctxt1;

				acc += t.stop_timer();
			}

			ctxt1 += ctxt1;

			f << "add between len1=" << first_len_cpy << " and len2=" << first_len_cpy << " time_cost="
				<< acc << " miliseconds\n";

			first_len_cpy *= 2;
		}

		f.flush();
	}

}

void only_perm_autoselect_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\conditional_multithreading\\for_perm\\no_autoselect_sequential_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);


	//MTValues::perm_m_threshold_autoselect(context);
	MTValues::perm_m_threshold = -1;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Permutation perm(context);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			uint64_t acc = 0;

			for (int rnd = 0; rnd < 200; rnd++) {

				Ciphertext aux_c(ctxt);

				t.stop_timer();

				aux_c.applyPermutation_inplace(perm);

				acc += t.stop_timer();
			}

			f << "permuting len=" << i << " in time_cost=" << acc << " miliseconds\n";
		}
	}
}

void all_autoselect_calc_test_time() {

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::m_threshold_autoselect(context);

	std::cout << MTValues::cpy_m_threshold << " "
		<< MTValues::dec_m_threshold << " "
		<< MTValues::mul_m_threshold << " "
		<< MTValues::add_m_threshold << " "
		<< MTValues::perm_m_threshold << " ";
}

void only_mul_test_time(const int test_count, const int FIRST_LEN = 3,
							const int SECOND_LEN = 5, const int MUL_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\for_mul\\release_optimizations\\no_intrinsics_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;

		Timervar t;

		t.start_timer();

		Ciphertext ctxt1;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		Ciphertext ctxt2;

		for (int i = 0; i < snd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt2 = c;
			else
				ctxt2 += c;
		}

		for (int i = 0; i < MUL_CNT; i++) {

			uint64_t acc = 0;

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext aux_c(ctxt1);

				t.stop_timer();

				aux_c *= ctxt2;

				uint64_t tt = t.stop_timer();
				acc += tt;
			}

			ctxt1 *= ctxt2;

			f << "mul between len1=" << first_len_cpy << " and len2=" << snd_len_cpy << " time_cost="
				<< acc << " miliseconds\n";

			first_len_cpy *= snd_len_cpy;
		}

		f.flush();
	}

}

void only_add_test_time(const int test_count, const int FIRST_LEN = 3, const int ADD_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\for_add\\release_optimizations\\no_intrinsics_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		int first_len_cpy = FIRST_LEN;

		Timervar t;

		t.start_timer();

		Ciphertext ctxt1;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		for (int i = 0; i < ADD_CNT; i++) {

			uint64_t acc = 0;

			t.stop_timer();

			ctxt1 += ctxt1;

			acc += t.stop_timer();

			f << "add between len1=" << first_len_cpy << " and len2=" << first_len_cpy << " time_cost="
				<< acc << " miliseconds\n";

			first_len_cpy *= 2;
		}

		f.flush();
	}

}

void intrinsic_fullop_test_time(const int test_count, const int FIRST_LEN = 15, const int SECOND_LEN = 25,
								const int THIRD_LEN = 2, const int ROUND_CNT = 5) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\full_op\\move_added\\debug_no_bextr_full_intrinsics_stats.txt", std::fstream::out | std::fstream::app);

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey seckey(context);

	Permutation perm(context);
	SecretKey perm_seckey = seckey.applyPermutation(perm);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;
		int trd_len_cpy = THIRD_LEN;

		Timervar t;

		t.start_timer();

		uint64_t ti = t.stop_timer();
		f << "TEST\n";
		t.stop_timer();

		Ciphertext ctxt1, ctxt2, ctxt3;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		for (int i = 0; i < snd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt2 = c;
			else
				ctxt2 += c;
		}

		for (int i = 0; i < trd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt3 = c;
			else
				ctxt3 += c;
		}

		t.stop_timer();

		for (int i = 0; i < ROUND_CNT; i++) {

			ctxt1 *= ctxt3;
			ctxt2 = ctxt2 * ctxt3;

			Ciphertext ctxt5;
			ctxt5 = ctxt1;

			ctxt5 = ctxt5 + ctxt2;

			Ciphertext ctxt_perm = ctxt5.applyPermutation(perm);
			Plaintext ptxt = perm_seckey.decrypt(ctxt_perm);

			ctxt1 += ctxt2;

			uint64_t ti = t.stop_timer();
			f << "round with len1=" << first_len_cpy << " len2=" << snd_len_cpy << " len3="
				<< trd_len_cpy << " time_cost=" << ti << " miliseconds\n";
			t.stop_timer();

			first_len_cpy *= trd_len_cpy;
			snd_len_cpy *= trd_len_cpy;

			first_len_cpy += snd_len_cpy;
		}

		f.flush();
	}
}

void intrinsics_add_mul_cpy_test_time(const int test_count, const int FIRST_LEN = 15, const int SECOND_LEN = 25,
										const int THIRD_LEN = 2, const int ROUND_CNT = 5) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\release_stats.txt", std::fstream::out | std::fstream::app);

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey seckey(context);

	Permutation perm(context);
	SecretKey perm_seckey = seckey.applyPermutation(perm);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;
		int trd_len_cpy = THIRD_LEN;

		Timervar t;

		t.start_timer();

		uint64_t ti = t.stop_timer();
		f << "TEST\n";
		t.stop_timer();

		Ciphertext ctxt1, ctxt2, ctxt3;

		for (int i = 0; i < first_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt1 = c;
			else
				ctxt1 += c;
		}

		for (int i = 0; i < snd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt2 = c;
			else
				ctxt2 += c;
		}

		for (int i = 0; i < trd_len_cpy; i++) {

			Plaintext p(rand() % 2);
			Ciphertext c = seckey.encrypt(p);

			if (i == 0)
				ctxt3 = c;
			else
				ctxt3 += c;
		}

		t.stop_timer();

		for (int i = 0; i < ROUND_CNT; i++) {

			ctxt1 *= ctxt3;
			ctxt2 = ctxt2 * ctxt3;

			Ciphertext ctxt5;
			ctxt5 = ctxt1;

			ctxt5 = ctxt5 + ctxt2;

			ctxt1 += ctxt2;

			uint64_t ti = t.stop_timer();
			f << "round with len1=" << first_len_cpy << " len2=" << snd_len_cpy << " len3="
				<< trd_len_cpy << " time_cost=" << ti << " miliseconds\n";
			t.stop_timer();

			first_len_cpy *= trd_len_cpy;
			snd_len_cpy *= trd_len_cpy;

			first_len_cpy += snd_len_cpy;
		}

		f.flush();
	}
}

void only_dec_intrinsics_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\for_dec\\release_optimizations\\mask_onspot_load_intrinsics_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::m_threshold_autoselect(context);
	//MTValues::dec_m_threshold = 0;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			for (int rnd = 0; rnd < 200; rnd++)
				sk.decrypt(ctxt);

			uint64_t ti = t.stop_timer();

			f << "decrypting len=" << i << " in time_cost=" << ti << " miliseconds\n";
		}
		f.flush();
	}
}

void only_perm_intrinsics_test_time(const int test_count, const int C_MAX_LEN) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\for_perm\\release_perm_intrinsics_added_invs_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::m_threshold_autoselect(context);

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		Plaintext p(rand() % 2);
		Ciphertext ctxt = sk.encrypt(p);

		Permutation perm(context);

		Timervar t;
		t.start_timer();

		for (int i = 2; i <= C_MAX_LEN; i *= 2) {

			ctxt += ctxt;

			t.stop_timer();

			uint64_t acc = 0;

			for (int rnd = 0; rnd < 100; rnd++) {

				Ciphertext aux_c(ctxt);

				t.stop_timer();

				aux_c.applyPermutation_inplace(perm);

				acc += t.stop_timer();
			}

			f << "permuting len=" << i << " in time_cost=" << acc << " miliseconds\n";
		}
		f.flush();
	}
}

void shift_vs_mul_test_time(const int test_count) {

	Timervar t;
	t.start_timer();

	double mul_cnt = 0;
	double shift_cnt = 0;

	uint64_t var1 = 182389243239;
	uint64_t var2 = 318912480321110;
	
	for (int i = 0; i < test_count; i++) {

		var1 = 18238924312239 + rand();
		var2 = 31821110 - rand();

		t.stop_timer();

		var1 >>= 16;
		var2 <<= 6;

		double te = t.stop_timer();
		shift_cnt += te;
	}

	for (int i = 0; i < test_count; i++) {

		var1 = 18238924312239;
		var2 = 31821110;

		t.stop_timer();

		var1 /= 12312;
		var2 *= 242;

		double te = t.stop_timer();
		mul_cnt += te;
	}
	
	std::cout << "shift " << shift_cnt << " mul " << mul_cnt << '\n';
	
}

void test_dag_implem_time(const int TEST_COUNT = 20, const int ROUND_CNT = 100) {

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey sk(context);

	Timervar t;
	t.start_timer();

	std::fstream f;
	f.open(STATS_PATH + "\\DAG_implementation\\with_shortening_when_merging_stats.txt", std::fstream::out | std::fstream::app);

	Plaintext p0(0);
	Plaintext p1(1);

	int med_acc = 0;

	for (int ts = 0; ts < TEST_COUNT; ts++) {

		//f << "TEST\n";

		uint64_t acc = 0;

		Ciphertext c1(p1, sk);
		Ciphertext c0(p0, sk);

		int realval1 = 1;
		int realval0 = 0;

		int rndcnt = ROUND_CNT;
		for (int r = 0; r < rndcnt; r++) {

			Ciphertext caux1 = sk.encrypt(p1);

			t.stop_timer();

			c1 += caux1;

			int a = t.stop_timer();
			acc += a;

			realval1 ^= 1;
		}
		for (int r = 0; r < rndcnt; r++) {

			int opc = rand() % 3;

			if (opc == 0) {

				Ciphertext caux1(p1, sk);
				Ciphertext caux0(p0, sk);

				int realval0aux = 0;
				int jj = rand() % 4;

				for (int j = 0; j < jj; j++) {

					t.stop_timer();

					caux0 = caux0 + caux1;

					int a = t.stop_timer();
					acc += a;

					realval0aux ^= 1;
				}

				c1 += caux0;
				realval1 ^= realval0aux;
			}
			else if (opc == 1) {

				t.stop_timer();

				c0 += c1;

				int a = t.stop_timer();
				acc += a;

				realval0 ^= realval1;
			}
			else if (opc == 2) {

				Ciphertext caux1 = sk.encrypt(p1);

				t.stop_timer();

				c1 += caux1;
				c0 += caux1;

				int a = t.stop_timer();
				acc += a;

				realval1 ^= 1;
				realval0 ^= 1;
			}
		}

		//f << "time=" << acc << '\n';
		//f.flush();

		med_acc += acc;

		if (realval1 != (sk.decrypt(c1).getValue() && 0x01))
			std::cout << realval1 << " " << (sk.decrypt(c1).getValue() && 0x01) << '\n';

		if (realval0 != (sk.decrypt(c0).getValue() && 0x01))
			std::cout << realval0 << " " << (sk.decrypt(c0).getValue() && 0x01) << '\n';

		//std::cout << "\nTEST " << ts << " DONE\n\n";
	}

	f << "MED TEST\ntime=" << med_acc / TEST_COUNT;

	std::cout << "\nTESTS DONE\n\n";
}

void test_res_correct_noperm() {

	Timervar t;

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey sk(context);

	MTValues::m_threshold_autoselect(context);

	const int TEST_COUNT = 100; // sansa fals pozitiv: 2^(-TEST_COUNT)

	t.start_timer();

	for (int tst = 0; tst < TEST_COUNT; tst++) {  // decriptare deflen

		int r = rand() % 2;
		Plaintext p(r);

		Ciphertext c = sk.encrypt(p);

		if (r != (sk.decrypt(c).getValue() & 0x01))
			std::cout << "DEFLEN DECRYPTION FAIL " << r << " " << (sk.decrypt(c).getValue() & 0x01) << '\n';
	}

	for (int tst = 0; tst < TEST_COUNT; tst++) {  // copiere lungime > deflen, adunare, decriptare

		Plaintext paux(1);
		int pauxn = 1;
		Ciphertext caux = sk.encrypt(paux);

		for (int i = 0; i < 100; i++) {

			int r = rand() % 2;
			Plaintext p(r);

			Ciphertext c = sk.encrypt(p);
			caux += c;

			pauxn ^= r;
		}

		Ciphertext caux_c = caux;

		Ciphertext caux_c2(caux);

		if (((sk.decrypt(caux).getValue() & 0x01) != pauxn) ||
			((sk.decrypt(caux_c).getValue() & 0x01) != pauxn) ||
			((sk.decrypt(caux_c2).getValue() & 0x01) != pauxn))

			std::cout << "COPY FAIL\n";
	}

	for (int tst = 0; tst < TEST_COUNT; tst++) { // adunare, inmultire, permutare, decriptare

		Plaintext p0(0);
		Plaintext p1(1);

		Ciphertext c0 = sk.encrypt(p0);
		Ciphertext c1 = sk.encrypt(p1);

		int c00 = 0;
		int c11 = 1;

		for (int i = 0; i < 1000; i++) {

			int r = rand() % 2;
			c00 += r;
			c00 %= 2;

			Plaintext p(r);
			Ciphertext c = sk.encrypt(p);

			c0 += c;
		}

		for (int i = 0; i < 17; i++) {

			int r = rand() % 2;
			c11 += r;
			c11 %= 2;

			Plaintext p(r);
			Ciphertext c = sk.encrypt(p);

			c1 += c;
		}

		c1 *= c0;
		c11 *= c00;

		if ((((sk.decrypt(c0).getValue() & 0x01) == c00) && ((sk.decrypt(c1).getValue() & 0x01) == c11)) == false)
			std::cout << "ADDITION / MULTIPLICATION FAIL \n";
		//else
			//std::cout << "OK\n";

	}
	std::cout << "\nTESTS DONE " << t.stop_timer() << "\n\n";
}

int main2(){

	{
		//only_mul_test_time(25, 3, 2, 22);

		//mul_add_test_time(20, 15, 25, 2, 15);

		//test_res_correct();

		//only_dec_test_time(20, 1000000);

		//dec_mul_add_test_time(10, 15, 25, 2, 14);

		//only_perm_test_time(10, 100000);

		//only_cpy_test_time(10, 1000000);

		//conditional_multithreading_cpy_test_time(5, 100000);

		//only_cpy_autoselect_test_time(10, 100000);

		//only_dec_autoselect_test_time(10, 100000);

		//only_mul_autoselect_test_time(10, 3, 2, 18);

		//only_add_autoselect_test_time(10, 3, 18);

		//only_perm_autoselect_test_time(10, 1000);

		//all_autoselect_calc_test_time();
	}

	{	
		//only_mul_test_time(10, 3, 2, 18);

		//only_add_test_time(10, 5, 23);

		//intrinsic_fullop_test_time(5, 15, 25, 2, 11);

		//intrinsics_add_mul_cpy_test_time(4, 15, 25, 2, 15);

		//only_dec_intrinsics_test_time(20, 1000000);

		//only_perm_intrinsics_test_time(6, 5000);
	}

	//shift_vs_mul_test_time(100000);

	{
		//test_dag_implem_time(200, 400);
		//test_res_correct_noperm();

		//dec_mul_add_test_time(10, 15, 25, 2, 14);
	}

    return 0;
}
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

static string STATS_PATH = "C:\\Users\\intern.andreis\\Desktop\\certfhe_stats\\certfhe_nobitlen_stats";

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

/*
 * test to check if operations are implemented correctly
*/
void test_res_correct() {

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey sk(context);

	MTValues::dec_m_threshold_autoselect(context);

	const int TEST_COUNT = 10; // sansa fals pozition: 2^(-TEST_COUNT)

	for (int tst = 0; tst < TEST_COUNT; tst++) {  // decriptare deflen

		int r = rand() % 2;
		Plaintext p(r);

		Ciphertext c = sk.encrypt(p);

		if (r != sk.decrypt(c).getValue() & 0x01)
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

		if ((sk.decrypt(caux).getValue() & 0x01 != pauxn) || 
			(sk.decrypt(caux_c).getValue() & 0x01 != pauxn) ||
			(sk.decrypt(caux_c2).getValue() & 0x01 != pauxn))

			std::cout << "COPY FAIL\n";
	}

	for (int tst = 0; tst < TEST_COUNT; tst++) { // adunare, inmultire, permutare, decriptare

		Plaintext p0(0);
		Plaintext p1(1);

		Ciphertext c0 = sk.encrypt(p0);
		Ciphertext c1 = sk.encrypt(p1);

		int c00 = 0;
		int c11 = 1;

		for (int i = 0; i < 100; i++) {

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

/*
 * Relevant only for multithreading decryption testing
*/
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

/*
 * Relevant for multithreading decryption, addition and multiplication testing
*/
void dec_mul_add_test_time(const int test_count, const int FIRST_LEN = 15, const int SECOND_LEN = 25,
	const int THIRD_LEN = 2, const int ROUND_CNT = 5) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\no_bitlen_all_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

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
			ctxt2 *= ctxt3;

			ctxt1 += ctxt2;

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

/*
 * Relevant only for permutation testing
*/
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

/*
 * Relevant only for copying testing
*/
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

/*
 * Relevant for testing multithreading with threshold
*/
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

void only_mul_autoselect_test_time(const int test_count, const int FIRST_LEN = 3, const int SECOND_LEN = 5, const int MUL_CNT = 10) {

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

void only_add_autoselect_test_time(const int test_count, const int FIRST_LEN = 3, const int MUL_CNT = 10) {

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

		for (int i = 0; i < MUL_CNT; i++) {

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

			f << "decrypting len=" << i << " in time_cost=" << acc << " miliseconds\n";
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

void perm_generator_autoselect_test_time(const int test_count, const int MAX_PERM_SIZE) {

	std::fstream f;
	f.open(STATS_PATH + "\\perm_gen_stats\\steps_stats.txt", std::fstream::out | std::fstream::app);

	PMValues::perm_gen_threshold_autoselect();
	//std::cout << PMValues::perm_gen_threshold << '\n';
	//PMValues::perm_gen_threshold = 0;
	//PMValues::perm_gen_threshold = -1;

	for (int ts = 0; ts < test_count; ts++) {

		f << "TEST\n";

		for (int perm_size = 2; perm_size < MAX_PERM_SIZE; perm_size *= 1.5) {

			uint64_t acc;

			Timervar t;
			t.start_timer();

			for (int rnd = 0; rnd < 10000; rnd++) 
				Permutation p(perm_size);

			acc = t.stop_timer();

			f << "perm gen len=" << perm_size << " time_cost=" << acc << '\n';
		}

		f.flush();
	}
}

int main(){

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

	//perm_generator_autoselect_test_time(2, 256);

	PMValues::inv_factor_stats(50000, 101, 51);

    return 0;
}
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

static string STATS_PATH = "C:\\Users\\intern.andreis\\Desktop\\certfhe_stats";

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

	for (int tst = 0; tst < 1000; tst++) {

		Plaintext p0(0);
		Plaintext p1(1);

		Ciphertext c0 = sk.encrypt(p0);
		Ciphertext c1 = sk.encrypt(p1);

		int c00 = 0;
		int c11 = 1;

		if ((((sk.decrypt(c0).getValue() & 0x01) == c00) && ((sk.decrypt(c1).getValue() & 0x01) == c11)) == false)
			std::cout << "INITIALIZE FAIL\n";

		for (int i = 0; i < 10; i++) {

			int r = rand() % 2;
			c00 += r;
			c00 %= 2;

			Plaintext p(r);
			Ciphertext c = sk.encrypt(p);

			c0 += c;
		}

		for (int i = 0; i < 10; i++) {

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
			std::cout << "FAIL\n";
		//else
			//std::cout << "OK\n";

	}
	std::cout << "done";
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

		for (int i = 1; i < C_MAX_LEN; i *= 2) {

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
	f.open(STATS_PATH + "\\add_mul_decr_multithreading_stats\\all_ops\\all_multithreading_stats.txt", std::fstream::out | std::fstream::app);

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
 * Relevant only for multithreading addition and multiplication testing
*/
void mul_add_test_time(const int test_count, const int FIRST_LEN = 15, const int SECOND_LEN = 25,
						const int THIRD_LEN = 2, const int ROUND_CNT = 5) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\add_mul_multithreading_stats\\mul_add_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
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
		}

		f.flush();
	}

	certFHE::Library::getThreadpool()->close();
}

/*
 * Relevant only for multiplication multithreading testing
*/
void only_mul_test_time(const int test_count, const int FIRST_LEN = 3, const int SECOND_LEN = 5, const int MUL_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\only_multiplication_multithreading_stats\\multiplication_multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary(true);
	certFHE::Context context(1247, 16);
	certFHE::SecretKey seckey(context);

	for (int ts = 0; ts < test_count; ts++) {

		int first_len_cpy = FIRST_LEN;
		int snd_len_cpy = SECOND_LEN;

		Timervar t;

		t.start_timer();

		//std::cout << context.getDefaultN();

		uint64_t ti = t.stop_timer();
		f << "TEST\nafter init context and key init_time=" << ti << " miliseconds\n";
		t.stop_timer();

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

		t.stop_timer();

		for (int i = 0; i < MUL_CNT; i++) {

			ctxt1 *= ctxt2;

			uint64_t ti = t.stop_timer();
			f << "mul between len1=" << first_len_cpy << " and len2=" << snd_len_cpy << " time_cost="
				<< ti << " miliseconds\n";
			t.stop_timer();

			first_len_cpy *= snd_len_cpy;
		}

		f.flush();
	}

	certFHE::Library::getThreadpool()->close();
}

int main(){

	//only_mul_test_time(25, 3, 2, 22);

	//mul_add_test_time(20, 15, 25, 2, 15);

	//test_res_correct();

	//only_dec_test_time(20, 1000000);

	//dec_mul_add_test_time(10, 15, 25, 2, 12);

    return 0;
}
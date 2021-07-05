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

void test_time(const int test_count, const int FIRST_LEN = 3, const int SECOND_LEN = 5, const int MUL_CNT = 10) {

	Timervar t;

	std::fstream f;
	f.open(STATS_PATH + "\\multithreading_stats.txt", std::fstream::out | std::fstream::app);

	certFHE::Library::initializeLibrary();
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

	certFHE::Library::getMulThreadpool()->close();
}

int main(){

    test_time(25, 3, 2, 22);

    return 0;
}
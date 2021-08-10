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
#include "Threadpool.h"
#include "./old_implementation/certFHE_old.h"

static std::string STATS_PATH = "C:\\Users\\intern.andreis\\Desktop\\certfhe_stats\\tests";

void array_ctxt_test(const std::vector <int> randoms,
	const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16,
	std::ostream & out = std::cout,
	std::ostream & out_old = std::cout,
	bool execute_old_test = true) {

	/**
	 * Addition and multiplication applied to ctxts of different sizes
	 * All of them being single CCC objects
	**/

	// current implementation stats
	{	
		try {
				
			certFHE::Timer timer;
			int randindex = 0; // for randoms

			const char * TIME_MEASURE_UNIT = " miliseconds";

			out << "Starting...";
			out.flush();

			timer.start();

			certFHE::Library::initializeLibrary();
			certFHE::Context context(CONTEXT_N, CONTEXT_D);
			certFHE::SecretKey sk(context);

			certFHE::Permutation perm(context);
			certFHE::SecretKey psk = sk.applyPermutation(perm);

			// declared here to force compiler to use it and not remove it
			// when doing optimisations
			certFHE::Ciphertext temp;

			out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			out << "Multithreading thresholds autoselection...";
			out.flush();

			timer.start();

			certFHE::MTValues::m_threshold_autoselect(context, false);

			/*std::cout << certFHE::MTValues::add_m_threshold << " "
				<< certFHE::MTValues::mul_m_threshold << " "
				<< certFHE::MTValues::dec_m_threshold << " "
				<< certFHE::MTValues::perm_m_threshold << "\n\n";*/

			out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			/****** TEST CODE SHOULD BE CHANGED IF THOSE CONSTANT ARE CHANGED ******/
			const int S_CNT = 8;
			const int CS_CNT = 2;

			const int ctxt_starting_sizes[S_CNT] = { 1, 5, 10, 50, 100, 200, 500, 1000 };
			const int rounds_per_epoch[S_CNT] = { ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 6, ROUNDS_PER_TEST / 6,
													ROUNDS_PER_TEST / 6, ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 10,
													ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 10 };

			bool old_remove_duplicates_onadd = certFHE::OPValues::remove_duplicates_onadd;
			bool old_remove_duplicates_onmul = certFHE::OPValues::remove_duplicates_onmul;

			certFHE::OPValues::remove_duplicates_onadd = false;
			certFHE::OPValues::remove_duplicates_onmul = false;

			int val[CS_CNT];
			certFHE::Ciphertext ** cs;
			cs = new certFHE::Ciphertext *[CS_CNT];

			out << "Starting tests:\n\n";
			out.flush();

			for (int ts = 0; ts < TEST_COUNT; ts++) {

				try {

					out << "TEST " << ts << ":\n";
					out.flush();

					for (int epoch = 0; epoch < S_CNT; epoch++) {

						for (int i = 0; i < CS_CNT; i++) {

							int r = randoms[randindex];
							randindex += 1;

							certFHE::Plaintext p(r);
							val[i] = r;

							cs[i] = new certFHE::Ciphertext();
							*cs[i] = sk.encrypt(p);

							// even though there are already performed addition operations
							// they are not measured
							for (int s = 1; s < ctxt_starting_sizes[epoch]; s++) {

								int r = randoms[randindex];
								randindex += 1;

								certFHE::Plaintext p(r);
								val[i] ^= r;

								*cs[i] += sk.encrypt(p);
							}
						}

						double average_time = 0;
						double t_acc = 0;
						double t;

						for (int rnd = 0; rnd < rounds_per_epoch[epoch] / 2; rnd++) {

							timer.start();

							temp = *cs[0] + *cs[1];

							t = timer.stop();
							timer.reset();

							t_acc += t;
						}

						out << "Addition average time " << t_acc / (rounds_per_epoch[epoch] / 2) << TIME_MEASURE_UNIT
							<< " for both ctxt of len " << ctxt_starting_sizes[epoch] << '\n';

						average_time = 0;
						t_acc = 0;
						t;

						for (int rnd = 0; rnd < rounds_per_epoch[epoch] / 2; rnd++) {

							timer.start();

							temp = *cs[0] * *cs[1];

							t = timer.stop();
							timer.reset();

							t_acc += t;
						}

						out << "Multiplication average time " << t_acc / (rounds_per_epoch[epoch] / 2) << TIME_MEASURE_UNIT
							<< " for both ctxt of len " << ctxt_starting_sizes[epoch] << '\n';
						out << '\n';
					}

					for (int c = 0; c < CS_CNT; c++)
						delete cs[c];

					out << "TEST " << ts << " DONE\n\n";
					out.flush();
				}
				catch (std::exception e) {

					out << "ERROR: " << e.what() << '\n';
				}

			}

			certFHE::OPValues::remove_duplicates_onadd = old_remove_duplicates_onadd;
			certFHE::OPValues::remove_duplicates_onmul = old_remove_duplicates_onmul;

		}
		catch (std::exception & err) {

			out << "ERROR running current implementation tests: " << err.what() << '\n';
		}
	}

	// original implementation stats
	if(execute_old_test) {

		try {

			certFHE_old::Timer timer;
			int randindex = 0; // for randoms

			const char * TIME_MEASURE_UNIT = " miliseconds";

			out_old << "Starting...";
			out_old.flush();

			timer.start();

			certFHE_old::Library::initializeLibrary();
			certFHE_old::Context context(CONTEXT_N, CONTEXT_D);
			certFHE_old::SecretKey sk(context);

			certFHE_old::Permutation perm(context);
			certFHE_old::SecretKey psk = sk.applyPermutation(perm);

			// declared here to force compiler to use it and not remove it
			// when doing optimisations
			certFHE_old::Ciphertext temp;

			out_old << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			/****** TEST CODE SHOULD BE CHANGED IF THOSE CONSTANT ARE CHANGED ******/
			const int S_CNT = 8;
			const int CS_CNT = 2;

			const int ctxt_starting_sizes[S_CNT] = { 1, 5, 10, 50, 100, 200, 500, 1000 };
			const int rounds_per_epoch[S_CNT] = { ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 6, ROUNDS_PER_TEST / 6,
													ROUNDS_PER_TEST / 6, ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 10,
													ROUNDS_PER_TEST / 10, ROUNDS_PER_TEST / 10 };

			int val[CS_CNT];
			certFHE_old::Ciphertext ** cs;
			cs = new certFHE_old::Ciphertext *[CS_CNT];

			out_old << "Starting tests:\n\n";
			out_old.flush();

			for (int ts = 0; ts < TEST_COUNT; ts++) {

				try {

					out_old << "TEST " << ts << ":\n";
					out_old.flush();

					for (int epoch = 0; epoch < S_CNT; epoch++) {

						for (int i = 0; i < CS_CNT; i++) {

							int r = randoms[randindex];
							randindex += 1;

							certFHE_old::Plaintext p(r);
							val[i] = r;

							cs[i] = new certFHE_old::Ciphertext();
							*cs[i] = sk.encrypt(p);

							// even though there are already performed addition operations
							// they are not measured
							for (int s = 1; s < ctxt_starting_sizes[epoch]; s++) {

								int r = randoms[randindex];
								randindex += 1;

								certFHE_old::Plaintext p(r);
								val[i] ^= r;

								*cs[i] += sk.encrypt(p);
							}
						}

						double average_time = 0;
						double t_acc = 0;
						double t;

						for (int rnd = 0; rnd < rounds_per_epoch[epoch] / 2; rnd++) {

							timer.start();

							temp = *cs[0] + *cs[1];

							t = timer.stop();
							timer.reset();

							t_acc += t;
						}

						out_old << "Addition average time " << t_acc / (rounds_per_epoch[epoch] / 2) << TIME_MEASURE_UNIT
							<< " for both ctxt of len " << ctxt_starting_sizes[epoch] << '\n';

						average_time = 0;
						t_acc = 0;
						t;

						for (int rnd = 0; rnd < rounds_per_epoch[epoch] / 2; rnd++) {

							timer.start();

							temp = *cs[0] * *cs[1];

							t = timer.stop();
							timer.reset();

							t_acc += t;
						}

						out_old << "Multiplication average time " << t_acc / (rounds_per_epoch[epoch] / 2) << TIME_MEASURE_UNIT
							<< " for both ctxt of len " << ctxt_starting_sizes[epoch] << '\n';
						out_old << '\n';
					}

					for (int c = 0; c < CS_CNT; c++)
						delete cs[c];

					out_old << "TEST " << ts << " DONE\n\n";
					out_old.flush();
				}
				catch (std::exception e) {

					out_old << "ERROR: " << e.what() << '\n';
				}

			}

		}
		catch (std::exception & err) {

			out_old << "ERROR running initial implementation tests: " << err.what() << '\n';
		}
	}
}

void array_ctxt_test(std::string randoms_file_source,
	const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16,
	std::ostream & out = std::cout,
	std::ostream & out_old = std::cout,
	bool execute_old_test = true) {

	std::vector <int> randoms;

	if (randoms_file_source == "")

		for (int i = 0; i < TEST_COUNT * ROUNDS_PER_TEST * 10 + 100; i++)
			randoms.push_back(rand());

	else {

		std::fstream randsource(randoms_file_source, std::ios::in | std::ios::binary);

		if (!randsource.is_open()) {

			std::fstream new_randsource(randoms_file_source, std::ios::out | std::ios::binary);

			int tmp;
			for (int i = 0; i < TEST_COUNT * ROUNDS_PER_TEST * 10 + 100; i++) {

				tmp = rand();

				randoms.push_back(tmp);
				new_randsource.write((char *)&tmp, sizeof(int));
			}

			new_randsource.close();
		}
		else {

			int tmp;
			for (int i = 0; i < TEST_COUNT * ROUNDS_PER_TEST * 10 + 100; i++) {

				randsource.read((char *)&tmp, sizeof(int));
				randoms.push_back(tmp);
			}

			randsource.close();
		}
	}

	array_ctxt_test(randoms,
		TEST_COUNT, ROUNDS_PER_TEST,
		CONTEXT_N, CONTEXT_D,
		out,
		out_old,
		execute_old_test);
}

void array_ctxt_predefined_test(std::string path = "\\array_ctxt_test\\release_stats",
								bool execute_old_test = true) {

	if (execute_old_test) {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);
		std::fstream log_old(STATS_PATH + path + "_old.txt", std::ios::out);

		array_ctxt_test("arrctxttestops.bin", 1, 1000, 1247, 16, log, log_old, true);

		log.close();
		log_old.close();
	}
	else {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);

		array_ctxt_test("arrctxttestops.bin", 1, 1000, 1247, 16, log, std::cout, false);

		log.close();
	}
}

void multiple_array_ctxt_predefined_tests(std::string path) {
	
	// changing OPValues parameters in current implementation

	bool exec_old_tests = true;

	uint64_t max_ccc_val_arr[] = { (uint64_t)512, (uint64_t)2048, (uint64_t)8192, (uint64_t)-1 };
	uint64_t max_cadd_merge_val_arr[] = { (uint64_t)512, (uint64_t)4096 * 4096, (uint64_t)-1 };
	uint64_t max_cmul_merge_val_arr[] = { (uint64_t)512, (uint64_t)4096 * 4096 * 4096, (uint64_t)-1 };
	bool always_def_mul_val_arr[] = { true, false };
	bool rem_dupl_val_arr[] = { true, false };
	bool shorten_on_rec_val_arr[] = { true, false };

	/*uint64_t max_ccc_val_arr[] = { (uint64_t)2048 };
	uint64_t max_cadd_merge_val_arr[] = { (uint64_t)4096 * 4096 };
	uint64_t max_cmul_merge_val_arr[] = { (uint64_t)4096 * 4096 * 4096 };
	bool always_def_mul_val_arr[] = { true };
	bool rem_dupl_val_arr[] = { true };
	bool shorten_on_rec_val_arr[] = { true };*/

	for (int i = 0; i < 4; i++) {

		certFHE::OPValues::max_ccc_deflen_size = max_ccc_val_arr[i];

		for (int j = 0; j < 3; j++) {

			certFHE::OPValues::max_cadd_merge_size = max_cadd_merge_val_arr[j];
			certFHE::OPValues::max_cmul_merge_size = max_cmul_merge_val_arr[j];

			for (int k = 0; k < 2; k++) {

				certFHE::OPValues::always_default_multiplication = always_def_mul_val_arr[k];

				for (int p = 0; p < 2; p++) {

					certFHE::OPValues::remove_duplicates_onadd = rem_dupl_val_arr[p];
					certFHE::OPValues::remove_duplicates_onmul = rem_dupl_val_arr[p];

					for (int q = 0; q < 2; q++) {

						certFHE::OPValues::shorten_on_recursive_cadd_merging = shorten_on_rec_val_arr[q];
						certFHE::OPValues::shorten_on_recursive_cmul_merging = shorten_on_rec_val_arr[q];

						char maxccc[21];
						sprintf_s(maxccc, 21, "%llu", certFHE::OPValues::max_ccc_deflen_size);

						char maxcaddm[21];
						sprintf_s(maxcaddm, 21, "%llu", certFHE::OPValues::max_cadd_merge_size);

						char maxcmulm[21];
						sprintf_s(maxcmulm, 21, "%llu", certFHE::OPValues::max_cmul_merge_size);

						char adefm[6];
						sprintf_s(adefm, 6, "%s", certFHE::OPValues::always_default_multiplication ? "true" : "false");

						char remdupl[6];
						sprintf_s(remdupl, 6, "%s", certFHE::OPValues::remove_duplicates_onadd ? "true" : "false");

						char shrec[6];
						sprintf_s(shrec, 6, "%s", certFHE::OPValues::shorten_on_recursive_cadd_merging ? "true" : "false");
						
						std::string path_tmp = path + "_" + maxccc + "_" + maxcaddm + "_" + maxcmulm
													+ "_" + adefm + "_" + remdupl + "_" + shrec;

						array_ctxt_predefined_test(path_tmp, exec_old_tests);

						exec_old_tests = false; // execute only once
					}

				}

			}
		}
	}
}

void average_thrfct_rndloaded_test(const std::vector <int> & randoms, int randindex,
	certFHE::SecretKey & sk, certFHE::Permutation & perm,
	certFHE::Ciphertext ** cs, int * val,
	std::ostream & out, std::mutex & out_mutex,
	const int ROUNDS_PER_THREAD,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	bool PERM = true) {

	out_mutex.lock();
	out << "Entered thread specific function, thread " << std::this_thread::get_id() << '\n';
	out.flush();
	out_mutex.unlock();

	const int rounds_per_epoch = ROUNDS_PER_THREAD / EPOCH_CNT;

	uint64_t pp;
	certFHE::Ciphertext temp;

	int OP_MODULUS = PERM ? 3 : 2;

	try {

		int max_index = CS_CNT;

		for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

			int i, j, k;

			for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

				int opc = randoms[randindex] % OP_MODULUS;
				randindex += 1;

				switch (opc) {

				case(0): // * between two random ctxt, += in the third

					i = randoms[randindex] % max_index;
					j = randoms[randindex + 1] % max_index;
					k = randoms[randindex + 2] % max_index;

					randindex += 3;

					*cs[k] += *cs[i] * *cs[j];
					
					val[k] ^= (val[i] & val[j]);

					break;

				case(1): // + between two random ctxt, *= in the third

					i = randoms[randindex] % max_index;
					j = randoms[randindex + 1] % max_index;
					k = randoms[randindex + 2] % max_index;

					randindex += 3;

					*cs[k] *= *cs[i] + *cs[j];

					val[k] &= (val[i] ^ val[j]);

					break;

				case(2): // permutation on a random ctxt

					i = randoms[randindex] % max_index;

					randindex += 1;

					temp = cs[i]->applyPermutation(perm);

					pp = sk.decrypt(*cs[i]).getValue() & 0x01;

					if (val[i] != pp) {

						out_mutex.lock();
						out << "WRONG decryption on permuted ctxt on thread " << std::this_thread::get_id()
							<< "; should be " << val[i] << ", decrypted " << pp << '\n';
						out.flush();
						out_mutex.unlock();
					}

					break;

				default:
					break;
				}
			}

			for (int pos = 0; pos < max_index; pos++) {

				uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

				if (p != val[pos]) {

					out_mutex.lock();
					out << "WRONG decryption on thread " << std::this_thread::get_id()
						<< "; should be " << val[pos] << ", decrypted " << p << '\n';
					out.flush();
					out_mutex.unlock();
				}
			}

			int to_delete_cnt = 0;
			if (DEL_FACTOR > 0)
				to_delete_cnt = max_index / DEL_FACTOR;

			for (int td = 0; td < to_delete_cnt; td++) {

				max_index -= 1;
				delete cs[max_index];
			}
		}

		for (int c_left = 0; c_left < max_index; c_left++)
			delete cs[c_left];

	}
	catch (std::exception e) {

		out << "ERROR on thread " << std::this_thread::get_id() << ": " << e.what() << '\n';
	}

	out_mutex.lock();
	out << "Thread " << std::this_thread::get_id() << " done\n";
	out.flush();
	out_mutex.unlock();
}

void average_thrfct_rndloaded_old_test(const std::vector <int> & randoms, int randindex,
	certFHE_old::SecretKey & sk, certFHE_old::Permutation & perm,
	certFHE_old::Ciphertext ** cs, int * val,
	std::ostream & out, std::mutex & out_mutex,
	const int ROUNDS_PER_THREAD,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	bool PERM = true) {

	out_mutex.lock();
	out << "Entered thread specific function, thread " << std::this_thread::get_id() << '\n';
	out.flush();
	out_mutex.unlock();

	const int rounds_per_epoch = ROUNDS_PER_THREAD / EPOCH_CNT;

	uint64_t pp;
	certFHE_old::Ciphertext temp;

	int OP_MODULUS = PERM ? 3 : 2;

	try {

		int max_index = CS_CNT;

		for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

			int i, j, k;

			for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

				int opc = randoms[randindex] % OP_MODULUS;
				randindex += 1;

				switch (opc) {

				case(0): // * between two random ctxt, += in the third

					i = randoms[randindex] % max_index;
					j = randoms[randindex + 1] % max_index;
					k = randoms[randindex + 2] % max_index;

					randindex += 3;

					*cs[k] += *cs[i] * *cs[j];

					val[k] ^= (val[i] & val[j]);

					break;

				case(1): // + between two random ctxt, *= in the third

					i = randoms[randindex] % max_index;
					j = randoms[randindex + 1] % max_index;
					k = randoms[randindex + 2] % max_index;

					randindex += 3;

					*cs[k] *= *cs[i] + *cs[j];

					val[k] &= (val[i] ^ val[j]);

					break;

				case(2): // permutation on a random ctxt

					i = randoms[randindex] % max_index;

					randindex += 1;

					temp = cs[i]->applyPermutation(perm);

					pp = sk.decrypt(*cs[i]).getValue() & 0x01;

					if (val[i] != pp) {

						out_mutex.lock();
						out << "WRONG decryption on permuted ctxt on thread " << std::this_thread::get_id()
							<< "; should be " << val[i] << ", decrypted " << pp << '\n';
						out.flush();
						out_mutex.unlock();
					}

					break;

				default:
					break;
				}
			}

			for (int pos = 0; pos < max_index; pos++) {

				uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

				if (p != val[pos]) {

					out_mutex.lock();
					out << "WRONG decryption on thread " << std::this_thread::get_id()
						<< "; should be " << val[pos] << ", decrypted " << p << '\n';
					out.flush();
					out_mutex.unlock();
				}
			}

			int to_delete_cnt = 0;
			if (DEL_FACTOR > 0)
				to_delete_cnt = max_index / DEL_FACTOR;

			for (int td = 0; td < to_delete_cnt; td++) {

				max_index -= 1;
				delete cs[max_index];
			}
		}

		for (int c_left = 0; c_left < max_index; c_left++)
			delete cs[c_left];

	}
	catch (std::exception e) {

		out << "ERROR on thread " << std::this_thread::get_id() << ": " << e.what() << '\n';
	}

	out_mutex.lock();
	out << "Thread " << std::this_thread::get_id() << " done\n";
	out.flush();
	out_mutex.unlock();
}

void average_rndloaded_test(const std::vector <int> randoms,
	const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000,
	const int ROUNDS_PER_THREAD = 40, const int THR_CNT = 11,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	std::ostream & out = std::cout, 
	std::ostream & out_old = std::cout, 
	bool PERM = true,
	bool execute_old_test = true) {

	// addition (+, +=), multiplication (*, *=), permutation inplace (only!)
	// 3 rounds of deletion, so that reference count is tested
	// decryption time measured only at the end of every epoch (3 times per test)

	// current implementation stats
	{	
		try {

			certFHE::Timer timer;
			int randindex = 0; // for randoms

			const char * TIME_MEASURE_UNIT = "miliseconds";

			out << ROUNDS_PER_TEST << " rounds per test, "
				<< ROUNDS_PER_THREAD << " rounds per thread, "
				<< CS_CNT << " ciphertexts, "
				<< EPOCH_CNT << " epochs per test, "
				<< DEL_FACTOR << " ciphertexts deleted per epoch factor\n\n";

			out << "Starting...";
			out.flush();

			timer.start();

			certFHE::Library::initializeLibrary();
			certFHE::Context context(CONTEXT_N, CONTEXT_D);
			certFHE::SecretKey sk(context);

			certFHE::Permutation perm(context);
			certFHE::SecretKey psk = sk.applyPermutation(perm);

			// declared here to force compiler to use it and not remove it
			// when doing optimisations
			certFHE::Ciphertext temp;

			out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			out << "Multithreading thresholds autoselection...";
			out.flush();

			timer.start();

			certFHE::MTValues::m_threshold_autoselect(context, false);

			out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			const int rounds_per_epoch = ROUNDS_PER_TEST / EPOCH_CNT;

			int * val = new int[CS_CNT];
			certFHE::Ciphertext ** cs;
			cs = new certFHE::Ciphertext *[CS_CNT];

			uint64_t pp;

			int OP_MODULUS = PERM ? 3 : 2;

			out << "Starting tests:\n\n";
			out.flush();

			for (int ts = 0; ts < TEST_COUNT; ts++) {

				try {

					out << "TEST " << ts << ":\n";
					out.flush();

					out << "Initializing starting values...";
					out.flush();

					timer.start();

					for (int i = 0; i < CS_CNT; i++) {

						val[i] = randoms[randindex] % 2;
						randindex += 1;

						cs[i] = new certFHE::Ciphertext();

						certFHE::Plaintext p(val[i]);
						*cs[i] = sk.encrypt(p);
					}

					out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
					timer.reset();

					int max_index = CS_CNT;

					for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

						double t_acc = 0;
						double t;

						int i, j, k;

						for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

							int opc = randoms[randindex] % OP_MODULUS;
							randindex += 1;

							switch (opc) {

							case(0): // * between two random ctxt, += in the third

								i = randoms[randindex] % max_index;
								j = randoms[randindex + 1] % max_index;
								k = randoms[randindex + 2] % max_index;

								randindex += 3;

								timer.start();

								*cs[k] += *cs[i] * *cs[j];

								t = timer.stop();
								timer.reset();

								t_acc += t;

								val[k] ^= (val[i] & val[j]);

								break;

							case(1): // + between two random ctxt, *= in the third

								i = randoms[randindex] % max_index;
								j = randoms[randindex + 1] % max_index;
								k = randoms[randindex + 2] % max_index;

								randindex += 3;

								timer.start();

								*cs[k] *= *cs[i] + *cs[j];

								t = timer.stop();
								timer.reset();

								t_acc += t;

								val[k] &= (val[i] ^ val[j]);

								break;

							case(2): // permutation on a random ctxt

								i = randoms[randindex] % max_index;

								randindex += 1;

								timer.start();

								temp = cs[i]->applyPermutation(perm);

								t = timer.stop();
								timer.reset();

								t_acc += t;

								pp = sk.decrypt(*cs[i]).getValue() & 0x01;

								if (val[i] != pp) {

									out << "WRONG decryption on permuted ctxt; should be " << val[i] << ", decrypted " << pp << '\n';
									out.flush();
								}

								certFHE::CNODE::clear_decryption_cache();

								break;

							default:
								break;
							}
						}

						out << "Decrypting...\n";
						out.flush();

						double t_acc_dec = 0;
						double t_dec;

						for (int pos = 0; pos < max_index; pos++) {

							timer.start();

							uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

							t_dec = timer.stop();
							timer.reset();

							t_acc_dec += t_dec;

							if (p != val[pos]) {

								out << "WRONG decryption; should be " << val[pos] << ", decrypted " << p << '\n';
								out.flush();
							}
						}

						certFHE::CNODE::clear_decryption_cache();

						timer.start();

						int to_delete_cnt = 0;
						if(DEL_FACTOR > 0)
							to_delete_cnt = max_index / DEL_FACTOR;

						for (int td = 0; td < to_delete_cnt; td++) {

							max_index -= 1;
							delete cs[max_index];
						}

						t = timer.stop();
						timer.reset();

						t_acc += t;

						out << "Epoch " << epoch << ": operations " << t_acc << " " << TIME_MEASURE_UNIT
							<< ", decryption " << t_acc_dec << " " << TIME_MEASURE_UNIT << "\n";
						out.flush();
					}

					double t_m_acc = 0;

					out << "Starting threads...\n";
					out.flush();

					certFHE::Ciphertext *** thr_args = new certFHE::Ciphertext **[THR_CNT];
					int ** thr_val = new int *[THR_CNT];

					const int LEFT_CTXT_CNT = max_index;

					for (int thr = 0; thr < THR_CNT; thr++) {

						thr_args[thr] = new certFHE::Ciphertext *[LEFT_CTXT_CNT];
						thr_val[thr] = new int[LEFT_CTXT_CNT];

						for (int carg = 0; carg < LEFT_CTXT_CNT; carg++) {

							thr_args[thr][carg] = new certFHE::Ciphertext(*cs[carg]);
							thr_val[thr][carg] = val[carg];
						}
					}

					std::thread ** thrs = new std::thread *[THR_CNT];

					std::mutex out_mutex;

					int rand_offset = 0;

					timer.start();

					for (int thr = 0; thr < THR_CNT; thr++) {

						thrs[thr] = new std::thread(&average_thrfct_rndloaded_test, std::ref(randoms),
							randindex + rand_offset,
							std::ref(sk), std::ref(perm), thr_args[thr], thr_val[thr],
							std::ref(out), std::ref(out_mutex), 
							ROUNDS_PER_THREAD, LEFT_CTXT_CNT, EPOCH_CNT, DEL_FACTOR, PERM);

						rand_offset += ROUNDS_PER_THREAD * 10;
					}

					for (int thr = 0; thr < THR_CNT; thr++)
						thrs[thr]->join();

					t_m_acc = timer.stop();
					timer.reset();

					for (int thr = 0; thr < THR_CNT; thr++) {

						delete thr_val[thr];
						delete thr_args[thr];
					}

					delete thr_args;
					delete thr_val;

					for (int c_left = 0; c_left < max_index; c_left++)
						delete cs[c_left];

					out << "Multithreading total time " << t_m_acc << " miliseconds\n";
					out.flush();

					out << "TEST " << ts << " DONE\n\n";
					out.flush();

				}
				catch (std::exception e) {

					out << "ERROR: " << e.what() << '\n';
				}
			}

			delete val;
		}
		catch (std::exception & err) {

			out << "ERROR running current implementation tests: " << err.what() << '\n';
		}
	}

	// initial implementation stats
	if (execute_old_test) {

		try {

			certFHE_old::Timer timer;
			int randindex = 0; // for randoms

			const char * TIME_MEASURE_UNIT = "miliseconds";

			out_old << ROUNDS_PER_TEST << " rounds per test, "
				<< ROUNDS_PER_THREAD << " rounds per thread, "
				<< CS_CNT << " ciphertexts, "
				<< EPOCH_CNT << " epochs per test, "
				<< DEL_FACTOR << " ciphertexts deleted per epoch factor\n\n";

			out_old << "Starting...";
			out_old.flush();

			timer.start();

			certFHE_old::Library::initializeLibrary();
			certFHE_old::Context context(CONTEXT_N, CONTEXT_D);
			certFHE_old::SecretKey sk(context);

			certFHE_old::Permutation perm(context);
			certFHE_old::SecretKey psk = sk.applyPermutation(perm);

			// declared here to force compiler to use it and not remove it
			// when doing optimisations
			certFHE_old::Ciphertext temp;

			out_old << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
			timer.reset();

			const int rounds_per_epoch = ROUNDS_PER_TEST / EPOCH_CNT;

			int * val = new int[CS_CNT];
			certFHE_old::Ciphertext ** cs;
			cs = new certFHE_old::Ciphertext *[CS_CNT];

			uint64_t pp;

			int OP_MODULUS = PERM ? 3 : 2;

			out_old << "Starting tests:\n\n";
			out_old.flush();

			for (int ts = 0; ts < TEST_COUNT; ts++) {

				try {

					out_old << "TEST " << ts << ":\n";
					out_old.flush();

					out_old << "Initializing starting values...";
					out_old.flush();

					timer.start();

					for (int i = 0; i < CS_CNT; i++) {

						val[i] = randoms[randindex] % 2;
						randindex += 1;

						cs[i] = new certFHE_old::Ciphertext();

						certFHE_old::Plaintext p(val[i]);
						*cs[i] = sk.encrypt(p);
					}

					out_old << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
					timer.reset();

					int max_index = CS_CNT;

					for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

						double t_acc = 0;
						double t;

						int i, j, k;

						for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

							int opc = randoms[randindex] % OP_MODULUS;
							randindex += 1;

							switch (opc) {

							case(0): // * between two random ctxt, += in the third

								i = randoms[randindex] % max_index;
								j = randoms[randindex + 1] % max_index;
								k = randoms[randindex + 2] % max_index;

								randindex += 3;

								timer.start();

								*cs[k] += *cs[i] * *cs[j];

								t = timer.stop();
								timer.reset();

								t_acc += t;

								val[k] ^= (val[i] & val[j]);

								break;

							case(1): // + between two random ctxt, *= in the third

								i = randoms[randindex] % max_index;
								j = randoms[randindex + 1] % max_index;
								k = randoms[randindex + 2] % max_index;

								randindex += 3;

								timer.start();

								*cs[k] *= *cs[i] + *cs[j];

								t = timer.stop();
								timer.reset();

								t_acc += t;

								val[k] &= (val[i] ^ val[j]);

								break;

							case(2): // permutation on a random ctxt

								i = randoms[randindex] % max_index;

								randindex += 1;

								timer.start();

								temp = cs[i]->applyPermutation(perm);

								t = timer.stop();
								timer.reset();

								t_acc += t;

								pp = sk.decrypt(*cs[i]).getValue() & 0x01;

								if (val[i] != pp) {

									out_old << "WRONG decryption on permuted ctxt; should be " << val[i] << ", decrypted " << pp << '\n';
									out_old.flush();
								}

								break;

							default:
								break;
							}
						}

						out_old << "Decrypting...\n";
						out_old.flush();

						double t_acc_dec = 0;
						double t_dec;

						for (int pos = 0; pos < max_index; pos++) {

							timer.start();

							uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

							t_dec = timer.stop();
							timer.reset();

							t_acc_dec += t_dec;

							if (p != val[pos]) {

								out_old << "WRONG decryption; should be " << val[pos] << ", decrypted " << p << '\n';
								out_old.flush();
							}
						}

						timer.start();

						int to_delete_cnt = 0;
						if (DEL_FACTOR > 0)
							to_delete_cnt = max_index / DEL_FACTOR;

						for (int td = 0; td < to_delete_cnt; td++) {

							max_index -= 1;
							delete cs[max_index];
						}

						t = timer.stop();
						timer.reset();

						t_acc += t;

						out_old << "Epoch " << epoch << ": operations " << t_acc << " " << TIME_MEASURE_UNIT
							<< ", decryption " << t_acc_dec << " " << TIME_MEASURE_UNIT << "\n";
						out_old.flush();
					}

					double t_m_acc = 0;

					out_old << "Starting threads...\n";
					out_old.flush();

					certFHE_old::Ciphertext *** thr_args = new certFHE_old::Ciphertext **[THR_CNT];
					int ** thr_val = new int *[THR_CNT];

					const int LEFT_CTXT_CNT = max_index;

					for (int thr = 0; thr < THR_CNT; thr++) {

						thr_args[thr] = new certFHE_old::Ciphertext *[LEFT_CTXT_CNT];
						thr_val[thr] = new int[LEFT_CTXT_CNT];

						for (int carg = 0; carg < LEFT_CTXT_CNT; carg++) {

							thr_args[thr][carg] = new certFHE_old::Ciphertext(*cs[carg]);
							thr_val[thr][carg] = val[carg];
						}
					}

					std::thread ** thrs = new std::thread *[THR_CNT];

					std::mutex out_mutex;

					int rand_offset = 0;

					timer.start();

					for (int thr = 0; thr < THR_CNT; thr++) {

						thrs[thr] = new std::thread(&average_thrfct_rndloaded_old_test, std::ref(randoms),
							randindex + rand_offset,
							std::ref(sk), std::ref(perm), thr_args[thr], thr_val[thr],
							std::ref(out), std::ref(out_mutex),
							ROUNDS_PER_THREAD, LEFT_CTXT_CNT, EPOCH_CNT, DEL_FACTOR, PERM);

						rand_offset += ROUNDS_PER_THREAD * 10;
					}

					for (int thr = 0; thr < THR_CNT; thr++)
						thrs[thr]->join();

					t_m_acc = timer.stop();
					timer.reset();

					for (int thr = 0; thr < THR_CNT; thr++) {

						delete thr_val[thr];
						delete thr_args[thr];
					}

					delete thr_args;
					delete thr_val;

					for (int c_left = 0; c_left < max_index; c_left++)
						delete cs[c_left];

					out_old << "Multithreading total time " << t_m_acc << " miliseconds\n";
					out_old.flush();

					out_old << "TEST " << ts << " DONE\n\n";
					out_old.flush();

				}
				catch (std::exception e) {

					out_old << "ERROR: " << e.what() << '\n';
				}
			}

			delete val;
		}
		catch (std::exception & err) {

			out_old << "ERROR running initial implementation tests: " << err.what() << '\n';
		}
	}
}

void average_rndloaded_test(std::string randoms_file_source,
	const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000,
	const int ROUNDS_PER_THREAD = 40, const int THR_CNT = 11,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	std::ostream & out = std::cout,
	std::ostream & out_old = std::cout,
	bool PERM = true,
	bool execute_old_test = true) {

	std::vector <int> randoms;

	if (randoms_file_source == "")

		for (int i = 0; i < TEST_COUNT * (ROUNDS_PER_TEST + ROUNDS_PER_THREAD * THR_CNT) * 3 + 100; i++)
			randoms.push_back(rand());

	else {

		std::fstream randsource(randoms_file_source, std::ios::in | std::ios::binary);

		if (!randsource.is_open()) {

			std::fstream new_randsource(randoms_file_source, std::ios::out | std::ios::binary);

			int tmp;
			for (int i = 0; i < TEST_COUNT * (ROUNDS_PER_TEST + ROUNDS_PER_THREAD * THR_CNT) * 3 + 100; i++) {

				tmp = rand();

				randoms.push_back(tmp);
				new_randsource.write((char *)&tmp, sizeof(int));
			}

			new_randsource.close();
		}
		else {

			int tmp;
			for (int i = 0; i < TEST_COUNT * (ROUNDS_PER_TEST + ROUNDS_PER_THREAD * THR_CNT) * 3 + 100; i++) {

				randsource.read((char *)&tmp, sizeof(int));
				randoms.push_back(tmp);
			}

			randsource.close();
		}
	}

	average_rndloaded_test(randoms,
		TEST_COUNT, ROUNDS_PER_TEST,
		ROUNDS_PER_THREAD, THR_CNT,
		CONTEXT_N, CONTEXT_D,
		CS_CNT, EPOCH_CNT, DEL_FACTOR,
		out,
		out_old,
		PERM,
		execute_old_test);
}

void average_rndloaded_predefined_test(std::string path = "\\average_test\\debug_stats",
								bool execute_old_test = false,
								bool permutations = false) {

	if (execute_old_test) {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);
		std::fstream log_old(STATS_PATH + path + "_old.txt", std::ios::out);

		average_rndloaded_test("avgtestops.bin", 10, 2000000, 0, 0, 1247, 16, 1000, 10, 100, log, log_old, permutations, true);

		log.close();
		log_old.close();
	}
	else {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);

		average_rndloaded_test("avgtestops.bin", 10, 2000000, 0, 0, 1247, 16, 1000, 10, 100, log, std::cout, permutations, false);

		log.close();
	}
}

void multiple_average_rndloaded_predefined_tests(std::string path) {

	// changing OPValues parameters in current implementation

	int rnd = 0;

	int ARR1_CNT = 1;
	int ARR2_CNT = 1;
	int ARR3_CNT = 1;
	int ARR4_CNT = 1;
	int ARR5_CNT = 1;

	int TOTAL_CNT = ARR1_CNT * ARR2_CNT * ARR3_CNT * ARR4_CNT * ARR5_CNT;

	uint64_t max_ccc_val_arr[] = { (uint64_t)2048 };
	uint64_t max_cadd_merge_val_arr[] = { (uint64_t)4096 * 4096 };
	uint64_t max_cmul_merge_val_arr[] = { (uint64_t)4096 * 4096 * 4096 };
	bool always_def_mul_val_arr[] = { true, false };
	bool rem_dupl_val_arr[] = { true, false };
	bool shorten_on_rec_val_arr[] = { true, false };

	for (int i = 0; i < ARR1_CNT; i++) {

		certFHE::OPValues::max_ccc_deflen_size = max_ccc_val_arr[i];

		for (int j = 0; j < ARR2_CNT; j++) {

			certFHE::OPValues::max_cadd_merge_size = max_cadd_merge_val_arr[j];
			certFHE::OPValues::max_cmul_merge_size = max_cmul_merge_val_arr[j];

			for (int k = 0; k < ARR3_CNT; k++) {

				certFHE::OPValues::always_default_multiplication = always_def_mul_val_arr[k];

				for (int p = 0; p < ARR4_CNT; p++) {

					certFHE::OPValues::remove_duplicates_onadd = rem_dupl_val_arr[p];
					certFHE::OPValues::remove_duplicates_onmul = rem_dupl_val_arr[p];

					for (int q = 0; q < ARR5_CNT; q++) {

						certFHE::OPValues::shorten_on_recursive_cadd_merging = shorten_on_rec_val_arr[q];
						certFHE::OPValues::shorten_on_recursive_cmul_merging = shorten_on_rec_val_arr[q];

						char maxccc[21];
						sprintf_s(maxccc, 21, "%llu", certFHE::OPValues::max_ccc_deflen_size);

						char maxcaddm[21];
						sprintf_s(maxcaddm, 21, "%llu", certFHE::OPValues::max_cadd_merge_size);

						char maxcmulm[21];
						sprintf_s(maxcmulm, 21, "%llu", certFHE::OPValues::max_cmul_merge_size);

						char adefm[6];
						sprintf_s(adefm, 6, "%s", certFHE::OPValues::always_default_multiplication ? "true" : "false");

						char remdupl[6];
						sprintf_s(remdupl, 6, "%s", certFHE::OPValues::remove_duplicates_onadd ? "true" : "false");

						char shrec[6];
						sprintf_s(shrec, 6, "%s", certFHE::OPValues::shorten_on_recursive_cadd_merging ? "true" : "false");

						std::string path_tmp = path + "_" + maxccc + "_" + maxcaddm + "_" + maxcmulm
							+ "_" + adefm + "_" + remdupl + "_" + shrec;

						rnd += 1;
						if (rnd == TOTAL_CNT)
							average_rndloaded_predefined_test(path_tmp, true, false);
						else
							average_rndloaded_predefined_test(path_tmp, false, false);
					}

				}

			}
		}
	}
}

void average_thrfct_test(certFHE::SecretKey & sk, certFHE::Permutation & perm,
	certFHE::Ciphertext ** cs, int * val,
	std::ostream & out, std::mutex & out_mutex,
	const int ROUNDS_PER_THREAD,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	bool PERM = true) {

	out_mutex.lock();
	out << "Entered thread specific function, thread " << std::this_thread::get_id() << '\n';
	out.flush();
	out_mutex.unlock();

	const int rounds_per_epoch = ROUNDS_PER_THREAD / EPOCH_CNT;

	uint64_t pp;
	certFHE::Ciphertext temp;

	int OP_MODULUS = PERM ? 3 : 2;

	try {

		int max_index = CS_CNT;

		for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

			int i, j, k;

			for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

				int opc = rand() % OP_MODULUS;

				switch (opc) {

				case(0): // * between two random ctxt, += in the third

					i = rand() % max_index;
					j = rand() % max_index;
					k = rand() % max_index;

					*cs[k] += *cs[i] * *cs[j];

					val[k] ^= (val[i] & val[j]);

					break;

				case(1): // + between two random ctxt, *= in the third

					i = rand() % max_index;
					j = rand() % max_index;
					k = rand() % max_index;

					*cs[k] *= *cs[i] + *cs[j];

					val[k] &= (val[i] ^ val[j]);

					break;

				case(2): // permutation on a random ctxt

					i = rand() % max_index;

					temp = cs[i]->applyPermutation(perm);

					pp = sk.decrypt(*cs[i]).getValue() & 0x01;

					if (val[i] != pp) {

						out_mutex.lock();
						out << "WRONG decryption on permuted ctxt on thread " << std::this_thread::get_id()
							<< "; should be " << val[i] << ", decrypted " << pp << '\n';
						out.flush();
						out_mutex.unlock();
					}

					break;

				default:
					break;
				}
			}

			for (int pos = 0; pos < max_index; pos++) {

				uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

				if (p != val[pos]) {

					out_mutex.lock();
					out << "WRONG decryption on thread " << std::this_thread::get_id()
						<< "; should be " << val[pos] << ", decrypted " << p << '\n';
					out.flush();
					out_mutex.unlock();
				}
			}

			int to_delete_cnt = 0;
			if (DEL_FACTOR > 0)
				to_delete_cnt = max_index / DEL_FACTOR;

			for (int td = 0; td < to_delete_cnt; td++) {

				max_index -= 1;
				delete cs[max_index];
			}
		}

		for (int c_left = 0; c_left < max_index; c_left++)
			delete cs[c_left];

	}
	catch (std::exception e) {

		out << "ERROR on thread " << std::this_thread::get_id() << ": " << e.what() << '\n';
	}

	out_mutex.lock();
	out << "Thread " << std::this_thread::get_id() << " done\n";
	out.flush();
	out_mutex.unlock();
}

void average_thrfct_old_test(certFHE_old::SecretKey & sk, certFHE_old::Permutation & perm,
	certFHE_old::Ciphertext ** cs, int * val,
	std::ostream & out, std::mutex & out_mutex,
	const int ROUNDS_PER_THREAD,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	bool PERM = true) {

	out_mutex.lock();
	out << "Entered thread specific function, thread " << std::this_thread::get_id() << '\n';
	out.flush();
	out_mutex.unlock();

	const int rounds_per_epoch = ROUNDS_PER_THREAD / EPOCH_CNT;

	uint64_t pp;
	certFHE_old::Ciphertext temp;

	int OP_MODULUS = PERM ? 3 : 2;

	try {

		int max_index = CS_CNT;

		for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

			int i, j, k;

			for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

				int opc = rand() % OP_MODULUS;

				switch (opc) {

				case(0): // * between two random ctxt, += in the third

					i = rand() % max_index;
					j = rand() % max_index;
					k = rand() % max_index;

					*cs[k] += *cs[i] * *cs[j];

					val[k] ^= (val[i] & val[j]);

					break;

				case(1): // + between two random ctxt, *= in the third

					i = rand() % max_index;
					j = rand() % max_index;
					k = rand() % max_index;

					*cs[k] *= *cs[i] + *cs[j];

					val[k] &= (val[i] ^ val[j]);

					break;

				case(2): // permutation on a random ctxt

					i = rand() % max_index;

					temp = cs[i]->applyPermutation(perm);

					pp = sk.decrypt(*cs[i]).getValue() & 0x01;

					if (val[i] != pp) {

						out_mutex.lock();
						out << "WRONG decryption on permuted ctxt on thread " << std::this_thread::get_id()
							<< "; should be " << val[i] << ", decrypted " << pp << '\n';
						out.flush();
						out_mutex.unlock();
					}

					break;

				default:
					break;
				}
			}

			for (int pos = 0; pos < max_index; pos++) {

				uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

				if (p != val[pos]) {

					out_mutex.lock();
					out << "WRONG decryption on thread " << std::this_thread::get_id()
						<< "; should be " << val[pos] << ", decrypted " << p << '\n';
					out.flush();
					out_mutex.unlock();
				}
			}

			int to_delete_cnt = 0;
			if (DEL_FACTOR > 0)
				to_delete_cnt = max_index / DEL_FACTOR;

			for (int td = 0; td < to_delete_cnt; td++) {

				max_index -= 1;
				delete cs[max_index];
			}
		}

		for (int c_left = 0; c_left < max_index; c_left++)
			delete cs[c_left];

	}
	catch (std::exception e) {

		out << "ERROR on thread " << std::this_thread::get_id() << ": " << e.what() << '\n';
	}

	out_mutex.lock();
	out << "Thread " << std::this_thread::get_id() << " done\n";
	out.flush();
	out_mutex.unlock();
}

void average_test(const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000,
	const int ROUNDS_PER_THREAD = 40, const int THR_CNT = 11,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16,
	const int CS_CNT = 20, const int EPOCH_CNT = 3, const int DEL_FACTOR = 3,
	std::ostream & out = std::cout,
	std::ostream & out_old = std::cout,
	bool PERM = true,
	bool execute_old_test = true) {

	// addition (+, +=), multiplication (*, *=), permutation inplace (only!)
	// 3 rounds of deletion, so that reference count is tested
	// decryption time measured only at the end of every epoch (3 times per test)

	// current implementation stats
		{
			try {

				certFHE::Timer timer;

				const char * TIME_MEASURE_UNIT = "miliseconds";

				out << ROUNDS_PER_TEST << " rounds per test, "
					<< ROUNDS_PER_THREAD << " rounds per thread, "
					<< CS_CNT << " ciphertexts, "
					<< EPOCH_CNT << " epochs per test, "
					<< DEL_FACTOR << " ciphertexts deleted per epoch factor\n\n";

				out << "Starting...";
				out.flush();

				timer.start();

				certFHE::Library::initializeLibrary();
				certFHE::Context context(CONTEXT_N, CONTEXT_D);
				certFHE::SecretKey sk(context);

				certFHE::Permutation perm(context);
				certFHE::SecretKey psk = sk.applyPermutation(perm);

				// declared here to force compiler to use it and not remove it
				// when doing optimisations
				certFHE::Ciphertext temp;

				out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
				timer.reset();

				out << "Multithreading thresholds autoselection...";
				out.flush();

				timer.start();

				certFHE::MTValues::m_threshold_autoselect(context, false);

				out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
				timer.reset();

				const int rounds_per_epoch = ROUNDS_PER_TEST / EPOCH_CNT;

				int * val = new int[CS_CNT];
				certFHE::Ciphertext ** cs;
				cs = new certFHE::Ciphertext *[CS_CNT];

				uint64_t pp;

				int OP_MODULUS = PERM ? 3 : 2;

				out << "Starting tests:\n\n";
				out.flush();
				std::cout << "tests start\n";
				for (int ts = 0; ts < TEST_COUNT; ts++) {

					try {

						out << "TEST " << ts << ":\n";
						out.flush();

						out << "Initializing starting values...";
						out.flush();

						timer.start();

						for (int i = 0; i < CS_CNT; i++) {

							val[i] = rand() % 2;

							cs[i] = new certFHE::Ciphertext();

							certFHE::Plaintext p(val[i]);
							*cs[i] = sk.encrypt(p);
						}

						out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
						timer.reset();

						int max_index = CS_CNT;

						for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

							double t_acc = 0;
							double t;

							int i, j, k;

							for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

								int opc = rand() % OP_MODULUS;

								switch (opc) {

								case(0): // * between two random ctxt, += in the third

									i = rand() % max_index;
									j = rand() % max_index;
									k = rand() % max_index;

									timer.start();

									*cs[k] += *cs[i] * *cs[j];

									t = timer.stop();
									timer.reset();

									t_acc += t;

									val[k] ^= (val[i] & val[j]);

									break;

								case(1): // + between two random ctxt, *= in the third

									i = rand() % max_index;
									j = rand() % max_index;
									k = rand() % max_index;

									timer.start();

									*cs[k] *= *cs[i] + *cs[j];

									t = timer.stop();
									timer.reset();

									t_acc += t;

									val[k] &= (val[i] ^ val[j]);

									break;

								case(2): // permutation on a random ctxt

									i = rand() % max_index;

									timer.start();

									temp = cs[i]->applyPermutation(perm);

									t = timer.stop();
									timer.reset();

									t_acc += t;

									pp = sk.decrypt(*cs[i]).getValue() & 0x01;

									if (val[i] != pp) {

										out << "WRONG decryption on permuted ctxt; should be " << val[i] << ", decrypted " << pp << '\n';
										out.flush();
									}

									certFHE::CNODE::clear_decryption_cache();

									break;

								default:
									break;
								}
							}

							out << "Decrypting...\n";
							out.flush();

							double t_acc_dec = 0;
							double t_dec;

							for (int pos = 0; pos < max_index; pos++) {

								timer.start();

								uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

								t_dec = timer.stop();
								timer.reset();

								t_acc_dec += t_dec;

								if (p != val[pos]) {

									out << "WRONG decryption; should be " << val[pos] << ", decrypted " << p << '\n';
									out.flush();
								}
							}

							certFHE::CNODE::clear_decryption_cache();

							timer.start();

							int to_delete_cnt = 0;
							if (DEL_FACTOR > 0)
								to_delete_cnt = max_index / DEL_FACTOR;

							for (int td = 0; td < to_delete_cnt; td++) {

								max_index -= 1;
								delete cs[max_index];
							}

							t = timer.stop();
							timer.reset();

							t_acc += t;

							out << "Epoch " << epoch << ": operations " << t_acc << " " << TIME_MEASURE_UNIT
								<< ", decryption " << t_acc_dec << " " << TIME_MEASURE_UNIT << "\n";
							out.flush();
						}

						double t_m_acc = 0;

						out << "Starting threads...\n";
						out.flush();

						certFHE::Ciphertext *** thr_args = new certFHE::Ciphertext **[THR_CNT];
						int ** thr_val = new int *[THR_CNT];

						const int LEFT_CTXT_CNT = max_index;

						for (int thr = 0; thr < THR_CNT; thr++) {

							thr_args[thr] = new certFHE::Ciphertext *[LEFT_CTXT_CNT];
							thr_val[thr] = new int[LEFT_CTXT_CNT];

							for (int carg = 0; carg < LEFT_CTXT_CNT; carg++) {

								thr_args[thr][carg] = new certFHE::Ciphertext(*cs[carg]);
								thr_val[thr][carg] = val[carg];
							}
						}

						std::thread ** thrs = new std::thread *[THR_CNT];

						std::mutex out_mutex;

						int rand_offset = 0;

						timer.start();

						for (int thr = 0; thr < THR_CNT; thr++) {

							thrs[thr] = new std::thread(&average_thrfct_test,
								std::ref(sk), std::ref(perm), thr_args[thr], thr_val[thr],
								std::ref(out), std::ref(out_mutex),
								ROUNDS_PER_THREAD, LEFT_CTXT_CNT, EPOCH_CNT, DEL_FACTOR, PERM);

							rand_offset += ROUNDS_PER_THREAD * 10;
						}

						for (int thr = 0; thr < THR_CNT; thr++)
							thrs[thr]->join();

						t_m_acc = timer.stop();
						timer.reset();

						for (int thr = 0; thr < THR_CNT; thr++) {

							delete thr_val[thr];
							delete thr_args[thr];
						}

						delete thr_args;
						delete thr_val;

						for (int c_left = 0; c_left < max_index; c_left++) {

							//std::cout << cs[c_left]->node->downstream_reference_count << '\n';
							delete cs[c_left];
						}
							
						out << "Multithreading total time " << t_m_acc << " miliseconds\n";
						out.flush();

						std::cout << "TEST " << ts << " DONE\n\n";
						out << "TEST " << ts << " DONE\n\n";
						out.flush();

					}
					catch (std::exception e) {

						out << "ERROR: " << e.what() << '\n';
					}
				}

				delete val;
			}
			catch (std::exception & err) {

				out << "ERROR running current implementation tests: " << err.what() << '\n';
			}
		}

		// initial implementation stats
		if (execute_old_test) {

			try {

				certFHE_old::Timer timer;
				int randindex = 0; // for randoms

				const char * TIME_MEASURE_UNIT = "miliseconds";

				out_old << ROUNDS_PER_TEST << " rounds per test, "
					<< ROUNDS_PER_THREAD << " rounds per thread, "
					<< CS_CNT << " ciphertexts, "
					<< EPOCH_CNT << " epochs per test, "
					<< DEL_FACTOR << " ciphertexts deleted per epoch factor\n\n";

				out_old << "Starting...";
				out_old.flush();

				timer.start();

				certFHE_old::Library::initializeLibrary();
				certFHE_old::Context context(CONTEXT_N, CONTEXT_D);
				certFHE_old::SecretKey sk(context);

				certFHE_old::Permutation perm(context);
				certFHE_old::SecretKey psk = sk.applyPermutation(perm);

				// declared here to force compiler to use it and not remove it
				// when doing optimisations
				certFHE_old::Ciphertext temp;

				out_old << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
				timer.reset();

				const int rounds_per_epoch = ROUNDS_PER_TEST / EPOCH_CNT;

				int * val = new int[CS_CNT];
				certFHE_old::Ciphertext ** cs;
				cs = new certFHE_old::Ciphertext *[CS_CNT];

				uint64_t pp;

				int OP_MODULUS = PERM ? 3 : 2;

				out_old << "Starting tests:\n\n";
				out_old.flush();

				for (int ts = 0; ts < TEST_COUNT; ts++) {

					try {

						out_old << "TEST " << ts << ":\n";
						out_old.flush();

						out_old << "Initializing starting values...";
						out_old.flush();

						timer.start();

						for (int i = 0; i < CS_CNT; i++) {

							val[i] = rand() % 2;
							randindex += 1;

							cs[i] = new certFHE_old::Ciphertext();

							certFHE_old::Plaintext p(val[i]);
							*cs[i] = sk.encrypt(p);
						}

						out_old << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
						timer.reset();

						int max_index = CS_CNT;

						for (int epoch = 0; epoch < EPOCH_CNT; epoch++) {

							double t_acc = 0;
							double t;

							int i, j, k;

							for (int rnd = 0; rnd < rounds_per_epoch; rnd++) {

								int opc = rand() % OP_MODULUS;
								randindex += 1;

								switch (opc) {

								case(0): // * between two random ctxt, += in the third

									i = rand() % max_index;
									j = rand() % max_index;
									k = rand() % max_index;

									randindex += 3;

									timer.start();

									*cs[k] += *cs[i] * *cs[j];

									t = timer.stop();
									timer.reset();

									t_acc += t;

									val[k] ^= (val[i] & val[j]);

									break;

								case(1): // + between two random ctxt, *= in the third

									i = rand() % max_index;
									j = rand() % max_index;
									k = rand() % max_index;

									randindex += 3;

									timer.start();

									*cs[k] *= *cs[i] + *cs[j];

									t = timer.stop();
									timer.reset();

									t_acc += t;

									val[k] &= (val[i] ^ val[j]);

									break;

								case(2): // permutation on a random ctxt

									i = rand() % max_index;

									randindex += 1;

									timer.start();

									temp = cs[i]->applyPermutation(perm);

									t = timer.stop();
									timer.reset();

									t_acc += t;

									pp = sk.decrypt(*cs[i]).getValue() & 0x01;

									if (val[i] != pp) {

										out_old << "WRONG decryption on permuted ctxt; should be " << val[i] << ", decrypted " << pp << '\n';
										out_old.flush();
									}

									break;

								default:
									break;
								}
							}

							out_old << "Decrypting...\n";
							out_old.flush();

							double t_acc_dec = 0;
							double t_dec;

							for (int pos = 0; pos < max_index; pos++) {

								timer.start();

								uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

								t_dec = timer.stop();
								timer.reset();

								t_acc_dec += t_dec;

								if (p != val[pos]) {

									out_old << "WRONG decryption; should be " << val[pos] << ", decrypted " << p << '\n';
									out_old.flush();
								}
							}

							timer.start();

							int to_delete_cnt = 0;
							if (DEL_FACTOR > 0)
								to_delete_cnt = max_index / DEL_FACTOR;

							for (int td = 0; td < to_delete_cnt; td++) {

								max_index -= 1;
								delete cs[max_index];
							}

							t = timer.stop();
							timer.reset();

							t_acc += t;

							out_old << "Epoch " << epoch << ": operations " << t_acc << " " << TIME_MEASURE_UNIT
								<< ", decryption " << t_acc_dec << " " << TIME_MEASURE_UNIT << "\n";
							out_old.flush();
						}

						double t_m_acc = 0;

						out_old << "Starting threads...\n";
						out_old.flush();

						certFHE_old::Ciphertext *** thr_args = new certFHE_old::Ciphertext **[THR_CNT];
						int ** thr_val = new int *[THR_CNT];

						const int LEFT_CTXT_CNT = max_index;

						for (int thr = 0; thr < THR_CNT; thr++) {

							thr_args[thr] = new certFHE_old::Ciphertext *[LEFT_CTXT_CNT];
							thr_val[thr] = new int[LEFT_CTXT_CNT];

							for (int carg = 0; carg < LEFT_CTXT_CNT; carg++) {

								thr_args[thr][carg] = new certFHE_old::Ciphertext(*cs[carg]);
								thr_val[thr][carg] = val[carg];
							}
						}

						std::thread ** thrs = new std::thread *[THR_CNT];

						std::mutex out_mutex;

						int rand_offset = 0;

						timer.start();

						for (int thr = 0; thr < THR_CNT; thr++) {

							thrs[thr] = new std::thread(&average_thrfct_old_test,
								std::ref(sk), std::ref(perm), thr_args[thr], thr_val[thr],
								std::ref(out), std::ref(out_mutex),
								ROUNDS_PER_THREAD, LEFT_CTXT_CNT, EPOCH_CNT, DEL_FACTOR, PERM);

							rand_offset += ROUNDS_PER_THREAD * 10;
						}

						for (int thr = 0; thr < THR_CNT; thr++)
							thrs[thr]->join();

						t_m_acc = timer.stop();
						timer.reset();

						for (int thr = 0; thr < THR_CNT; thr++) {

							delete thr_val[thr];
							delete thr_args[thr];
						}

						delete thr_args;
						delete thr_val;

						for (int c_left = 0; c_left < max_index; c_left++)
							delete cs[c_left];

						out_old << "Multithreading total time " << t_m_acc << " miliseconds\n";
						out_old.flush();

						out_old << "TEST " << ts << " DONE\n\n";
						out_old.flush();

					}
					catch (std::exception e) {

						out_old << "ERROR: " << e.what() << '\n';
					}
				}

				delete val;
			}
			catch (std::exception & err) {

				out_old << "ERROR running initial implementation tests: " << err.what() << '\n';
			}
		}
}

void average_predefined_test(std::string path = "\\average_test\\debug_stats",
	bool execute_old_test = false,
	bool permutations = false) {

	if (execute_old_test) {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);
		std::fstream log_old(STATS_PATH + path + "_old.txt", std::ios::out);

		average_test(10, 2000000, 0, 0, 1247, 16, 1000, 10, 100, log, log_old, permutations, true);

		log.close();
		log_old.close();
	}
	else {

		std::fstream log(STATS_PATH + path + ".txt", std::ios::out);

		average_test(10, 2000000, 0, 0, 1247, 16, 1000, 10, 100, log, std::cout, permutations, false);

		log.close();
	}
}

int main(){

	//average_predefined_test();

	//array_ctxt_predefined_test();

	//average_m_predefined_test();

	//multiple_array_ctxt_predefined_tests("\\array_ctxt_test\\multiple_tests\\debug");

	//multiple_average_predefined_tests("\\average_test\\multiple_tests\\release");

	average_predefined_test("\\average_test\\release_noperm_nomerging_stats", false, false);
	
    return 0;
}
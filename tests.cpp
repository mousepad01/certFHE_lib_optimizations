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

// STATS_PATH to be manually configured 
static std::string STATS_PATH = "";

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

void array_ctxt_predefined_test(std::string path_sufix = "\\array_ctxt_test\\release_stats",
								bool execute_old_test = true) {

	if (execute_old_test) {

		std::fstream log(STATS_PATH + "arrtest_" + path_sufix + ".txt", std::ios::out);
		std::fstream log_old(STATS_PATH + "arrtest_" + path_sufix + "_old.txt", std::ios::out);

		array_ctxt_test("arrctxttestops.bin", 2, 1000, 1247, 16, log, log_old, true);

		log.close();
		log_old.close();
	}
	else {

		std::fstream log(STATS_PATH + "arrtest_" + path_sufix + ".txt", std::ios::out);

		array_ctxt_test("arrctxttestops.bin", 2, 1000, 1247, 16, log, std::cout, false);

		log.close();
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

						timer.start();

						for (int thr = 0; thr < THR_CNT; thr++) {

							thrs[thr] = new std::thread(&average_thrfct_test,
								std::ref(sk), std::ref(perm), thr_args[thr], thr_val[thr],
								std::ref(out), std::ref(out_mutex),
								ROUNDS_PER_THREAD, LEFT_CTXT_CNT, EPOCH_CNT, DEL_FACTOR, PERM);

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

void average_predefined_test(std::string path_sufix = "\\average_test\\debug_stats",
	bool execute_old_test = false,
	bool permutations = false) {

	if (execute_old_test) {

		std::fstream log(STATS_PATH + "averagetest_" + path_sufix + ".txt", std::ios::out);
		std::fstream log_old(STATS_PATH + "averagetest_" + path_sufix + "_old.txt", std::ios::out);

		average_test(100, 50, 30, 5, 1247, 16, 100, 10, 0, log, log_old, permutations, true);

		log.close();
		log_old.close();
	}
	else {

		std::fstream log(STATS_PATH + "averagetest_" + path_sufix + ".txt", std::ios::out);

		average_test(100, 50, 30, 5, 1247, 16, 100, 10, 0, log, std::cout, permutations, false);

		log.close();
	}
}

void old_implementation_compare_statistics_tests() {

	std::cout << "NOTE: make sure the STATS_PATH is configured and all directories exist\n\n";

	std::cout << "Starting the first test, where random operations will be applied between a fixed amount of ciphertexts\n"
		<< "Stats will be saved in " << STATS_PATH << '\n'
		<< "To plot them, call average_test_plot function from plotter.py (dectime parameter - whether you want to plot decryption times in the same graph or not)\n"
		<< "NOTE: plotter.py needs to be in the same directory in which the result files are located\n\n";

	average_predefined_test("mthr_stats", false, false);

	std::cout << "First test done\n\n";

	std::cout << "Starting the second test, where the addition and multiplication times are measured separately, on small ciphertexts\n"
		<< "Stats will be saved in " << STATS_PATH << '\n'
		<< "To plot them, call array_ctxt_tests_plot from plotter.py (op parameter - Addition or Multiplication)\n"
		<< "NOTE: plotter.py needs to be in the same directory in which the result files are located\n\n";

	//array_ctxt_predefined_test("statsGPU", true);

	std::cout << "Second test done\n\n";
}

void serialization_test(const int TEST_COUNT = 10, const int ROUNDS_PER_TEST = 1000, const int CS_CNT = 20,
	const int CONTEXT_N = 1247, const int CONTEXT_D = 16, std::ostream & out = std::cout) {

	try {

		certFHE::Timer timer;

		const char * TIME_MEASURE_UNIT = "miliseconds";

		out << ROUNDS_PER_TEST << " rounds per test, "
			<< CS_CNT << " ciphertexts\n\n";

		out << "Starting...";
		out.flush();

		timer.start();

		certFHE::Library::initializeLibrary();
		certFHE::Context context(CONTEXT_N, CONTEXT_D);
		certFHE::SecretKey sk(context);

		out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
		timer.reset();

		out << "Multithreading thresholds autoselection...";
		out.flush();

		timer.start();

		certFHE::MTValues::m_threshold_autoselect(context, false);

		out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
		timer.reset();

		int * val = new int[CS_CNT];
		certFHE::Ciphertext ** cs;
		cs = new certFHE::Ciphertext *[CS_CNT];

		int OP_MODULUS = 2;

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

					val[i] = rand() % 2;

					cs[i] = new certFHE::Ciphertext();

					certFHE::Plaintext p(val[i]);
					*cs[i] = sk.encrypt(p);
				}

				out << timer.stop() << " " << TIME_MEASURE_UNIT << "\n";
				timer.reset();

				double t_acc = 0;
				double t;

				int i, j, k;

				for (int rnd = 0; rnd < ROUNDS_PER_TEST; rnd++) {

					int opc = rand() % OP_MODULUS;

					switch (opc) {

					case(0): // * between two random ctxt, += in the third

						i = rand() % CS_CNT;
						j = rand() % CS_CNT;
						k = rand() % CS_CNT;

						timer.start();

						*cs[k] += *cs[i] * *cs[j];

						t = timer.stop();
						timer.reset();

						t_acc += t;

						val[k] ^= (val[i] & val[j]);

						break;

					case(1): // + between two random ctxt, *= in the third

						i = rand() % CS_CNT;
						j = rand() % CS_CNT;
						k = rand() % CS_CNT;

						timer.start();

						*cs[k] *= *cs[i] + *cs[j];

						t = timer.stop();
						timer.reset();

						t_acc += t;

						val[k] &= (val[i] ^ val[j]);

						break;

					default:
						break;
					}
				}

				out << "Decrypting...\n";
				out.flush();

				double t_acc_dec = 0;
				double t_dec;

				

				for (int pos = 0; pos < CS_CNT; pos++) {

					timer.start();

					uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

					t_dec = timer.stop();
					timer.reset();

					t_acc_dec += t_dec;

					if (p != val[pos]) {

						out << "WRONG initial decryption; should be " << val[pos] << ", decrypted " << p << '\n';
						out.flush();
					}
				}

				

				out << "Operations done: " << t_acc << " " << TIME_MEASURE_UNIT
					<< ", decryption " << t_acc_dec << " " << TIME_MEASURE_UNIT << "\n";
				out.flush();
				
				out << "Serializing...\n";
				out.flush();

				double t_ser;
				double t_ser_acc = 0;

				timer.start();

				auto ser_res = certFHE::Ciphertext::serialize(CS_CNT, cs);
				unsigned char * serialized = ser_res.first;

				t_ser = timer.stop();
				timer.reset();

				t_ser_acc += t_ser;

				out << "Serialization done: " << t_ser_acc << " " << TIME_MEASURE_UNIT << "\n";
				out << "Deserializing...\n";
				out.flush();

				t_ser_acc = 0;

				timer.start();

				auto deserialized_res = certFHE::Ciphertext::deserialize(serialized);
				certFHE::Ciphertext ** deserialized = deserialized_res.first;

				t_ser = timer.stop();
				timer.reset();

				t_ser_acc += t_ser;

				

				out << "Deserialization done: " << t_ser_acc << " " << TIME_MEASURE_UNIT << "\n";
				out << "Decrypting deserialized ciphertexts...\n";
				out.flush();

				for (int i = 0; i < CS_CNT; i++) {

					uint64_t p = sk.decrypt(*deserialized[i]).getValue() & 0x01;

					if (p != val[i]) {

						out << "WRONG deserialized decryption; should be " << val[i] << ", decrypted " << p << '\n';
						out.flush();
					}
				}
				out << "Deserialized ciphertext decryption done\n";
				out.flush();

				

				delete[] serialized;

				for (int ct = 0; ct < CS_CNT; ct++)
					delete deserialized[ct];

				delete[] deserialized;

				for (int ct = 0; ct < CS_CNT; ct++)
					delete cs[ct];

				out << "TEST " << ts << " DONE\n\n";
				out.flush();

			}
			catch (std::exception e) {

				out << "ERROR: " << e.what() << '\n';
				out.flush();
			}
		}

		delete val;
	}
	catch (std::exception & err) {

		out << "ERROR running (de)serialization tests: " << err.what() << '\n';
	}
}

void serialization_predefined_test(std::string path_sufix = "\\serialization_test\\debug_stats") {

	std::fstream log(STATS_PATH + "sertest_" + path_sufix + ".txt", std::ios::out);

	serialization_test(1000, 100, 100, 1247, 16, log);

	log.close();
}

void save_rnd_ser_test(const int ROUNDS = 100, const int CS_CNT = 20, const int CONTEXT_N = 1247, const int CONTEXT_D = 16, std::string out_name = "ser") {

	out_name += ".bin";

	certFHE::Library::initializeLibrary();
	certFHE::Context context(CONTEXT_N, CONTEXT_D);
	certFHE::SecretKey sk(context);

	certFHE::MTValues::m_threshold_autoselect(context);

	int * val = new int[CS_CNT];
	certFHE::Ciphertext ** cs;
	cs = new certFHE::Ciphertext *[CS_CNT];

	int OP_MODULUS = 2;

	for (int i = 0; i < CS_CNT; i++) {

		val[i] = rand() % 2;

		cs[i] = new certFHE::Ciphertext();

		certFHE::Plaintext p(val[i]);
		*cs[i] = sk.encrypt(p);
	}

	int i, j, k;

	for (int rnd = 0; rnd < ROUNDS; rnd++) {

		int opc = rand() % OP_MODULUS;

		switch (opc) {

		case(0): // * between two random ctxt, += in the third

			i = rand() % CS_CNT;
			j = rand() % CS_CNT;
			k = rand() % CS_CNT;

			*cs[k] += *cs[i] * *cs[j];

			val[k] ^= (val[i] & val[j]);

			break;

		case(1): // + between two random ctxt, *= in the third

			i = rand() % CS_CNT;
			j = rand() % CS_CNT;
			k = rand() % CS_CNT;

			*cs[k] *= *cs[i] + *cs[j];

			val[k] &= (val[i] ^ val[j]);

			break;

		default:
			break;
		}
	}

	

	for (int pos = 0; pos < CS_CNT; pos++) {

		uint64_t p = sk.decrypt(*cs[pos]).getValue() & 0x01;

		if (p != val[pos]) {

			std::cout << "WRONG initial decryption; should be " << val[pos] << ", decrypted " << p << '\n';
			std::cout.flush();
		}
	}

	

	auto ser_res = certFHE::Ciphertext::serialize(CS_CNT, cs);
	unsigned char * serialized = ser_res.first;

	auto deserialized_res = certFHE::Ciphertext::deserialize(serialized);
	certFHE::Ciphertext ** deserialized = deserialized_res.first;

	

	for (int i = 0; i < CS_CNT; i++) {

		uint64_t p = sk.decrypt(*deserialized[i]).getValue() & 0x01;

		if (p != val[i]) {

			std::cout << "WRONG deserialized decryption; should be " << val[i] << ", decrypted " << p << '\n';
			std::cout.flush();
		}
	}

	

	for (int ct = 0; ct < CS_CNT; ct++)
		delete deserialized[ct];

	delete[] deserialized;

	// save in file: the key, the serialization, and (if active) CNODE_disjoint_set stats
	std::fstream out(out_name, std::ios::binary | std::ios::out);

	std::pair <unsigned char *, int> sk_ser_res = sk.serialize();
	
	out.write((const char *)&(sk_ser_res.second), 4);
	out.write((const char *)sk_ser_res.first, sk_ser_res.second);

	out.write((const char *)&(ser_res.second), 4);
	out.write((const char *)serialized, ser_res.second);
	
	out.write((const char *)&CS_CNT, 4);
	out.write((const char *)val, 4 * CS_CNT);

	// for each ctxt, check if it has common root with other ctxts
	for (int i = 0; i < CS_CNT - 1; i++) {

		for (int j = i + 1; j < CS_CNT; j++) {

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT
			bool k = cs[i]->concurrency_guard->get_root() == cs[j]->concurrency_guard->get_root();
#else
			bool k = 0;
#endif
			out.write((const char *)&k, 1);
		}
	}
	
	out.flush();
	out.close();

	for (int ct = 0; ct < CS_CNT; ct++)
		delete cs[ct];

	delete[] val;
	delete[] serialized;
}

void load_rnd_ser_test(std::string in_name = "ser") {

	in_name += ".bin";

	std::fstream in(in_name, std::ios::binary | std::ios::in);

	int sk_ser_length;
	unsigned char * sk_ser;

	int ser_length;
	unsigned char * ser;

	int CS_CNT;
	int * val;

	in.read((char *)&sk_ser_length, 4);

	sk_ser = new unsigned char[sk_ser_length];
	in.read((char *)sk_ser, sk_ser_length);
	
	in.read((char *)&ser_length, 4);
	
	ser = new unsigned char[ser_length];
	in.read((char *)ser, ser_length);

	in.read((char *)&CS_CNT, 4);

	val = new int[CS_CNT];
	in.read((char *)val, 4 * CS_CNT);

	auto sk_deserialize_res = certFHE::SecretKey::deserialize(sk_ser);
	certFHE::SecretKey sk = sk_deserialize_res.first;

	auto deserialized_res = certFHE::Ciphertext::deserialize(ser);
	certFHE::Ciphertext ** deserialized = deserialized_res.first;

	

	for (int i = 0; i < CS_CNT; i++) {

		uint64_t p = sk.decrypt(*deserialized[i]).getValue() & 0x01;
		
		if (p != val[i]) {

			std::cout << "WRONG deserialized decryption; should be " << val[i] << ", decrypted " << p << '\n';
			std::cout.flush();
		}
	}

	

	// for each ctxt, check if it has common root with other ctxts
	for (int i = 0; i < CS_CNT - 1; i++) {

		for (int j = i + 1; j < CS_CNT; j++) {

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT
			bool k = deserialized[i]->concurrency_guard->get_root() == deserialized[j]->concurrency_guard->get_root();
#else
			bool k = 0;
#endif
			bool saved_k;
			in.read((char *)&saved_k, 1);

			if (k != saved_k)
				std::cout << "WRONG disjoint set stat: expecting " << saved_k << " got " << k << '\n';
		}
	}

	for (int ct = 0; ct < CS_CNT; ct++)
		delete deserialized[ct];

	delete[] deserialized;
	delete[] val;
	delete[] ser;
}

int main(){

	//old_implementation_compare_statistics_tests();

	//serialization_predefined_test("release_stats");

	//save_rnd_ser_test(100, 100, 1247, 16, "ser1");
	//load_rnd_ser_test("ser1");

    return 0;
}
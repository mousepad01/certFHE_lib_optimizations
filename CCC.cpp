#include "CCC.h"

namespace certFHE {

	CCC::CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt) : CNODE(context) {

		if (deflen_cnt > OPValues::max_ccc_deflen_size) {

			std::cout << "ERROR creating CCC node: deflen " << deflen_cnt
				<< " exceeds limit " << OPValues::max_ccc_deflen_size << "\n";

			throw new std::invalid_argument("ERROR creating CCC node: deflen exceeds limit");
		}
		else {

			this->deflen_count = deflen_cnt;
			this->ctxt = ctxt;
		}
			
		/*uint64_t fingerprint = 0;
		uint64_t deflen_u64_cnt = context->getDefaultN();

		uint64_t * current = ctxt;

		for (uint64_t i = 0; i < deflen_cnt; i++) {

			uint64_t hash_buffer[4] = {0, 0, 0, 0};
			SHA256((unsigned char *)current, sizeof(uint64_t) * deflen_u64_cnt, (unsigned char *)hash_buffer);

			fingerprint += hash_buffer[0];  // overflow does not matter, it is considered MOD 2^64

			current += deflen_u64_cnt;
		}*/
	}

	CCC::CCC(const CCC & other) : CNODE(other) {

		if (other.ctxt != 0 && other.deflen_count > 0) {

			uint64_t u64_length = this->deflen_count * this->context->getDefaultN();
			this->ctxt = new uint64_t[u64_length];

			for (int i = 0; i < u64_length; i++)
				this->ctxt[i] = other.ctxt[i];
		}
		else
			this->ctxt = 0;
	}

	CCC::CCC(const CCC && other) : CNODE(other) {

		this->deflen_count = other.deflen_count;
		this->ctxt = other.ctxt;
	}

	CCC::~CCC() {

		if (this->ctxt != 0)
			delete[] ctxt;
		else
			std::cout << "WARNIG: CCC ctxt pointer is null, should never be\n";
	}

	CNODE * CCC::make_copy() {

		return new CCC(*this);
	}

	void CCC::chunk_decrypt(Args * raw_args) {

		DecArgs * args = (DecArgs *)raw_args;

		uint64_t * to_decrypt = args->to_decrypt;
		uint64_t * sk_mask = args->sk_mask;
		uint64_t snd_deflen_pos = args->snd_deflen_pos;

		uint64_t default_len = args->default_len;

		uint64_t * decrypted = args->decrypted;

		*decrypted = 0;

#ifdef __AVX512F__

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			uint64_t u = 0;

			for (; u + 8 <= default_len; u += 8) {

				__m512i avx_aux = _mm512_loadu_si512((const void *)(current_chunk + u));
				__m512i avx_mask = _mm512_loadu_si512((const void *)(sk_mask + u));

				avx_aux = _mm512_and_si512(avx_aux, avx_mask);
				avx_aux = _mm512_xor_si512(avx_aux, avx_mask);

				__mmask8 is_zero_mask = _mm512_test_epi64_mask(avx_aux, avx_aux);
				current_decrypted &= (is_zero_mask == 0);
			}

			for (u; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#elif __AVX2__

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			uint64_t u = 0;

			for (; u + 4 <= default_len; u += 4) {

				__m256i avx_aux = _mm256_loadu_si256((const __m256i *)(current_chunk + u));
				__m256i avx_mask = _mm256_loadu_si256((const __m256i *)(sk_mask + u));

				avx_aux = _mm256_and_si256(avx_aux, avx_mask);
				avx_aux = _mm256_xor_si256(avx_aux, avx_mask);

				current_decrypted &= _mm256_testz_si256(avx_aux, avx_aux);
			}

			for (; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#else

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			for (uint64_t u = 0; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#endif

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_add(Args * raw_args) {

		AddArgs * args = (AddArgs *)raw_args;

		uint64_t * result = args->result;
		uint64_t * fst_chunk = args->fst_chunk;
		uint64_t * snd_chunk = args->snd_chunk;
		uint64_t fst_len = args->fst_len;

		uint64_t res_snd_deflen_pos = args->res_snd_deflen_pos;

		for (uint64_t i = args->res_fst_deflen_pos; i < res_snd_deflen_pos; i++)

			if (i < fst_len)
				result[i] = fst_chunk[i];
			else
				result[i] = snd_chunk[i - fst_len];

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_multiply(Args * raw_args) {

		MulArgs * args = (MulArgs *)raw_args;

		uint64_t * result = args->result;
		uint64_t * fst_chunk = args->fst_chunk;
		uint64_t * snd_chunk = args->snd_chunk;
		uint64_t snd_chlen = args->snd_chlen;
		uint64_t default_len = args->default_len;

		uint64_t res_snd_deflen_pos = args->res_snd_deflen_pos;
		uint64_t res_fst_deflen_pos = args->res_fst_deflen_pos;

		for (uint64_t i = args->res_fst_deflen_pos; i < res_snd_deflen_pos; i++) {

			uint64_t fst_ch_i = (i / snd_chlen) * default_len;
			uint64_t snd_ch_j = (i % snd_chlen) * default_len;

#ifdef __AVX512F__

			uint64_t k = 0;
			for (; k + 8 <= default_len; k += 8) {

				__m512i avx_fst_chunk = _mm512_loadu_si512((const void *)(fst_chunk + fst_ch_i + k));
				__m512i avx_snd_chunk = _mm512_loadu_si512((const void *)(snd_chunk + snd_ch_j + k));
				__m512i avx_result = _mm512_and_si512(avx_fst_chunk, avx_snd_chunk);

				_mm512_storeu_si512((void *)(result + i * default_len + k), avx_result);
			}

			for (; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#elif __AVX2__

			uint64_t k = 0;
			for (; k + 4 <= default_len; k += 4) {

				__m256i avx_fst_chunk = _mm256_loadu_si256((const __m256i *)(fst_chunk + fst_ch_i + k));
				__m256i avx_snd_chunk = _mm256_loadu_si256((const __m256i *)(snd_chunk + snd_ch_j + k));
				__m256i avx_result = _mm256_and_si256(avx_fst_chunk, avx_snd_chunk);

				_mm256_storeu_si256((__m256i *)(result + i * default_len + k), avx_result);
			}

			for (; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#else	

			for (uint64_t k = 0; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#endif
		}

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_permute(Args * raw_args) {

		PermArgs * args = (PermArgs *)raw_args;

		CtxtInversion * perm_invs = args->perm_invs;
		uint64_t inv_cnt = args->inv_cnt;
		uint64_t * ctxt = args->ctxt;
		uint64_t * res = args->res;
		uint64_t default_len = args->default_len;

		uint64_t snd_deflen_pos = args->snd_deflen_pos;

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = ctxt + i * default_len;
			uint64_t * current_chunk_res = res + i * default_len;

			for (uint64_t k = 0; k < inv_cnt; k++) {

				uint64_t fst_u64_ch = perm_invs[k].fst_u64_ch;
				uint64_t snd_u64_ch = perm_invs[k].snd_u64_ch;
				uint64_t fst_u64_r = perm_invs[k].fst_u64_r;
				uint64_t snd_u64_r = perm_invs[k].snd_u64_r;

#if MSVC_COMPILER_LOCAL_MACRO_WORSE

				//unsigned char val_i = _bittest64((const __int64 *)current_chunk + fst_u64_ch, fst_u64_r);
				//unsigned char val_j = _bittest64((const __int64 *)current_chunk + snd_u64_ch, snd_u64_r);

				unsigned char val_i = _bextr_u64(current_chunk[fst_u64_ch], fst_u64_r, 1);
				unsigned char val_j = _bextr_u64(current_chunk[snd_u64_ch], snd_u64_r, 1);

#else

				unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
				unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#endif

				if (val_i)
					current_chunk_res[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
				else
					current_chunk_res[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

				if (val_j)
					current_chunk_res[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
				else
					current_chunk_res[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
			}
		}

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	CCC * CCC::add(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();

		uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
		uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
		uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		uint64_t * res = new uint64_t[res_u64_cnt];
		
		if (res_u64_cnt < MTValues::add_m_threshold) {

			for (uint64_t i = 0; i < fst_u64_cnt; i++)
				res[i] = fst_c[i];

			for (uint64_t i = 0; i < snd_u64_cnt; i++)
				res[i + fst_u64_cnt] = snd_c[i];

		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->THR_CNT;

			AddArgs * args = new AddArgs[thread_count];

			uint64_t r = res_u64_cnt % thread_count;
			uint64_t q = res_u64_cnt / thread_count;

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].fst_len = fst_u64_cnt;

				threadpool->add_task(&chunk_add, args + thr);
			}

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64);
	}

	CCC * CCC::multiply(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();
		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		if (fst->deflen_count == 1 && snd->deflen_count == 1) {

			uint64_t* res = new uint64_t[deflen_to_u64];

			for (uint64_t i = 0; i < deflen_to_u64; i++)
				res[i] = fst_c[i] & snd_c[i];

			return new CCC(fst->context, res, 1);
		}

		uint64_t res_u64_cnt = (fst->deflen_count + snd->deflen_count) * deflen_to_u64;
		uint64_t * res = new uint64_t[res_u64_cnt];

		uint64_t fst_deflen_cnt = fst->deflen_count;
		uint64_t snd_deflen_cnt = snd->deflen_count;
		uint64_t res_deflen_cnt = fst_deflen_cnt * snd_deflen_cnt;

		if (res_u64_cnt < MTValues::mul_m_threshold) {

			for (uint64_t i = 0; i < res_deflen_cnt; i++) {

				uint64_t fst_ch_i = (i / snd_deflen_cnt) * deflen_to_u64;
				uint64_t snd_ch_j = (i % snd_deflen_cnt) * deflen_to_u64;

#ifdef __AVX512F__

				uint64_t k = 0;
				for (; k + 4 <= deflen_to_u64; k += 4) {

					__m512i avx_fst_c = _mm512_loadu_si512((const void *)(fst_c + fst_ch_i + k));
					__m512i avx_snd_c = _mm512_loadu_si512((const void *)(snd_c + snd_ch_j + k));
					__m512i avx_res = _mm512_and_si512(avx_fst_c, avx_snd_c);

					_mm512_storeu_si512((void *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & fst_c[snd_ch_j + k];

#elif __AVX2__

				uint64_t k = 0;
				for (; k + 4 <= deflen_to_u64; k += 4) {

					__m256i avx_fst_c = _mm256_loadu_si256((const __m256i *)(fst_c + fst_ch_i + k));
					__m256i avx_snd_c = _mm256_loadu_si256((const __m256i *)(snd_c + snd_ch_j + k));
					__m256i avx_res = _mm256_and_si256(avx_fst_c, avx_snd_c);

					_mm256_storeu_si256((__m256i *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#else

				for (uint64_t k = 0; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#endif
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->THR_CNT;

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= res_deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = res_deflen_cnt;
			}
			else {

				q = res_deflen_cnt / thread_count;
				r = res_deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			MulArgs * args = new MulArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].snd_chlen = snd_deflen_cnt;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_multiply, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return new CCC(fst->context, res, res_deflen_cnt);
	}

	CCC * CCC::permute(CCC * c, const Permutation & perm) {

		CtxtInversion * invs = perm.getInversions();
		uint64_t inv_cnt = perm.getInversionsCnt();

		uint64_t deflen_to_u64 = c->context->getDefaultN();
		uint64_t deflen_cnt = c->deflen_count;

		uint64_t * res = new uint64_t[deflen_cnt * deflen_to_u64];


		if (deflen_cnt < MTValues::perm_m_threshold) {

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = c->ctxt + i * deflen_to_u64;
				uint64_t * current_chunk_res = res + i * deflen_to_u64;

				for (uint64_t k = 0; k < inv_cnt; k++) {

					uint64_t fst_u64_ch = invs[k].fst_u64_ch;
					uint64_t snd_u64_ch = invs[k].snd_u64_ch;
					uint64_t fst_u64_r = invs[k].fst_u64_r;
					uint64_t snd_u64_r = invs[k].snd_u64_r;

#if MSVC_COMPILER_LOCAL_MACRO

					//unsigned char val_i = _bittest64((const __int64 *)current_chunk + fst_u64_ch, fst_u64_r);
					//unsigned char val_j = _bittest64((const __int64 *)current_chunk + snd_u64_ch, snd_u64_r);

					unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
					unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#else

					unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
					unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#endif

					if (val_i)
						current_chunk_res[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
					else
						current_chunk_res[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

					if (val_j)
						current_chunk_res[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
					else
						current_chunk_res[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
				}
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->THR_CNT;

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			PermArgs * args = new PermArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].perm_invs = invs;
				args[thr].inv_cnt = inv_cnt;

				args[thr].ctxt = c->ctxt;
				args[thr].res = res;

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_permute, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return new CCC(c->context, res, deflen_cnt);
	}

	uint64_t CCC::decrypt(const SecretKey & sk) {

		uint64_t dec = 0;

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t * sk_mask = sk.getMaskKey();
		uint64_t * ctxt = this->ctxt;

		if (deflen_cnt < MTValues::dec_m_threshold) {

#ifdef __AVX2__

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				uint64_t u = 0;

				for (; u + 4 <= deflen_to_u64; u += 4) {

					__m256i avx_aux = _mm256_loadu_si256((const __m256i *)(current_chunk + u));
					__m256i avx_mask = _mm256_loadu_si256((const __m256i *)(sk_mask + u));

					avx_aux = _mm256_and_si256(avx_aux, avx_mask);
					avx_aux = _mm256_xor_si256(avx_aux, avx_mask);

					current_decrypted &= _mm256_testz_si256(avx_aux, avx_aux);
				}

				for (; u < deflen_to_u64; u++)
					current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

				dec ^= current_decrypted;
			}

#else

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				for (uint64_t u = 0; u < deflen_to_u64; u++)
					current_decrypted &= (((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0);

				dec ^= current_decrypted;
			}

#endif
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->THR_CNT;

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			DecArgs * args = new DecArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].to_decrypt = ctxt;
				args[thr].sk_mask = sk_mask;

				args[thr].default_len = deflen_to_u64;
				args[thr].d = this->context->getD();

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].decrypted = new uint64_t;

				threadpool->add_task(&chunk_decrypt, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});

				dec ^= *(args[thr].decrypted);
			}

			delete[] args;
		}

		return dec;
	}

	void CCC::permute_inplace(const Permutation & perm) {

		CtxtInversion * invs = perm.getInversions();
		uint64_t inv_cnt = perm.getInversionsCnt();

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t len = deflen_to_u64 * deflen_cnt;

		if (deflen_cnt < MTValues::perm_m_threshold) {

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = this->ctxt + i * deflen_to_u64;

				for (uint64_t k = 0; k < inv_cnt; k++) {

					uint64_t fst_u64_ch = invs[k].fst_u64_ch;
					uint64_t snd_u64_ch = invs[k].snd_u64_ch;
					uint64_t fst_u64_r = invs[k].fst_u64_r;
					uint64_t snd_u64_r = invs[k].snd_u64_r;

#if GPP_COMPILER_LOCAL_MACRO

					unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
					unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#elif MSVC_COMPILER_LOCAL_MACRO

					unsigned char val_i = _bittest64((const __int64 *)current_chunk + fst_u64_ch, fst_u64_r);
					unsigned char val_j = _bittest64((const __int64 *)current_chunk + snd_u64_ch, snd_u64_r);

#endif

					if (val_i)
						current_chunk[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
					else
						current_chunk[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

					if (val_j)
						current_chunk[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
					else
						current_chunk[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
				}
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->THR_CNT;

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			PermArgs * args = new PermArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].perm_invs = invs;
				args[thr].inv_cnt = inv_cnt;

				args[thr].ctxt = this->ctxt;

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_permute, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}
	}
}

/*
void SHA256(unsigned char * msg, size_t msg_byte_size, unsigned char * digest_buffer) {

	size_t msg_bit_size = 8 * msg_byte_size;

	size_t msg_padded_bit_size = 512;

	while (msg_padded_bit_size < msg_bit_size + 1 + 64) /// sau msg_bit_size + 8 + 64, datorita lungimii multiplu de 8 de start
		msg_padded_bit_size += 512;

	unsigned char * padded_msg = new unsigned char[msg_padded_bit_size / 8];

	/// padding

	size_t pos;

	for (pos = 0; pos < msg_byte_size; pos++)
		padded_msg[pos] = msg[pos];

	padded_msg[pos] = (unsigned char)(1 << 7);
	pos++;

	size_t msg_padded_byte_size = msg_padded_bit_size / 8;

	for (; pos < msg_padded_byte_size - 8; pos++)
		padded_msg[pos] = 0;

	for (; pos < msg_padded_byte_size - 4; pos++)
		padded_msg[pos] = 0;

	size_t aux_m_bit_size = msg_bit_size;

	for (int i = 3; i >= 0; i--) {

		padded_msg[pos + i] = aux_m_bit_size & 255;
		aux_m_bit_size >>= 8;
	}

	uint32_t h[8];
	h[0] = 0x6a09e667;
	h[1] = 0xbb67ae85;
	h[2] = 0x3c6ef372;
	h[3] = 0xa54ff53a;
	h[4] = 0x510e527f;
	h[5] = 0x9b05688c;
	h[6] = 0x1f83d9ab;
	h[7] = 0x5be0cd19;

	uint32_t k[64] =
	{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	size_t chunk_cnt = msg_padded_bit_size / 512;

	for (uint32_t chunk = 0; chunk < chunk_cnt; chunk++) {

		/// w array processing

		size_t chunk_pos = 0;

		uint32_t * w = new uint32_t[64];

		size_t w_pos = 0;

		for (; w_pos < 16; w_pos++) {

			w[w_pos] = (uint32_t)(MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos] << 24)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 1] << 16)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 2] << 8)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 3])));

			chunk_pos += 4;
		}

		for (; w_pos < 64; w_pos++) {

			uint32_t s0 = ROTR32(w[w_pos - 15], 7) ^ ROTR32(w[w_pos - 15], 18) ^ MODPOW32(w[w_pos - 15] >> 3);
			uint32_t s1 = ROTR32(w[w_pos - 2], 17) ^ ROTR32(w[w_pos - 2], 19) ^ MODPOW32(w[w_pos - 2] >> 10);

			w[w_pos] = MODPOW32(w[w_pos - 16] + s0 + w[w_pos - 7] + s1);

		}

		/// compress

		uint32_t a = h[0];
		uint32_t b = h[1];
		uint32_t c = h[2];
		uint32_t d = h[3];
		uint32_t e = h[4];
		uint32_t f = h[5];
		uint32_t g = h[6];
		uint32_t hh = h[7];

		for (w_pos = 0; w_pos < 64; w_pos++) {

			uint32_t s1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = MODPOW32(hh + s1 + ch + k[w_pos] + w[w_pos]);
			uint32_t s0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = MODPOW32(s0 + maj);

			hh = g;
			g = f;
			f = e;
			e = MODPOW32(d + temp1);
			d = c;
			c = b;
			b = a;
			a = MODPOW32(temp1 + temp2);

		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += hh;

		delete[] w;
	}

	for (pos = 0; pos < 8; pos++) {

		for (int i = 3; i >= 0; i--) {

			digest_buffer[pos * 4 + i] = h[pos] & 255;
			h[pos] >>= 8;
		}
	}

	delete[] padded_msg;
}*/



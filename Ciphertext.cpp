#include "Ciphertext.h"
#include "GlobalParams.h"
#include "Threadpool.hpp"

//using namespace certFHE;

namespace certFHE{

#pragma region Public methods

	void chunk_permute(Args * raw_args) {

		PermArgs * args = (PermArgs *)raw_args;

		CtxtInversion * perm_invs = args->perm_invs;
		uint64_t inv_cnt = args->inv_cnt;
		uint64_t * ctxt = args->ctxt;
		uint64_t default_len = args->default_len;

		uint64_t snd_deflen_pos = args->snd_deflen_pos;

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = ctxt + i * default_len;

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
					current_chunk[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
				else
					current_chunk[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

				if (val_j)
					current_chunk[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
				else
					current_chunk[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
			}
		}

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	// TODO: get permutation as inversion product to optimise memory used 
	//			when doing the permutation
	void Ciphertext::applyPermutation_inplace(const Permutation& permutation)
	{

		CtxtInversion * invs = permutation.getInversions();
		uint64_t inv_cnt = permutation.getInversionsCnt();

		uint64_t len = this->len;
		uint64_t default_len = this->certFHEcontext->getDefaultN();

		uint64_t deflen_cnt = len / default_len;

		if (deflen_cnt < MTValues::perm_m_threshold) {

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = this->v + i * default_len;

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

				args[thr].ctxt = this->v;

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].default_len = default_len;

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

	Ciphertext Ciphertext::applyPermutation(const Permutation& permutation) {

		std::cout << "permutation not yet implemented\n";
		return *this;
		/*Ciphertext newCiphertext(*this);
		newCiphertext.applyPermutation_inplace(permutation);
		return newCiphertext;*/
	}

#pragma endregion

#pragma region Private methods

	CNODE * Ciphertext::add(CNODE * fst, CNODE * snd) {

		CADD * addition_result = new CADD(fst->context);

		/**
		 * From now on, fst and snd nodes
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		addition_result->nodes->insert_next_element(fst);
		addition_result->nodes->insert_next_element(snd);

		addition_result->upstream_merging();

		return addition_result;
	}

	CNODE * Ciphertext::multiply(CNODE * fst, CNODE * snd) {

		CMUL * mul_result = new CMUL(fst->context);

		/**
		 * From now on, fst and snd nodes 
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		mul_result->nodes->insert_next_element(fst);
		mul_result->nodes->insert_next_element(snd);

		mul_result->upstream_merging();

		return mul_result;
	}

	Plaintext Ciphertext::decrypt(const SecretKey & sk) const {


	}
#pragma endregion

#pragma region Operators

	std::ostream & operator<<(std::ostream &out, const Ciphertext &c)
	{
		uint64_t* _v = c.getValues();

		uint64_t u64_length = c.getLen();
		uint64_t n = c.certFHEcontext->getN();

		uint64_t current_bitlen;
		if (n > 64)
			current_bitlen = 64;
		else
			current_bitlen = n;

		for (uint64_t step = 0; step < u64_length; step++) {

			for (uint64_t b = 0; b < current_bitlen; b++) 
				out << (char)(0x30 | ((_v[step] >> (63 - b)) & 0x01));

			if (current_bitlen < 64)
				break;
			
			current_bitlen = (64 < n - current_bitlen) ? 64 : (n - current_bitlen);
			n -= current_bitlen;

		}
		out << '\n';

		return out;
	}

	Ciphertext Ciphertext::operator+(const Ciphertext& c) const {

		uint64_t newlen = this->len + c.getLen();

		uint64_t len2 = c.getLen();

		uint64_t outlen = 0;
		uint64_t* _values = add(this->v, c.v, this->len, len2, outlen);

		Ciphertext result;

		result.len = newlen;
		result.v = _values;
		result.certFHEcontext = new Context(*this->certFHEcontext);

		return result;
	}

	Ciphertext Ciphertext::operator*(const Ciphertext& c) const
	{
		uint64_t len2 = c.getLen();
		uint64_t *valuesSecondOperand = c.getValues();

		uint64_t newlen = 0;
		uint64_t * _values = multiply(this->getContext(), this->v, valuesSecondOperand, this->len, len2, newlen);

		Ciphertext result;

		result.len = newlen;
		result.v = _values;
		result.certFHEcontext = new Context(*this->certFHEcontext);

		return result;
	}

	Ciphertext& Ciphertext::operator+=(const Ciphertext& c)
	{
		uint64_t newlen = this->len + c.getLen();

		uint64_t len2 = c.getLen();

		uint64_t outlen = 0;
		uint64_t* _values = add(this->v, c.v, this->len, len2, outlen);

		if (this->v != nullptr)
			delete[] this->v;

		this->v = _values;
		this->len = newlen;

		return *this;
	}

	Ciphertext& Ciphertext::operator*=(const Ciphertext& c)
	{
		uint64_t len2 = c.getLen();
		uint64_t *valuesSecondOperand = c.getValues();

		uint64_t newlen = 0;
		uint64_t * _values = multiply(this->getContext(), this->v, valuesSecondOperand, this->len, len2, newlen);

		if (this->v != nullptr)
			delete[] this->v;

		this->v = _values;
		this->len = newlen;

		return *this;

	}

	Ciphertext& Ciphertext::operator=(const Ciphertext& c)
	{
		if (this->v != nullptr)
			delete[] this->v;

		if (this->certFHEcontext != nullptr)
			delete this->certFHEcontext;

		this->len = c.getLen();
		this->v = new uint64_t[this->len];

		if (c.certFHEcontext != nullptr)
			this->certFHEcontext = new Context(*c.certFHEcontext);
		else
			this->certFHEcontext = nullptr;

		uint64_t* _v = c.getValues();

		uint64_t u64_len = this->len;

		if (u64_len < MTValues::cpy_m_threshold)
			for (uint64_t i = 0; i < u64_len; i++)
				this->v[i] = _v[i];
		else
			Helper::u64_multithread_cpy(_v, this->v, u64_len);

		return *this;
	}

	Ciphertext& Ciphertext::operator=(Ciphertext && c)
	{
		if (this->v != nullptr)
			delete[] this->v;

		if (this->certFHEcontext != nullptr)
			delete this->certFHEcontext;

		this->len = c.len;
		this->v = c.v;
		this->certFHEcontext = c.certFHEcontext;

		c.v = nullptr;
		c.certFHEcontext = nullptr;

		return *this;
	}

#pragma endregion

#pragma region Constructors and destructor

	Ciphertext::Ciphertext() {

		this->node = 0;
	}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt(plaintext);
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt(plaintext);
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
	}

	Ciphertext::Ciphertext(const Ciphertext & ctxt) {

		ctxt.node->downstream_reference_count += 1;
		this->node = ctxt.node;
	}

	Ciphertext::Ciphertext(Ciphertext && ctxt) {

		this->node = ctxt.node;
	}

	Ciphertext::~Ciphertext() {

		this->node->try_delete();
	}

#pragma endregion

#pragma region Getters and Setters

	uint64_t Ciphertext::getLen() const {

		return this->node->getDeflenCnt();
	}

	Context Ciphertext::getContext() const {

		return this->node->getContext();
	}

#pragma endregion

}


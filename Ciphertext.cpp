#include "Ciphertext.h"
#include "GlobalParams.h"
#include "Threadpool.hpp"

using namespace certFHE;

#pragma region Public methods

void certFHE::chunk_permute(Args * raw_args) {

	PermArgs * args = (PermArgs *)raw_args;

	uint64_t * perm = args->perm;
	uint64_t * original_c = args->original_c;
	uint64_t * result_c = args->result_c;
	uint64_t default_len = args->default_len;
	uint64_t n = args->n;

	for (uint64_t i = args->fst_deflen_pos; i < args->snd_deflen_pos; i++) {

		uint64_t * current_chunk_original = original_c + i * default_len;
		uint64_t * current_chunk_result = result_c + i * default_len;

		for (uint64_t k = 0; k < n; k++) {

			int u64_k = k / 64;
			int b_k = 63 - (k % 64);

			int u64_p = perm[k] / 64;
			int b_p = 63 - (perm[k] % 64);

			current_chunk_result[u64_k] |= ((current_chunk_original[u64_p] >> b_p) & 0x01) << b_k;
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
	uint64_t * result_v = new uint64_t[this->len];
	memset(result_v, 0, sizeof(uint64_t) * this->len);

	uint64_t * perm = permutation.getPermutation();

	uint64_t len = this->len;
	uint64_t default_len = this->certFHEcontext->getDefaultN();

	uint64_t deflen_cnt = len / default_len;

	Threadpool <Args *> * threadpool = Library::getThreadpool();
	int thread_count = threadpool->THR_CNT;

	uint64_t q;
	uint64_t r;

	int worker_cnt;

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

	int prevchnk = 0;

	for (int thr = 0; thr < worker_cnt; thr++) {

		args[thr].perm = perm;

		args[thr].original_c = this->v;
		args[thr].result_c = result_v;

		args[thr].fst_deflen_pos = prevchnk;
		args[thr].snd_deflen_pos = prevchnk + q;

		if (r > 0) {

			args[thr].snd_deflen_pos += 1;
			r -= 1;
		}
		prevchnk = args[thr].snd_deflen_pos;

		args[thr].n = this->certFHEcontext->getN();
		args[thr].default_len = default_len;

		threadpool->add_task(&chunk_permute, args + thr);
	}

	for (int thr = 0; thr < worker_cnt; thr++) {

		std::unique_lock <std::mutex> lock(args[thr].done_mutex);

		args[thr].done.wait(lock, [thr, args] {
			return args[thr].task_is_done;
		});
	}

	delete[] args;

	delete[] this->v;
	this->v = result_v;
}

Ciphertext Ciphertext::applyPermutation(const Permutation& permutation)
{
	Ciphertext newCiphertext(*this);
	newCiphertext.applyPermutation_inplace(permutation);
	return newCiphertext;
}

long Ciphertext::size()
{
	long size = 0;
	size += sizeof(this->certFHEcontext);
	size += sizeof(this->len);
	size += sizeof(this->v);

	size += this->len * 2 * sizeof(uint64_t);
	return size;
}

#pragma endregion

#pragma region Private methods

void certFHE::chunk_add(Args * raw_args) {

	AddArgs * args = (AddArgs *)raw_args;

	uint64_t * result = args->result;
	uint64_t * fst_chunk = args->fst_chunk;
	uint64_t * snd_chunk = args->snd_chunk;
	uint64_t fst_len = args->fst_len;
	uint64_t snd_len = args->snd_len;

	for (uint64_t i = args->res_fst_deflen_pos; i < args->res_snd_deflen_pos; i++)

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

uint64_t* Ciphertext::add(uint64_t* c1, uint64_t* c2, uint64_t len1, uint64_t len2, uint64_t &newlen) const
{
	uint64_t* res = new uint64_t[len1 + len2];
	newlen = len1 + len2;

	if (newlen < 10000) {

		for (int i = 0; i < len1; i++)
		{
			res[i] = c1[i];
		}

		for (int i = 0; i < len2; i++)
		{
			res[i + len1] = c2[i];
		}
	}
	else {

		Threadpool <Args *> * threadpool = Library::getThreadpool();
		int thread_count = threadpool->THR_CNT;

		AddArgs * args = new AddArgs[thread_count];

		uint64_t r = newlen % thread_count;
		uint64_t q = newlen / thread_count;

		int prevchnk = 0;

		for (int thr = 0; thr < thread_count; thr++) {

			args[thr].fst_chunk = c1;
			args[thr].snd_chunk = c2;

			args[thr].result = res;

			args[thr].res_fst_deflen_pos = prevchnk;
			args[thr].res_snd_deflen_pos = prevchnk + q;

			if (r > 0) {

				args[thr].res_snd_deflen_pos += 1;
				r -= 1;
			}
			prevchnk = args[thr].res_snd_deflen_pos;

			args[thr].fst_len = len1;
			args[thr].snd_len = len2;

			threadpool->add_task(&chunk_add, args + thr);
		}

		for (int thr = 0; thr < thread_count; thr++) {

		std:unique_lock <std::mutex> lock(args[thr].done_mutex);

			args[thr].done.wait(lock, [thr, args] {
				return args[thr].task_is_done;
			});
		}

		delete[] args;
	}

	return res;
}

uint64_t* Ciphertext::defaultN_multiply(uint64_t* c1, uint64_t* c2, uint64_t len) const
{
	uint64_t* res = new uint64_t[len];
	for (int i = 0; i < len; i++)
		res[i] = c1[i] & c2[i];

	return res;
}

void certFHE::chunk_multiply(Args * raw_args) {

	MulArgs * args = (MulArgs *)raw_args;

	uint64_t * result = args->result;
	uint64_t * fst_chunk = args->fst_chunk;
	uint64_t * snd_chunk = args->snd_chunk;
	uint64_t fst_chlen = args->fst_chlen;
	uint64_t snd_chlen = args->snd_chlen;
	uint64_t default_len = args->default_len;

	for (uint64_t i = args->res_fst_deflen_pos; i < args->res_snd_deflen_pos; i++) {

		uint64_t fst_ch_i = (i / snd_chlen) * default_len;
		uint64_t snd_ch_j = (i % snd_chlen) * default_len;

		for (int k = 0; k < default_len; k++)
			result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];
	}

	{
		std::lock_guard <std::mutex> lock(args->done_mutex);

		args->task_is_done = true;
		args->done.notify_all();
	}
}

uint64_t* Ciphertext::multiply(const Context& ctx, uint64_t *c1, uint64_t*c2, uint64_t len1, uint64_t len2, uint64_t& newlen) const
{
	newlen = len1;

	uint64_t _defaultLen = ctx.getDefaultN();
	if (len1 == _defaultLen)
		if (len1 == len2)
			return defaultN_multiply(c1, c2, len1);

	newlen = (len1 / _defaultLen * len2 / _defaultLen) * _defaultLen;

	uint64_t* res = new uint64_t[newlen];
	uint64_t times1 = len1 / _defaultLen;
	uint64_t times2 = len2 / _defaultLen;

	Threadpool <Args *> * threadpool = Library::getThreadpool();

	int thread_count = threadpool->THR_CNT;
	uint64_t res_defChunks_len = times1 * times2;

	uint64_t q;
	uint64_t r;

	int worker_cnt;

	if (thread_count >= res_defChunks_len) {

		q = 1;
		r = 0;

		worker_cnt = res_defChunks_len;
	}
	else {

		q = res_defChunks_len / thread_count;
		r = res_defChunks_len % thread_count;

		worker_cnt = thread_count;
	}

	MulArgs * args = new MulArgs[worker_cnt];

	int prevchnk = 0;

	for (int thr = 0; thr < worker_cnt; thr++) {

		args[thr].fst_chunk = c1;
		args[thr].snd_chunk = c2;

		args[thr].result = res;

		args[thr].res_fst_deflen_pos = prevchnk;
		args[thr].res_snd_deflen_pos = prevchnk + q;

		if (r > 0) {

			args[thr].res_snd_deflen_pos += 1;
			r -= 1;
		}
		prevchnk = args[thr].res_snd_deflen_pos;

		args[thr].fst_chlen = times1;
		args[thr].snd_chlen = times2;

		args[thr].default_len = _defaultLen;

		threadpool->add_task(&chunk_multiply, args + thr);
	}

	for (int thr = 0; thr < worker_cnt; thr++) {

		std::unique_lock <std::mutex> lock(args[thr].done_mutex);

		args[thr].done.wait(lock, [thr, args] {
			return args[thr].task_is_done;
		});
	}

	delete[] args;

	return res;
}

#pragma endregion

#pragma region Operators

ostream& certFHE::operator<<(ostream &out, const Ciphertext &c)
{
	uint64_t* _v = c.getValues();

	uint64_t u64_length = c.getLen();
	uint64_t n = c.certFHEcontext->getN();

	uint64_t current_bitlen;
	if (n > 64)
		current_bitlen = 64;
	else
		current_bitlen = n;

	for (int step = 0; step < u64_length; step++) {

		for (int b = 0; b < current_bitlen; b++)
			out << (char)(0x30 | ((_v[step] >> (63 - b)) & 0x01));

		if (current_bitlen < 64)
			current_bitlen = 0;
		else
			current_bitlen = (64 > n - current_bitlen) ? 64 : (n - current_bitlen);

	}
	out << '\n';

	return out;
}

Ciphertext Ciphertext::operator+(const Ciphertext& c) const
{
	long newlen = this->len + c.getLen();

	uint64_t len2 = c.getLen();

	uint64_t outlen = 0;
	uint64_t* _values = add(this->v, c.v, this->len, len2, outlen);

	Ciphertext result(_values, newlen, *this->certFHEcontext);

	delete[] _values;
	return result;
}

Ciphertext Ciphertext::operator*(const Ciphertext& c) const
{
	uint64_t len2 = c.getLen();
	uint64_t *valuesSecondOperand = c.getValues();

	uint64_t newlen = 0;
	uint64_t * _values = multiply(this->getContext(), this->v, valuesSecondOperand, this->len, len2, newlen);

	Ciphertext result(_values, newlen, *this->certFHEcontext);

	delete[] _values;

	return result;
}

Ciphertext& Ciphertext::operator+=(const Ciphertext& c)
{
	long newlen = this->len + c.getLen();

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

#pragma endregion

#pragma region Constructors and destructor

Ciphertext::Ciphertext()
{
	this->v = nullptr;
	this->len = 0;
	this->certFHEcontext = nullptr;
}

Ciphertext::Ciphertext(const uint64_t* V, const uint64_t len, const Context& context) : Ciphertext()
{
	this->len = len;
	this->v = new uint64_t[len];

	if (len < MTValues::cpy_m_threshold)
		for (uint64_t i = 0; i < len; i++)
			this->v[i] = V[i];

	else
		Helper::u64_multithread_cpy(V, this->v, len);
		
	if (&context != nullptr)
		this->certFHEcontext = new Context(context);
}

Ciphertext::Ciphertext(const Ciphertext& ctxt) : Ciphertext(ctxt.v, ctxt.len, (const Context&)*ctxt.certFHEcontext)
{

}

Ciphertext::~Ciphertext()
{

	if (this->v != nullptr)
	{
		delete[] this->v;
		this->v = nullptr;
	}

	if (this->certFHEcontext != nullptr)
	{
		delete certFHEcontext;
		certFHEcontext = nullptr;
	}

	this->len = 0;
}

#pragma endregion

#pragma region Getters and Setters

void Ciphertext::setValues(const uint64_t * V, const uint64_t length)
{
	this->len = length;

	if (this->v != nullptr)
		delete[] this->v;

	this->v = new uint64_t[length];

	if (length < MTValues::cpy_m_threshold)
		for (uint64_t i = 0; i < length; i++)
			this->v[i] = V[i];
	else
		Helper::u64_multithread_cpy(V, this->v, len);
}

uint64_t  Ciphertext::getLen() const
{
	return this->len;
}

uint64_t* Ciphertext::getValues() const
{
	return this->v;
}

void Ciphertext::setContext(const Context& context)
{
	if (this->certFHEcontext != nullptr)
		delete certFHEcontext;
	certFHEcontext = new Context(context);
}

Context Ciphertext::getContext() const
{
	return *(this->certFHEcontext);
}

#pragma endregion
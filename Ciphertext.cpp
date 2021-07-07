#include "Ciphertext.h"
#include "Threadpool.hpp"

using namespace certFHE;

#pragma region Public methods
  
void Ciphertext::applyPermutation_inplace(const Permutation& permutation)
{
    uint64_t result_len =0;
    uint64_t *result_bitlen = nullptr;
    uint64_t *result_v = nullptr;

    uint64_t *perm = permutation.getPermutation();
   	
	int size = 0;
	for (int i = 0; i < len; i++)
		size += bitlen[i];
	
	uint64_t* temp = new uint64_t[size];
	uint64_t* temp2 = new uint64_t[size];
	uint64_t tval;
	int pos = 0;
	for (int i = 0; i < len; i++)
	{
		for (int j = 0; j < bitlen[i]; j++)
		{
			tval = (v[i] >> (sizeof(uint64_t)*8-1 - j)) & 0x01;
			temp[pos++] = tval;
		}
	}
	
	uint64_t defBitSize = this -> certFHEcontext -> getN();
	for (int i = 0; i < size; i++) 
		temp2[i] = temp[(i / defBitSize) * defBitSize + perm[i % defBitSize]];

	result_len = this->len;
	
	result_bitlen = new uint64_t[result_len];
	for(int i = 0; i < result_len; i++)
		result_bitlen[i] = this->bitlen[i];

	result_v = new uint64_t[result_len];

	int offset = 0;
	for (int i = 0; i < result_len; i++) {

		result_v[i] = 0;
		for (int b = 0; b < result_bitlen[i]; b++) 
			result_v[i] |= temp2[offset + b] << (sizeof(uint64_t) * 8 - 1 - b);

		offset += bitlen[i];
	}

	if (temp)
		delete[] temp;

	if (temp2)
		delete[] temp2;

    delete [] this->bitlen;
    delete [] this->v;
    this->len = result_len;
    this->bitlen = result_bitlen;
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
    long size  = 0;
    size+=sizeof(this->certFHEcontext);
    size+=sizeof(this->len);
    size+=sizeof(this->v);
    size+=sizeof(this->bitlen);

    size+= this->len *2 * sizeof(uint64_t);
    return size;
}

#pragma endregion

#pragma region Private methods

void certFHE::chunk_add(Args * raw_args) {

	AddArgs * args = (AddArgs *)raw_args;

	uint64_t * result = args->result;
	uint64_t * result_bitlen = args->result_bitlen;
	uint64_t * fst_chunk = args->fst_chunk;
	uint64_t * snd_chunk = args->snd_chunk;
	uint64_t * fst_input_bitlen = args->fst_input_bitlen;
	uint64_t * snd_input_bitlen = args->snd_input_bitlen;
	uint64_t fst_len = args->fst_len;
	uint64_t snd_len = args->snd_len;

	for (uint64_t i = args->res_fst_deflen_pos; i < args->res_snd_deflen_pos; i++) 

		if (i < fst_len) {

			result[i] = fst_chunk[i];
			result_bitlen[i] = fst_input_bitlen[i];
		}
		else {

			result[i] = snd_chunk[i - fst_len];
			result_bitlen[i] = snd_input_bitlen[i - fst_len];
		}
	

	{
		std::lock_guard <std::mutex> lock(args->done_mutex);
		args->task_is_done = true;
	}

	args->done.notify_all();
}

uint64_t* Ciphertext::add(uint64_t* c1,uint64_t* c2,uint64_t len1,uint64_t len2, uint64_t &newlen, uint64_t* bitlenin1, uint64_t* bitlenin2, uint64_t*& bitlenout) const
{	
    uint64_t* res = new uint64_t[len1+len2];
    newlen = len1+len2;

	if (newlen < 10000) {

		for (int i = 0; i < len1; i++)
		{
			res[i] = c1[i];
		}

		for (int i = 0; i < len2; i++)
		{
			res[i + len1] = c2[i];
		}

		for (int i = 0; i < len1; i++)
		{
			bitlenout[i] = bitlenin1[i];
		}
		for (int i = 0; i < len2; i++)
		{
			bitlenout[len1 + i] = bitlenin2[i];
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
			args[thr].fst_input_bitlen = bitlenin1;
			args[thr].snd_input_bitlen = bitlenin2;

			args[thr].result = res;
			args[thr].result_bitlen = bitlenout;

			args[thr].res_fst_deflen_pos = prevchnk;
			args[thr].res_snd_deflen_pos = prevchnk + q;

			if (r > 0) {

				args[thr].res_snd_deflen_pos += 1;
				r -= 1;
			}
			prevchnk = args[thr].res_snd_deflen_pos;

			args[thr].fst_len = len1;
			args[thr].snd_len = len2;

			args[thr].task_is_done = false;

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

void certFHE::chunk_multiply(Args * raw_args){

	MulArgs * args = (MulArgs *)raw_args;

    uint64_t * result = args -> result;
    uint64_t * fst_chunk = args -> fst_chunk;
    uint64_t * snd_chunk = args -> snd_chunk;
    uint64_t * input_bitlen = args -> input_bitlen;
    uint64_t * result_bitlen = args -> result_bitlen;
    uint64_t fst_chlen = args -> fst_chlen;
    uint64_t snd_chlen = args -> snd_chlen;
    uint64_t default_len = args -> default_len;

	for (uint64_t i = args->res_fst_deflen_pos; i < args->res_snd_deflen_pos; i++) {

		uint64_t fst_ch_i = (i / snd_chlen) * default_len;
		uint64_t snd_ch_j = (i % snd_chlen) * default_len;

		for (int k = 0; k < default_len; k++) {

			result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

			result_bitlen[i * default_len + k] = input_bitlen[k]; // input_bitlen[fst_ch_i + k] also works 
		}
	}

	{
		std::lock_guard <std::mutex> lock(args->done_mutex);
		args->task_is_done = true;
	}

	args->done.notify_all();
}

uint64_t* Ciphertext::multiply(const Context& ctx,uint64_t *c1,uint64_t*c2,uint64_t len1,uint64_t len2, uint64_t& newlen,uint64_t* bitlenin1,uint64_t* bitlenin2,uint64_t*& bitlenout) const
{
 newlen=len1;
 uint64_t _defaultLen = ctx.getDefaultN();
    if (len1 == _defaultLen)
   		 if (len1 == len2)
       		 {
				bitlenout = new  uint64_t [newlen];
				for(int i = 0 ; i<newlen;i++)
					bitlenout[i] = bitlenin1[i];
				return defaultN_multiply(c1,c2,len1);
		  	 } 

    newlen= (len1/_defaultLen *  len2/_defaultLen ) * _defaultLen;

	bitlenout = new  uint64_t [newlen];
	uint64_t* res = new uint64_t[newlen];
    uint64_t times1 = len1/_defaultLen;
    uint64_t times2 = len2/_defaultLen;

	Threadpool <Args *> * threadpool = Library::getThreadpool();

    int thread_count = threadpool -> THR_CNT;
	uint64_t res_defChunks_len = times1 * times2;

	// if there are more threads than final chunks, assign a thread 
	// for each multiplication of two default len chunks
	//
	// else
	// each thread is assigned an equal number (+- 1) of default len multiplications
	// (differences appear when number of deflen multiplications does not divide by the number of threads)

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

    for(int thr = 0; thr < worker_cnt; thr++){

        args[thr].fst_chunk = c1;
        args[thr].snd_chunk = c2;
        args[thr].input_bitlen = bitlenin1;

        args[thr].result = res;
        args[thr].result_bitlen = bitlenout;

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

		args[thr].task_is_done = false;

        threadpool -> add_task(&chunk_multiply, args + thr);
    }

	for (int thr = 0; thr < thread_count; thr++) {

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
    uint64_t* _v =      c.getValues();
    uint64_t* _bitlen = c.getBitlen();

    int div = c.getLen();
    uint64_t length = c.getLen();
	for (int step =0;step<length;step++)
	{
		    std::bitset<64> bs (_v[step]);	
			for (int s = 0;s< _bitlen[step];s++)
			{
				out<<bs.test(63-s);
			}
	}	
    out<<std::endl;
    return out;
}

Ciphertext Ciphertext::operator+(const Ciphertext& c) const
{
	long newlen = this->len + c.getLen();
    uint64_t* _bitlen = new uint64_t [newlen];

    uint64_t len2 = c.getLen();
    uint64_t* bitlenCtxt2 = c.getBitlen();

    uint64_t outlen = 0;
    uint64_t* _values = add(this->v,c.v,this->len,len2,outlen,this->bitlen,c.bitlen,_bitlen);

    Ciphertext result(_values,_bitlen,newlen,*this->certFHEcontext);
    delete [] _bitlen;
    delete [] _values;
    return result;
}

Ciphertext Ciphertext::operator*(const Ciphertext& c) const
{
    uint64_t len2 = c.getLen();
    uint64_t *valuesSecondOperand = c.getValues();
    uint64_t *bitlenSecondOperand = c.getBitlen();
    
    uint64_t newlen=0;
    uint64_t * _bitlen = nullptr;
    uint64_t * _values =multiply(this->getContext(),this->v,valuesSecondOperand,this->len,len2,newlen,this->bitlen,bitlenSecondOperand,_bitlen);
	
    Ciphertext result(_values,_bitlen,newlen,*this->certFHEcontext);
	    
    delete [] _values;
    delete [] _bitlen;

    return result;
}

Ciphertext& Ciphertext::operator+=(const Ciphertext& c)
{
    long newlen = this->len + c.getLen();
    uint64_t* _bitlen = new uint64_t [newlen];

    uint64_t len2 = c.getLen();
    uint64_t* bitlenCtxt2 = c.getBitlen();

    uint64_t outlen = 0;
    uint64_t* _values = add(this->v,c.v,this->len,len2,outlen,this->bitlen, c.bitlen, _bitlen);

    if (this->v != nullptr)
        delete [] this->v;
    if (this->bitlen != nullptr)
        delete [] this->bitlen;

    this->bitlen = _bitlen;
    this->v = _values;
    this->len = newlen;

    return *this;
}

Ciphertext& Ciphertext::operator*=(const Ciphertext& c)
{
    uint64_t len2 = c.getLen();
    uint64_t *valuesSecondOperand = c.getValues();
    uint64_t *bitlenSecondOperand = c.getBitlen();
    
    uint64_t newlen=0;
    uint64_t * _bitlen = nullptr;
    uint64_t * _values =multiply(this->getContext(),this->v,valuesSecondOperand,this->len,len2,newlen,this->bitlen,bitlenSecondOperand,_bitlen);
	
    if (this->v != nullptr)
        delete [] this->v;
    if (this->bitlen != nullptr)
        delete [] this->bitlen;
    
    this->v = _values;
    this->bitlen = _bitlen;
    this->len = newlen;

    return *this;

}

Ciphertext& Ciphertext::operator=(const Ciphertext& c)
{
    if (this->bitlen != nullptr)
        delete [] this->bitlen;
    if (this->v != nullptr)
        delete [] this->v;
    if (this->certFHEcontext != nullptr)
        delete this->certFHEcontext;

    this->len = c.getLen();
    this->v  = new uint64_t [this->len];
    this->bitlen  = new uint64_t [this->len];

	if (c.certFHEcontext != nullptr)
		this -> certFHEcontext = new Context(*c.certFHEcontext); 
	else
		this -> certFHEcontext = nullptr;

    uint64_t* _v = c.getValues();
    uint64_t* _bitlen = c.getBitlen();

    for(uint64_t i = 0;i<this->len;i++)
    {
        this->v[i] = _v[i];
        this->bitlen[i] = _bitlen[i];
    }

    return *this;
}

#pragma endregion

#pragma region Constructors and destructor

Ciphertext::Ciphertext()
{
    this->bitlen = nullptr;
    this->v = nullptr;
    this->len = 0;
    this->certFHEcontext = nullptr;

}

Ciphertext::Ciphertext(const uint64_t* V,const uint64_t * Bitlen,const uint64_t len,const Context& context) : Ciphertext()
{
    this->len = len;
    this->v = new uint64_t [len];
    this->bitlen = new uint64_t [len];
    
    for (uint64_t i =0; i<len;i++)
    {
        this->v[i] = V[i];
        this->bitlen[i] = Bitlen[i];
    }

	if(&context != nullptr)
		this->certFHEcontext = new Context(context);
}

Ciphertext::Ciphertext(const Ciphertext& ctxt) : Ciphertext(ctxt.v,ctxt.bitlen,ctxt.len,(const Context&)*ctxt.certFHEcontext)
{
   
}

Ciphertext::~Ciphertext()
{
    if (this->bitlen != nullptr)
    {
        delete [] this->bitlen;
        this->bitlen = nullptr;
    }

    if (this->v != nullptr)
    {
        delete [] this->v;
        this->v = nullptr;
    }

    if (this->certFHEcontext != nullptr)
    {
        delete certFHEcontext;
        certFHEcontext = nullptr;
    }

    this->len =0;
}

#pragma endregion

#pragma region Getters and Setters

void Ciphertext::setValues(const uint64_t * V,const uint64_t length)
{
   this->len = length;
 
   if (this->v != nullptr)
    delete [] this->v;

   this->v = new uint64_t [length];
   for(uint64_t i=0;i<length;i++)
        this->v [i] = V[i];
    
}

void Ciphertext::setBitlen(const uint64_t * Bitlen,const uint64_t length)
{
    this->len = length;
 
   if (this->bitlen != nullptr)
    delete [] this->bitlen;

   this->bitlen = new uint64_t [length];
   for(uint64_t i=0;i<length;i++)
    this->bitlen [i] = Bitlen[i];
}

uint64_t  Ciphertext::getLen() const
{
    return this->len;
}

uint64_t* Ciphertext::getValues() const
{
    return this->v;
}

uint64_t* Ciphertext::getBitlen() const
{
    return this->bitlen;
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
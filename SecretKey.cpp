#include "SecretKey.h"

using namespace certFHE;
using namespace std;

#pragma region Operators

SecretKey& SecretKey::operator=(const SecretKey& secKey)
{
	if (this->s != nullptr)
	{
		delete [] this->s;
	}

	this->length = secKey.length;
	this->s = new uint64_t [secKey.length];
	for(uint64_t i =0 ;i<secKey.length;i++)
		this->s[i] = secKey.s[i];
	return *this;
}

ostream& certFHE::operator<<(ostream &out, const SecretKey &c)
  {
	  uint64_t* key = c.getKey();
	  for(long i =0;i<c.getLength();i++)
	  	out<<key[i]<<" ";
	  out<<endl;
	  return out;
  }

#pragma endregion

#pragma region Private functions

uint64_t* SecretKey::encrypt(unsigned char bit, uint64_t n, uint64_t d, uint64_t*s)
{
     //@TODO: generate only a random of size n-d instead of n-d randoms()
	uint64_t* res = new uint64_t[n];
	bit = BIT(bit);

	if (bit == 0x01)
	{
		for (int i = 0; i < n; i++)
			if (Helper::exists(s, d, i))
				res[i] = 0x01;
			else
				res[i] = rand() % 2;
	}
	else
	{
		uint64_t sRandom = rand() % d;
		uint64_t v = 0x00;
		bool vNok = true;

		for (int i = 0; i < n; i++)
			if (i != s[sRandom])
			{
				res[i] = rand() % 2;

				if (Helper::exists(s,d,i))
				{
					if (vNok)
					{
						v = res[i];
						vNok = false;
					}
					v = v & res[i];

				}

			}

		if (v == 0x01)
		res[s[sRandom]] = 0;
		else
		res[s[sRandom]] = rand() %2;

	}
	return res;
}

uint64_t SecretKey::defaultN_decrypt(uint64_t* v,uint64_t len, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
{
	uint64_t decrypted = 0x01;

	for (int j = 0; j < d; j++) {

		int u64_i = s[j] / 64;
		int b = 63 - (s[j] % 64);

		decrypted &= v[u64_i] >> b;
	}

	return decrypted;
}

void certFHE::chunk_decrypt(Args * raw_args) {

	DecArgs * args = (DecArgs *)raw_args;

	uint64_t * to_decrypt = args->to_decrypt;
	uint64_t * sk = args->sk;

	uint64_t default_len = args->default_len;

	uint64_t * decrypted = args->decrypted;

	*decrypted = 0;

	for (uint64_t i = args->fst_deflen_pos; i < args->snd_deflen_pos; i++) {

		uint64_t * current_chunk = to_decrypt + i * default_len;
		uint64_t current_decrypted = 0x01;

		for (int j = 0; j < args->d; j++) {

			int u64_i = sk[j] / 64;
			int b = 63 - (sk[j] % 64);

			current_decrypted &= current_chunk[u64_i] >> b;
		}

		*decrypted ^= current_decrypted;
	}

	{
		std::lock_guard <std::mutex> lock(args->done_mutex);
		args->task_is_done = true;
	}

	args->done.notify_all();
}

uint64_t SecretKey::decrypt(uint64_t* v,uint64_t len,uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
{
      
	if (len == defLen)
        return defaultN_decrypt(v,len,n,d,s,bitlen);

	uint64_t dec;

	uint64_t deflen_cnt = len / defLen;

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

	DecArgs * args = new DecArgs[worker_cnt];

	uint64_t prevchnk = 0;

	for (int thr = 0; thr < worker_cnt; thr++) {

		args[thr].to_decrypt = v;
		args[thr].sk = this->s;

		args[thr].default_len = defLen;
		args[thr].d = d;
		args[thr].n = n;

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

	for (int thr = 0; thr < worker_cnt; thr++) {

		std:unique_lock <std::mutex> lock(args[thr].done_mutex);

		args[thr].done.wait(lock, [thr, args] {
			return args[thr].task_is_done;
		});

		dec ^= *(args[thr].decrypted);
	}

	delete[] args;

	return dec;
}

#pragma endregion

#pragma region Public methods

Ciphertext SecretKey::encrypt(Plaintext &plaintext)
{
    uint64_t len;

	uint64_t n = this->certFHEContext->getN();
	uint64_t d = this->certFHEContext->getD();

	uint64_t div = n / (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    len = div;
	if ( rem != 0)
		len++;	

    unsigned char value = BIT(plaintext.getValue());
    uint64_t * vect =  encrypt(value,n,d,s);
	uint64_t * _bitlen = new uint64_t [len];
    uint64_t * _encValues = new uint64_t [len];

	for (int i = 0;i<div;i++)
		_bitlen[i] = sizeof(uint64_t)*8;
	_bitlen[div] = rem;

	int uint64index = 0;
	for (int step =0;step<div;step++)
	{
		    _encValues[uint64index]= 0x00;
			for (int s = 0;s< 64;s++)
			{
				uint64_t inter = ((vect[step*64+s]  ) & 0x01)<<sizeof(uint64_t)*8 - 1 -s;
				_encValues[uint64index] = (_encValues[uint64index] ) | ( inter );
			}
			uint64index++;
	}
	
	if (rem != 0)
	{		
			_encValues[uint64index]= 0x00;
			for (int r = 0 ;r<rem;r++)
			{
				uint64_t inter = ((vect[ div*64 +r ]  ) & 0x01)<<sizeof(uint64_t)*8 - 1-r;
				_encValues[uint64index] = (_encValues[uint64index] ) | ( inter );

			}

	}
	
    Ciphertext c(_encValues,_bitlen,len,*this->certFHEContext);
    delete [] vect;
    delete [] _bitlen;    
    delete [] _encValues;

    return c;

}

Plaintext SecretKey::decrypt(Ciphertext& ciphertext)
{   
    uint64_t n = this->certFHEContext->getN();
	uint64_t d = this->certFHEContext->getD();

	uint64_t div = n/ (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    uint64_t defLen = div;
	if ( rem != 0)
		defLen++;	

    uint64_t* _v = ciphertext.getValues();
    uint64_t* _bitlen = ciphertext.getBitlen();

    uint64_t decV =  decrypt(_v,ciphertext.getLen(),defLen,n,d,s,_bitlen);
    return Plaintext(decV);
}

void SecretKey::applyPermutation_inplace(const Permutation& permutation)
{
	uint64_t permLen = permutation.getLength();
	uint64_t *perm = permutation.getPermutation();

	uint64_t *current_key = new uint64_t[this->certFHEContext->getN()];
	
	for(uint64_t i = 0;i<this->certFHEContext->getN();i++)
		current_key[i] = 0;

	for(uint64_t i = 0;i<length;i++)
		current_key[s[i]] =1;

	uint64_t *temp = new uint64_t[this->certFHEContext->getN()];

	for (int i = 0; i < this->certFHEContext->getN(); i++)
		temp[i] = current_key[perm[i]];

	uint64_t *newKey = new uint64_t[length];
	uint64_t index = 0; 
	for(uint64_t i =0;i<this->certFHEContext->getN();i++)
	{
		if (temp[i] == 1)
			newKey[index++] = i;
	}

	delete [] this->s;
	this->s = newKey;


	delete [] current_key;
	delete [] temp;

}

SecretKey SecretKey::applyPermutation(const Permutation& permutation)
{

	SecretKey secKey(*this);
	secKey.applyPermutation_inplace(permutation);
	return secKey;
}

long SecretKey::size()
{
	long size = 0;
	size += sizeof(this->certFHEContext);
	size += sizeof(this->length);
	size += sizeof(uint64_t)*this->length;
	return size;
}

#pragma endregion

#pragma region Getters and setters

uint64_t  SecretKey::getLength() const
{
	return this->length;
}

uint64_t* SecretKey::getKey() const
{
	return this->s;
}

void SecretKey::setKey(uint64_t*s, uint64_t len)
{
	if (this->s != nullptr)
		delete [] this->s;
	
	this->s = new uint64_t[len];
	for(uint64_t i=0;i<len;i++)
		this->s[i] = s[i];

	this->length = len;
}

#pragma endregion

#pragma region Constructors and destructor

SecretKey::SecretKey(const Context &context)
{
    // seed once again the PRNG with local time
    time_t t = time(NULL);
	srand(t);

    this->certFHEContext = new certFHE::Context(context);

    uint64_t _d = certFHEContext->getD();
    uint64_t _n = certFHEContext->getN();

    this->s =  new uint64_t[_d];
    this->length = _d;

	int count = 0;
	bool go = true;
	while (go)
	{

		uint64_t temp = rand() % _n;
		if (Helper::exists(s,_d, temp))
			continue;

		s[count] = temp;
		count++;
		if (count == _d)
			go = false;
	}
    
}

SecretKey::SecretKey(const SecretKey& secKey) 
{
    this->certFHEContext = new certFHE::Context(*secKey.certFHEContext);

     if ( secKey.length < 0)
        return;
    
    this->s = new uint64_t [ secKey.length];
    this->length =  secKey.length;
    for(long i = 0;i< secKey.length;i++)
        this->s[i ] =secKey.s[i];

    
}

SecretKey::~SecretKey()
{
	for (uint64_t i = 0; i < length; i++)
		s[i] = 0;

    if (this->s != nullptr)
    {
        delete [] this->s;
        this->s = nullptr;
    }
    
    this->length =-1;

    if (this->certFHEContext != nullptr)
    {
        delete this->certFHEContext;
        this->certFHEContext = nullptr;
    }
}

#pragma endregion
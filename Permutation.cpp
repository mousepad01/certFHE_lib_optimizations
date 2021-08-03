#include "Permutation.h"
#include "GlobalParams.h"

namespace certFHE{

#pragma region Public methods

	Permutation Permutation::getInverse() {

		uint64_t * p = new uint64_t[length];

		for (uint64_t i = 0; i < length; i++) {
			for (uint64_t j = 0; j < length; j++) {
				
				if (permutation[j] == i) {

					p[i] = j; 
					break;
				}
			}
		}
    
		Permutation invP(p, length);
		delete[] p;
		return invP;
	}

#pragma endregion

#pragma region Operators

	std::ostream & operator << (std::ostream & out, const Permutation & p)
	{
		uint64_t* _p = p.getPermutation();
		uint64_t l = p.getLength();
		out <<"(";
		for(uint64_t i = 0; i<l;i++)
			out<<i<<" ";
		out<<")"<<'\n';
		out <<"(";
		for(uint64_t i = 0; i<l;i++)
			out<<_p[i]<<" ";
		out<<")"<<'\n';
		return out;
	}

	Permutation& Permutation::operator=(const Permutation& perm)
	{
		this->length = perm.getLength();


		if (this->permutation != nullptr)
			delete [] this->permutation;

		this->permutation = new uint64_t [this->length];
		for(uint64_t i=0;i<this->length;i++)
			this->permutation[i] = perm.permutation[i];

		return *this;
	}

	Permutation Permutation::operator+(const Permutation& permB) const
	{
		if ( length != permB.getLength())
			return Permutation();         

		uint64_t *p = new uint64_t[length];
		uint64_t *pB = permB.getPermutation();
		for (uint64_t i = 0; i < length; i++)
		{
			p[i] = this->permutation[pB[i]];
		}

		Permutation result(p,length);
		delete [] p;
		return result;
	}

	Permutation& Permutation::operator+=(const Permutation& permB)
	{
		if (length != permB.getLength())
			return *this;         

		uint64_t *p = new uint64_t[length];
		uint64_t *pB = permB.getPermutation();
		for (uint64_t i = 0; i < length; i++)
		{
			p[i] = this->permutation[pB[i]];
		}

		delete [] this->permutation;
		this->permutation = p;

	return *this;
	}

#pragma endregion

#pragma region Getters and setters

	uint64_t Permutation::getLength() const
	{
		return this->length;
	}

	uint64_t Permutation::getInversionsCnt() const {

		return this->inversions_cnt;
	}

	uint64_t * Permutation::getPermutation() const
	{
		return this->permutation;
	}

	CtxtInversion * Permutation::getInversions() const {

		return this->inversions;
	}

	void Permutation::setLength(uint64_t len)
	{
		this->length = len;
	}

	void Permutation::setInversionsCnt(uint64_t inv_cnt) {

		this->inversions_cnt = inv_cnt;
	}

	void Permutation::setPermutation(uint64_t * perm, uint64_t len)
	{
		if (this->permutation != nullptr)
			delete [] this->permutation;
		
		this->permutation = new uint64_t [len];
		this->length = len;
		for(uint64_t i = 0; i<len;i++)
			this->permutation[i] = perm[i];

		this->inversions = nullptr;
	}

	void Permutation::setPermutation(uint64_t * perm, uint64_t len, uint64_t inv_cnt, CtxtInversion * invs) {

		if (this->permutation != nullptr)
			delete[] this->permutation;

		if (this->inversions != nullptr)
			delete[] this->inversions;

		this->permutation = new uint64_t[len];
		this->inversions = new CtxtInversion[inv_cnt];

		this->length = len;
		this->inversions_cnt = inv_cnt;

		for (uint64_t i = 0; i < len; i++)
			this->permutation[i] = perm[i];

		for (uint64_t i = 0; i < len; i++)
			this->inversions[i] = invs[i];
	}

#pragma endregion

#pragma region Constructors and destructor

	Permutation::Permutation()
	{
		this->length = 0;
		this->inversions_cnt = 0;

		this->permutation = nullptr;
		this->inversions = nullptr;
	}

	Permutation::Permutation(const uint64_t len) {

		this->permutation = new uint64_t[len];
		this->inversions = new CtxtInversion[len]; // allocating for maximum number of inversions

		this->length = len;
		this->inversions_cnt = 0;

		for (uint64_t i = 0; i < len; i++)
			permutation[i] = i;

	#if MSVC_COMPILER_LOCAL_MACRO // std::random_devide guaranteed by MSVC to be criptographically secure

		std::random_device csprng;

		for (uint64_t pos = 0; pos < length - 2; pos++) {

			uint64_t newpos = (uint64_t)(pos + csprng() % (length - pos));
			std::swap(permutation[pos], permutation[newpos]);

			if (newpos != pos) {
				
				inversions[inversions_cnt].fst_u64_ch = pos / 64;
				inversions[inversions_cnt].fst_u64_r = 63 - (pos % 64);

				inversions[inversions_cnt].snd_u64_ch = newpos / 64;
				inversions[inversions_cnt].snd_u64_r = 63 - (newpos % 64);

				inversions_cnt += 1;
			}
		}
			
	#else // for now, the default (insecure) rand

		for (uint64_t pos = 0; pos < length - 2; pos++) {

			uint64_t newpos = (uint64_t)(pos + rand() % (length - pos));
			std::swap(permutation[pos], permutation[newpos]);

			if (newpos != pos) {

				inversions[inversions_cnt].fst_u64_ch = pos / 64;
				inversions[inversions_cnt].fst_u64_r = 63 - (pos % 64);

				inversions[inversions_cnt].snd_u64_ch = newpos / 64;
				inversions[inversions_cnt].snd_u64_r = 63 - (newpos % 64);

				inversions_cnt += 1;
			}
		}

	#endif
	}

	Permutation::Permutation(const Context & context) : Permutation(context.getN())
	{

	}    

	Permutation::Permutation(const uint64_t *perm, const uint64_t len) : Permutation()
	{
		this->permutation = new uint64_t[len];

		this->length = len;

		for (uint64_t i = 0; i < len; i++)
			this->permutation[i] = perm[i];
	}

	Permutation::Permutation(const uint64_t *perm, const uint64_t len, uint64_t inv_cnt, CtxtInversion * invs) {

		this->permutation = new uint64_t[len];
		this->inversions = new CtxtInversion[inv_cnt];

		this->length = len;
		this->inversions_cnt = inv_cnt;

		for (uint64_t i = 0; i < len; i++)
			this->permutation[i] = perm[i];

		for (uint64_t i = 0; i < inv_cnt; i++)
			this->inversions[i] = invs[i];
	}

	Permutation::Permutation(const Permutation & perm)
	{
		this->length = perm.getLength();
		this->inversions_cnt = perm.getInversionsCnt();

		this->permutation = new uint64_t[this->length];
		this->inversions = new CtxtInversion[this->inversions_cnt];

		uint64_t * _perm = perm.getPermutation();
		CtxtInversion * _invs = perm.getInversions();

		for(uint64_t i = 0; i < this->length; i++)
			this->permutation[i] = _perm[i];
		
		for (uint64_t i = 0; i < this->inversions_cnt; i++)
			this->inversions[i] = _invs[i];
	}

	Permutation::~Permutation(){

		if (this->permutation != nullptr) {

			delete[] this->permutation;
			this->permutation = nullptr;
		}

		if (this->inversions != nullptr) {

			delete[] this->inversions;
			this->inversions = nullptr;
		}

		this->length = 0;
		this->inversions_cnt = 0;
	}

 #pragma endregion
 
}
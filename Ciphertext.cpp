#include "Ciphertext.h"
#include "GlobalParams.h"
#include "Threadpool.hpp"
#include "SecretKey.h"
#include "Permutation.h"
#include "Plaintext.h"
#include "Context.h"
#include "CMUL.h"
#include "CADD.h"

//using namespace certFHE;

namespace certFHE{

#pragma region Public methods

	Plaintext Ciphertext::decrypt(const SecretKey & sk) const {

		uint64_t dec = this->node->decrypt(sk);
		return Plaintext(dec);
	}

	Ciphertext Ciphertext::applyPermutation(const Permutation& permutation) {

		std::cout << "permutation not yet implemented\n";
		return *this;
		/*Ciphertext newCiphertext(*this);
		newCiphertext.applyPermutation_inplace(permutation);
		return newCiphertext;*/
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		this->node->permute_inplace(permutation);
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

#pragma endregion

#pragma region Operators

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		out << "ciphertext ostream overload not yet implemented\n";
		return out;
	}

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		CADD * addition_result = (CADD *)Ciphertext::add(this->node, c.node);
		Ciphertext * add_result_c = new Ciphertext();

		add_result_c->node = addition_result;
		return *add_result_c;
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {
		
		CMUL * mul_result = (CMUL *)Ciphertext::multiply(this->node, c.node);
		Ciphertext * mul_result_c = new Ciphertext();

		mul_result_c->node = mul_result;
		return *mul_result_c;
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {
		
		CADD * addition_result = (CADD *)Ciphertext::add(this->node, c.node);
		
		this->node->try_delete();
		this->node = addition_result;

		return *this;
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {
		
		CMUL * mul_result = (CMUL *)Ciphertext::multiply(this->node, c.node);

		this->node->try_delete();
		this->node = mul_result;

		return *this;
	}

	Ciphertext & Ciphertext::operator = (const Ciphertext & c) {
		
		if (this->node != 0)
			this->node->try_delete();

		c.node->downstream_reference_count += 1;
		this->node = c.node;
		
		return *this;
	}

	Ciphertext & Ciphertext::operator = (Ciphertext && c) {

		if (this->node != 0)
			this->node->try_delete();

		this->node = c.node;

		return *this;
	}

#pragma endregion

#pragma region Constructors and destructor

	Ciphertext::Ciphertext() {

		this->node = 0;
	}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);
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


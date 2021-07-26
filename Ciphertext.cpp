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

	Ciphertext Ciphertext::applyPermutation(const Permutation & permutation, bool force_deep_copy) {

		CNODE * permuted = this->node->permute(permutation, force_deep_copy);

		Ciphertext * permuted_ciphertext = new Ciphertext(*this);

		permuted_ciphertext->node->try_delete();
		permuted_ciphertext->node = permuted;

		return *permuted_ciphertext;
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		CNODE * permuted = this->node->permute(permutation, false);
		
		this->node->try_delete();
		this->node = permuted;
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

		addition_result->deflen_count = fst->deflen_count + snd->deflen_count;

		addition_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = addition_result->upstream_shortening();
		if (shortened != 0) {

			addition_result->try_delete();
			return shortened;
		}

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

		mul_result->deflen_count = fst->deflen_count * snd->deflen_count;

		mul_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = mul_result->upstream_shortening();
		if (shortened != 0) {

			mul_result->try_delete();
			return shortened;
		}

		return mul_result;
	}

#pragma endregion

#pragma region Operators

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		CCC * ccc_node = dynamic_cast <CCC *> (c.node);
		if (ccc_node != 0) 
			out << *ccc_node << '\n';
		
		else {

			COP * cop_node = dynamic_cast <COP *> (c.node);
			if (cop_node != 0)
				out << *cop_node << '\n';
		}

		return out;
	}

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		CADD * addition_result = (CADD *)Ciphertext::add(this->node, c.node);

		Ciphertext add_result_c;
		add_result_c.node = addition_result;

		return add_result_c;
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {
		
		CMUL * mul_result = (CMUL *)Ciphertext::multiply(this->node, c.node);

		Ciphertext mul_result_c;
		mul_result_c.node = mul_result;

		return mul_result_c;
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {
		
		CNODE * addition_result = Ciphertext::add(this->node, c.node);
		
		this->node->try_delete();
		this->node = addition_result;

		return *this;
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {
		
		CNODE * mul_result = Ciphertext::multiply(this->node, c.node);

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
		c.node = 0;

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
		ctxt.node = 0;
	}

	Ciphertext::~Ciphertext() {

		if(this->node != 0)
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


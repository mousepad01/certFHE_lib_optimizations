#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "utils.h"

namespace certFHE{

	class CNODE;
	class Permutation;
	class SecretKey;
	class Context;
	class Plaintext;

    /**
     * Class used for storing a ciphertext
    **/
	class Ciphertext{

	public:
    
		/**
		 * CNODE associated with the ciphertext
		 * It can be of any type (CCC, CMUL, CADD) or null
		**/
		CNODE * node;

		/**
			* Method for adding two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
			*
			* NOTE: this function treats the nodes as being different
			*		so the caller should manually increase the reference count (and then decrease it?)
			*		when calling this function with the same pointer in both arguments
		**/
		static CNODE * add(CNODE * fst, CNODE * snd);

		/**
			* Method for multiplying two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
			*
			* NOTE: this function treats the nodes as being different
			*		so the caller should manually increase the reference count (and then decrease it?)
			*		when calling this function with the same pointer in both arguments
		**/
		static CNODE * multiply(CNODE * fst, CNODE * snd);

	public:

		/**
			* Default constructor
		**/
		Ciphertext();

		/**
			* Custom constructor
			* @param[in] plaintext: plaintext to be encrypted 
			* @param[in] sk: secret key under which the encryption takes place
		**/
		Ciphertext(const Plaintext & plaintext, const SecretKey & sk);

		/**
			* Custom constructor
			* @param[in] plaintext: plaintext to be encrypted (first bit starting from any memory address)
			* @param[in] sk: secret key under which the encryption takes place
		**/
		Ciphertext(const void * plaintext, const SecretKey & sk);

		/**
			* Copy constructor
		**/
		Ciphertext(const Ciphertext & ctxt);

		/**
			* Move constructor
		**/
		Ciphertext(Ciphertext && ctxt);

		/**
			* Destructor
		**/
		virtual ~Ciphertext();

		/**
			* Getters and setters
		**/
		uint64_t getLen() const;
		Context getContext() const;
        
		/**
			* Friend class for operator<<
		**/
		friend std::ostream & operator << (std::ostream & out, const Ciphertext & c);
        
		/**
			* Operators for addition of ciphertexts
		**/
		Ciphertext operator + (const Ciphertext & c) const;
		Ciphertext & operator += (const Ciphertext & c);

		/**
			* Operators for multiplication of ciphertexts
		**/
		Ciphertext operator * (const Ciphertext & c) const;
		Ciphertext & operator *= (const Ciphertext & c);

		/**
			* Operator for copy assignment
		**/ 
		Ciphertext & operator = (const Ciphertext & c);

		/**
			* Operator for move assignment
		**/
		Ciphertext & operator = (Ciphertext && c);

		/**
			* Apply a permutation on the current ciphertxt 
			* @param[in] permutation : permutation object to be applied
		**/
		void applyPermutation_inplace(const Permutation & permutation);

		/**
			* Permute the current ciphertext and return a new object
			* @param[in] permutation: constant reference to permutation object
			* @return value : permuted ciphertext
		**/
		Ciphertext applyPermutation(const Permutation & permutation);

		/**
			* Creates a deep copy for the current ciphertext
			* This might be useful in a multithreading situation,
			* When one wants to parralelise operations on different ctxt
			* That originally shared at least a common CNODE node 
			* (usually when one of them was obtained by applying an operation on the other)
			* @return value : new ciphertext
		**/
		Ciphertext make_deep_copy();

		/**
			* Method for decrypting current ciphertext
			* @param[in] sk: key under which decryption takes place
			* @return value: decrypted value as a plaintext object
		**/
		Plaintext decrypt(const SecretKey & sk) const;

	};
}

#endif
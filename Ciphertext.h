#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "utils.h"
#include "Context.h"
#include "Permutation.h"

namespace certFHE{

	class CNODE;

    /**
     * Class used for storing a ciphertext
    **/
	class Ciphertext{

	public:
    
		CNODE * node;

		/**
			* Method for adding two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
		**/
		static CNODE * add(CNODE * fst, CNODE * snd);

		/**
			* Method for multiplying two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
		**/
		static CNODE * multiply(CNODE * fst, CNODE * snd);

		/**
			* Default private constructor
		**/
		Ciphertext();

	public:

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
		friend std::ostream & operator << (std::ostream &out, const Ciphertext &c);
        
		/**
			* Operators for addition of ciphertexts
		**/
		Ciphertext operator + (const Ciphertext & c) const;
		Ciphertext & operator+=(const Ciphertext& c);

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
		void applyPermutation_inplace(const Permutation &permutation);

		/**
			* Permute the current ciphertext and return a new object
			* @param[in] permutation: constant reference to permutation object
			* @return value : permuted ciphertext
		**/
		Ciphertext applyPermutation(const Permutation &permutation);

		/**
			* Method for decrypting current ciphertext
			* @param[in] sk: key under which decryption takes place
			* @return value: decrypted value as a plaintext object
		**/
		Plaintext decrypt(const SecretKey & sk) const;

	};
}

#endif
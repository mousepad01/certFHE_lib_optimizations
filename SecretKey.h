#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include "utils.h"
#include "Context.h"
#include "Plaintext.h"
#include "Ciphertext.h"
#include "Helpers.h"
#include "Permutation.h"

namespace certFHE
{
    /**
     * Class used for storing the secret key and to perform operations such as encrypt/decrypt
    **/
    class SecretKey{

    private:

        uint64_t * s;                    // secret positions from the vector [0,n-1]. 
		uint64_t * s_mask;				 // secret key as a bitmask

        uint64_t length;                 // length of the s vector, containing the secret posionts
		uint64_t mask_length;		     // length of secret key as bitmask IN UINT64 CHUNKS

        Context *certFHEContext;

		/**
		 * Useful for decryption optimization
		 * Sets key mask according to the already existing s
		 * @return value : nothing
		**/
		void set_mask_key();

    public:

        /**
         * Deleted default constructor
        **/
        SecretKey() = delete;

        /**
         * Custom constructor. Generates a secret key based on the context.
         * @param[in] context: a const. reference to an context
        **/
        SecretKey(const Context & context);

        /**
         * Copy constructor
         * @param[in] secKey: SecretKey object 
        **/
        SecretKey(const SecretKey & secKey);

        /**
         * Encrypts a plaintext
         * @param[in] plaintext: input to be encrypted ({0,1})
         * @return value: raw ciphertext chunk
        **/
        uint64_t * encrypt(const Plaintext & plaintext) const;

		/**
		 * Encrypts the first bit from a memory address
		 * @param[in] addr: the memory address
		 * @return value: raw ciphertext chunk
		**/
		uint64_t * encrypt(const void * addr) const;

        /**
         * Decrypts a ciphertext
         * @param[in] ciphertext: ciphertext to be decrypted 
         * @return value: decrypted plaintext
        **/
        Plaintext decrypt(Ciphertext & ciphertext);

		/**
		 * Decrypts a raw ciphertext
		 * @param[in] raw_ctxt: ciphertext to be decrypted
		 * @return value: decrypted plaintext
		**/
		Plaintext decrypt(uint64_t * raw_ctxt, uint64_t u64_len);

        /**
         * Apply the permutation on current secret key
         * @param[in] permutation: Permutation object
        **/
        void applyPermutation_inplace(const Permutation & permutation);

        /**
         * Apply a permutation on the current secret key and return a new object
         * @param[in] permutation: permutation object to be applied
         * @return value: a permuted secret key object
        **/
        SecretKey applyPermutation(const Permutation & permutation);

		/**
		 * Decrypt in chunks -- only for multithreading --
		**/
		friend void chunk_decrypt(Args * raw_args);

        /**
         * Friend class for operator<<
        **/
        friend std::ostream & operator << (std::ostream &out, const SecretKey &c);

        /**
         * Assignment operator
         * @param[in] secKey: a constant copy of an secret key object
        **/
        SecretKey & operator = (const SecretKey& secKey);

        /**
         * Destructor
        **/
        virtual ~SecretKey();

        /**
         * Getters
        **/
        uint64_t getLength() const;

		/**
		* DO NOT DELETE THIS POINTER
	   **/
		Context * getContext() const;

        /**
         * DO NOT DELETE THIS POINTER
        **/
        uint64_t* getKey() const;

		/**
		 * DO NOT DELETE THIS POINTER
		**/
		uint64_t* getMaskKey() const;

		
		/**
		 * Setters
		**/
		void setKey(uint64_t*s, uint64_t len);
		
        /**
         * Get the size in bytes of the secret key
         * @return value: size in bytes
        **/
        uint64_t size();

    };


}





#endif
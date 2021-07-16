#ifndef PERMUTATION_H
#define PERMUTATION_H

#include "utils.h"
#include "Helpers.h"
#include "Context.h"

namespace certFHE{

    /**
     * Class used to store permutations further applied on secret keys or ciphertexts
    **/
    class Permutation{

    private:

        uint64_t * permutation;			// vector used to store permutation
		CtxtInversion * inversions;		// permutation as inversions on a default len chunk -- for optimized permutation op --
        
		uint64_t length;				// size of permutation vector
		uint64_t inversions_cnt;		// number of inversions

    public:

        /**
         * Default constructor
        **/
        Permutation();

        /**
         * Custom constructor with 0 initialization
        **/
        Permutation(const uint64_t *perm, const uint64_t len);

		Permutation(const uint64_t *perm, const uint64_t len, uint64_t inv_cnt, CtxtInversion * invs);

        /**
         * Custom constructor - generates a random permutation using the N from context
        **/
        Permutation(const Context& context);

        /**
         * Custom constructor - generates a random permutation of size len
        **/
        Permutation(const uint64_t len);

        /**
         * Copy constructor
        **/
        Permutation(const Permutation& perm);

        /**
         * Destructor
        **/
       virtual ~Permutation();

       /**
        * Getters and setters
       **/
       uint64_t getLength() const;
	   uint64_t getInversionsCnt() const;

       void setLength(uint64_t len);
	   void setInversionsCnt(uint64_t inv_cnt);
       void setPermutation(uint64_t * perm,uint64_t len);
	   void setPermutation(uint64_t * perm, uint64_t len, uint64_t inv_cnt, CtxtInversion * invs);

       /**
        * DO NOT DELETE THE RETUNING POINTER
        **/
        uint64_t* getPermutation() const; 

		/**
		* DO NOT DELETE THE RETUNING POINTER
		**/
		CtxtInversion * getInversions() const;

        /**
         * Friend class for operator<<
        **/
        friend std::ostream& operator<<(std::ostream &out, const Permutation &c);

        /**
         * Asignment operator
        **/
        Permutation& operator=(const Permutation& perm);

        /**
         * Method to return the inverse of current permutation
         * @return value: inverse of current permutation
        **/
        Permutation getInverse();


        /**
         * Combine two permutations
         * @param[in] permB: the second permutation to combine
         * @return value : a permutatuion with value equal to this o permB
        **/
       Permutation operator+(const Permutation& permB) const;
       Permutation& operator+=(const Permutation& permB);
    };



}


#endif
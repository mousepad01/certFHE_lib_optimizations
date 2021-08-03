#ifndef CADD_HEADER
#define CADD_HEADER

#include "COP.h"

namespace certFHE {

	class CMUL;

	class CADD : public COP {

	protected:

		// Constructors & destructor

		CADD() = delete;
		CADD(Context * context): COP(context) {}

		CADD(const CADD & other): COP(other) {}
		CADD(const CADD && other): COP(other) {}

		virtual ~CADD() {}

		// Operators

		CADD & operator = (const CADD & other) = delete;
		CADD & operator = (const CADD && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CADD & cadd);

		// Getters, setters and methods

		/**
		 * This function tries to merge as many operations as possible
		 * NOTE: the changes are done inplace,
		 * and if there is another reference to this node, changes will also reflect there
		 * it should not be a problem, because the result after merged operations remains the same
		**/
		void upstream_merging() override;

		uint64_t decrypt(const SecretKey & sk) override;

		CNODE * permute(const Permutation & perm, bool force_deep_copy) override;

		CNODE * make_copy() override;

		//int getclass() { return 1; }

		static CNODE * upstream_merging(CNODE * fst, CNODE * snd);

		static CNODE * __upstream_merging(CADD * fst, CADD * snd);
		static CNODE * __upstream_merging(CADD * fst, CMUL * snd);
		static CNODE * __upstream_merging(CMUL * fst, CMUL * snd);

		static CNODE * __upstream_merging(CADD * fst, CCC * snd);
		static CNODE * __upstream_merging(CCC * fst, CCC * snd);
		static CNODE * __upstream_merging(CMUL * fst, CCC * snd);

		// Others

		friend class CMUL;
		friend class Ciphertext;
	};
}

#endif
#ifndef CADD_HEADER
#define CADD_HEADER

#include "COP.h"

namespace certFHE {

	class CADD : public COP {

	protected:

		CADD() = delete;
		CADD(Context * context): COP(context) {}

		CADD(const CADD & other): COP(other) {}
		CADD(const CADD && other): COP(other) {}

		CADD & operator = (const CADD & other) = delete;
		CADD & operator = (const CADD && other) = delete;

		virtual ~CADD() {}

		/**
		 * This function tries to merge as many operations as possible
		 * NOTE: the changes are done inplace,
		 * and if there is another reference to this node, changes will also reflect there
		 * it should not be a problem, because the result after merged operations remains the same
		**/
		void upstream_merging();

		CNODE * make_copy();

		static CNODE * upstream_merging(CNODE * fst, CNODE * snd);

		static CNODE * __upstream_merging(CADD * fst, CADD * snd);
		static CNODE * __upstream_merging(CADD * fst, CMUL * snd);
		static CNODE * __upstream_merging(CMUL * fst, CMUL * snd);

		static CNODE * __upstream_merging(CADD * fst, CCC * snd);
		static CNODE * __upstream_merging(CCC * fst, CCC * snd);
		static CNODE * __upstream_merging(CMUL * fst, CCC * snd);

		friend class CMUL;
		friend class Ciphertext;
	};
}

#endif
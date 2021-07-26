#ifndef CMUL_HEADER
#define CMUL_HEADER

#include "COP.h"

namespace certFHE {

	class CADD;

	class CMUL : public COP {

	protected:

		// Constructors - destructors

		CMUL() = delete;
		CMUL(Context * context): COP(context) {}

		CMUL(const CMUL & other): COP(other) {}
		CMUL(const CMUL && other): COP(other) {}

		virtual ~CMUL() {}

		// Operators

		CMUL & operator = (const CMUL & other) = delete;
		CMUL & operator = (const CMUL && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CMUL & cmul);

		// Getters, setters and methods

		void upstream_merging();

		uint64_t decrypt(const SecretKey & sk);

		CNODE * make_copy();

		static CNODE * upstream_merging(CNODE * fst, CNODE * snd);

		static CNODE * __upstream_merging(CADD * fst, CADD * snd);
		static CNODE * __upstream_merging(CADD * fst, CMUL * snd);
		static CNODE * __upstream_merging(CMUL * fst, CMUL * snd);

		static CNODE * __upstream_merging(CADD * fst, CCC * snd);
		static CNODE * __upstream_merging(CCC * fst, CCC * snd);
		static CNODE * __upstream_merging(CMUL * fst, CCC * snd);

		// Other

		friend class CADD;
		friend class Ciphertext;
	};

}

#endif
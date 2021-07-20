#ifndef CMUL_HEADER
#define CMUL_HEADER

#include "COP.h"

namespace certFHE {

	class CMUL : public COP {

	protected:

		CMUL() = delete;
		CMUL(Context * context): COP(context) {}

		CMUL(const CMUL & other): COP(other) {}
		CMUL(const CMUL && other): COP(other) {}

		CMUL & operator = (const CMUL & other) = delete;
		CMUL & operator = (const CMUL && other) = delete;

		virtual ~CMUL() {}

		void upstream_merging();

		CNODE * make_copy();

		static CNODE * upstream_merging(CNODE * fst, CNODE * snd);

		static CNODE * __upstream_merging(CADD * fst, CADD * snd);
		static CNODE * __upstream_merging(CADD * fst, CMUL * snd);
		static CNODE * __upstream_merging(CMUL * fst, CMUL * snd);

		static CNODE * __upstream_merging(CADD * fst, CCC * snd);
		static CNODE * __upstream_merging(CCC * fst, CCC * snd);
		static CNODE * __upstream_merging(CMUL * fst, CCC * snd);
	};

}

#endif
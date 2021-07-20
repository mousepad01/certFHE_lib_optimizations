#ifndef CCC_HEADER
#define CCC_HEADER

#include "CNODE.h"

namespace certFHE {

	class CCC : public CNODE {

	protected:

		uint64_t * ctxt;

		virtual ~CCC() {}

	public:

		CCC() = delete;
		CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt);

		CCC(const CCC & other);
		CCC(const CCC && other);

		CCC & operator = (const CCC & other) = delete;
		CCC & operator = (const CCC && other) = delete;

		void upstream_merging() {}

		CNODE * make_copy();

		static void chunk_add(Args * raw_args);

		/**
		 * It will add WITHOUT ANY CHECK
		 * Proper checks are expected to be managed by the caller function
		**/
		static CCC * add(CCC * fst, CCC * snd);
	};

}

#endif
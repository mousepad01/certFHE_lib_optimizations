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
	};

}

#endif
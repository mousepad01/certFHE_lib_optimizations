#ifndef CNODE_HEADER
#define CNODE_HEADER

#include "Context.h"
#include "GlobalParams.h"

namespace certFHE {

	class CNODE {

	protected:

		Context * context;
		uint64_t deflen_count;
		uint64_t downstream_reference_count;

		CNODE() = delete;
		CNODE(Context * context) : downstream_reference_count(1), context(context) {}

		CNODE(Context * context, uint64_t deflen_count): downstream_reference_count(1),
															deflen_count(deflen_count),
															context(context) {}

		CNODE(const CNODE & other);
		CNODE(const CNODE && other);

		virtual ~CNODE() {}

		CNODE & operator = (const CNODE & other) = delete;
		CNODE & operator = (const CNODE && other) = delete;

		virtual void upstream_merging() = 0;
		void try_delete();

		friend class CNODE_list;
		friend class CCC;
		friend class COP;
		friend class CADD;
		friend class CMUL;
	};
}

#endif
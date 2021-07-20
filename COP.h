#ifndef COP_HEADER
#define COP_HEADER

#include "CNODE.h"
#include "CNODE_list.h"
#include "CCC.h"

namespace certFHE {

	class CADD;
	class CMUL;

	class COP : public CNODE {

	protected:

		CNODE_list * nodes;

		COP() = delete;
		COP(Context * context) : CNODE(context), nodes(0) {}

		virtual ~COP();

		COP(const COP & other);
		COP(const COP && other);

		COP & operator = (const COP & other) = delete;
		COP & operator = (const COP && other) = delete;

		void upstream_merging() = 0;
		CNODE * make_copy() = 0;
	};
}

#endif
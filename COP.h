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

		/**
		 * ALWAYS first element is a dummy, to avoid changing first element address
		**/
		CNODE_list * nodes;

		// Constructors - destructors

		COP() = delete;
		COP(Context * context);

		virtual ~COP();

		COP(const COP & other);
		COP(const COP && other);

		// Operators

		COP & operator = (const COP & other) = delete;
		COP & operator = (const COP && other) = delete;

		// Getters, setters and methods

		void upstream_merging() = 0;

		CNODE * make_copy() = 0;

		virtual uint64_t decrypt(const SecretKey & sk) = 0;

		// Other

		friend class CMUL;
		friend class CADD;
		friend class Ciphertext;
	};
}

#endif
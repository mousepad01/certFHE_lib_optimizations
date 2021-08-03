#ifndef COP_HEADER
#define COP_HEADER

#include "CNODE.h"
#include "CNODE_list.h"
#include "CCC.h"

namespace certFHE {

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

		friend std::ostream & operator << (std::ostream & out, const COP & cop);

		// Getters, setters and methods

		void upstream_merging() override = 0;

		CNODE * upstream_shortening() override;

		CNODE * make_copy() override = 0;

		CNODE * make_deep_copy() override  = 0;

		uint64_t decrypt(const SecretKey & sk) override = 0;

		CNODE * permute(const Permutation & perm, bool force_deep_copy) override = 0;

		//int getclass() = 0;

		// Other

		friend class CMUL;
		friend class CADD;
		friend class Ciphertext;
	};
}

#endif
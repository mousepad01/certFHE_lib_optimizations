#ifndef CNODE_HEADER
#define CNODE_HEADER

#include "Context.h"
#include "GlobalParams.h"
#include "ArgClasses.h"

namespace certFHE {

	class CNODE {

	public:

		Context * context;
		uint64_t deflen_count;
		uint64_t downstream_reference_count;

		// Constructors - destructors

		CNODE() = delete;
		CNODE(Context * context): downstream_reference_count(1), context(context), deflen_count(0) {}

		CNODE(const CNODE & other);
		CNODE(const CNODE && other);

		virtual ~CNODE() {}

		// Operators

		CNODE & operator = (const CNODE & other) = delete;
		CNODE & operator = (const CNODE && other) = delete;

		// Getters, setters and methods

		Context getContext();
		uint64_t getDeflenCnt();

		virtual void upstream_merging() = 0;

		virtual CNODE * make_copy() = 0; // virtual copy constructor

		virtual uint64_t decrypt((const SecretKey & sk) = 0;

		void try_delete();

		// Other

		friend class CNODE_list;
		friend class CCC;
		friend class COP;
		friend class CADD;
		friend class CMUL;
	};
}

#endif
#ifndef CNODE_HEADER
#define CNODE_HEADER

#include "Context.h"
#include "GlobalParams.h"
#include "ArgClasses.h"
#include "SecretKey.h"
#include "Permutation.h"

namespace certFHE {

	class CNODE {

	public:

		/**
		 * certFHE context
		 * ASSUMED to be te SAME 
		 * on EVERY NODE that interacts with this node
		 * (currently, checks done only in Ciphertext class)
		**/
		Context * context;

		/**
		 * Number of default length chunks 
		 * For CCC - actual number
		 * For COP - number if all the operations were done (actual used memory is lower)
		**/
		uint64_t deflen_count;

		/**
		 * Number of nodes that have direct reference to this node
		 * As being part of an addition or multiplication, or by itself
		 * PLUS the number of Ciphertext objects that have this node pointed by their node attribute
		 * Used to decide when to delete this node from memory
		**/
		uint64_t downstream_reference_count;

		// Constructors - destructors

		CNODE() = delete;
		CNODE(Context * context): downstream_reference_count(1), context(context), deflen_count(0) {}

		/**
		 * Creates (intentional) shallow copy
		 * GOOD to use, at least in a single threaded environment
		**/ 
		CNODE(const CNODE & other);
		CNODE(const CNODE && other);

		virtual ~CNODE() {}

		// Operators

		CNODE & operator = (const CNODE & other) = delete;
		CNODE & operator = (const CNODE && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CNODE & cnode);

		// Getters, setters and methods

		Context getContext();
		uint64_t getDeflenCnt();

		/**
		 * This function tries to merge as many nodes as possible
		 * Starting from the results and going up to the operands (downstream -> upstream)
		**/
		virtual void upstream_merging() = 0;

		/**
		 * This function tries to shorten de depth of some chains 
		 * that formed (mostly) after upstream_merging calls
		 * (when the node refers to a single upstream node and so on)
		**/
		virtual CNODE * upstream_shortening() = 0;

		/**
		 * Virtual copy constructor
		**/
		virtual CNODE * make_copy() = 0; 

		/**
		 * (class Ciphertext, make_deep_copy method for more details)
		**/
		virtual CNODE * make_deep_copy() = 0; 

		virtual uint64_t decrypt(const SecretKey & sk) = 0;

		/**
		 * Used to permute both inplace or on a new (deep) copy
		**/
		virtual CNODE * permute(const Permutation & perm, bool force_deep_copy) = 0;

		/**
		 * Method used instead of directly deleting the current node
		 * Decides whether to decrease reference count or actually delete the node
		**/
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
#include "CNODE.h"

#if MULTITHREADING_EXTENDED_SUPPORT

#ifndef CNODE_DISJOIN_SET_H 
#define CNODE_DISJOIN_SET_H

namespace certFHE {

	class CNODE_disjoint_set {

		/**
		 * mutex that is required to be locked in order to to ANY operation on ANY set
		 * (so, there can only be one thread at a time that searches root / does union / removes)
		**/
		static std::mutex op_mutex; 

	public:

		std::mutex mtx;

		CNODE * current;

		int rank;  // upper bound for depth of the current set

		CNODE_disjoint_set * parent;  // parent of the node, root has this field 0
		CNODE_disjoint_set * child;   // one of the children of this node
		CNODE_disjoint_set * prev;  // one of the neighbours = some other child of this->parent
		CNODE_disjoint_set * next;  // same as prev

		CNODE_disjoint_set() : current(0), rank(0), parent(0), child(0), prev(0), next(0) {}

		CNODE_disjoint_set(CNODE * current_raw) : current(current_raw),
			rank(0), parent(0), child(0), prev(0), next(0) {}

		CNODE_disjoint_set(const CNODE_disjoint_set & other) = delete;
		CNODE_disjoint_set(const CNODE_disjoint_set && other) = delete;

		CNODE_disjoint_set & operator = (const CNODE_disjoint_set & other) = delete;
		CNODE_disjoint_set & operator = (const CNODE_disjoint_set && other) = delete;

		~CNODE_disjoint_set() {}

		CNODE_disjoint_set * get_root();

		void set_union(CNODE_disjoint_set * other);

		CNODE_disjoint_set * remove_from_set();
	};
}

#endif

#endif


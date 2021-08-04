#include "CNODE_disjoint_set.h"

namespace certFHE {
	
	CNODE_disjoint_set * CNODE_disjoint_set::get_root() {

		if (this->parent != 0) {

			CNODE_disjoint_set * root = this->parent->get_root();

			/**
			 * condition to reduce overhead 
			 * in the common case in which the root is also the parent
			**/
			if (root != this->parent) {  

				// path compression

				if (this->prev != 0) {

					this->prev->next = this->next;
					this->parent->child = this->prev; // (one of the ways to) make sure the parent points to another valid child
				}

				if (this->next != 0) {

					this->next->prev = this->prev;
					this->parent->child = this->next; // (one of the ways to) make sure the parent points to another valid child
				}

				this->parent = root;

				// one of the ways to rewire the pointers 

				CNODE_disjoint_set * root_oldchild = root->child;  // guaranteed to NOT be null,
																   // otherwise there would not be any path to the root
				root->child = this;
				this->prev = root_oldchild;
				this->next = root_oldchild->next;
				root_oldchild->next = this;

				if (this->next != 0)
					this->next->prev = this;
			}

			return root;
		}
		else
			return this;
	}

	void CNODE_disjoint_set::set_union(CNODE_disjoint_set * other) {

		CNODE_disjoint_set * fst_root = this->get_root();
		CNODE_disjoint_set * snd_root = other->get_root();

		if (fst_root == snd_root)
			return;

		if (fst_root->rank < snd_root->rank)
			std::swap(fst_root, snd_root);

		snd_root->parent = fst_root;

		// one of the ways to rewire the pointers 

		CNODE_disjoint_set * fst_root_oldchild = fst_root->child;  // guaranteed to NOT be null,
																   // otherwise there would not be any path to the root
		fst_root->child = snd_root;
		snd_root->prev = fst_root_oldchild;
		snd_root->next = fst_root_oldchild->next;
		fst_root_oldchild->next = snd_root;

		if (snd_root->next != 0)
			snd_root->next->prev = snd_root;

		// increase rank 

		if (fst_root->rank == snd_root->rank)
			fst_root->rank += 1;
	}

	void CNODE_disjoint_set::remove_from_set(CNODE_disjoint_set * to_remove) {


	}
}

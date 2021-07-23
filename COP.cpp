#include "COP.h"

namespace certFHE {

	COP::COP(Context * context): CNODE(context) {

		this->nodes = new CNODE_list;
		this->nodes->prev = 0;
		this->nodes->next = 0;
		this->nodes->current = (CNODE *)0xDEADBEEFDEADBEEF;
	}

	COP::~COP() {

		try {

			nodes->current = 0; // dummy current node set to 0
			while (nodes != 0) 
				nodes = nodes->pop_current_node();

		}
		catch (std::exception e) {

			std::cout << "ERROR in destructor of COP node: " << e.what() << '\n';
		}
	}

	COP::COP(const COP & other) : CNODE(other) {

		this->nodes = new CNODE_list;
		this->nodes->prev = 0;
		this->nodes->next = 0;
		this->nodes->current = (CNODE *)0xDEADBEEFDEADBEEF;

		CNODE_list * othernodes = other.nodes->next;
		
		while (othernodes != 0 && othernodes->current != 0) {

			this->nodes->insert_next_element(othernodes->current);
			othernodes->current->downstream_reference_count += 1;

			othernodes = othernodes->next;
		}
	}

	COP::COP(const COP && other) : CNODE(other) {

		this->nodes = other.nodes;
	}

	//TODO: check for multiple references, if true create new nodes
	void COP::permute_inplace(const Permutation & perm) {

		CNODE_list * thisnodes = this->nodes->next;

		if (thisnodes == 0 || thisnodes->current == 0)
			return;

		while (thisnodes != 0 && thisnodes->current != 0) {

			thisnodes->current->permute_inplace(perm);
			thisnodes = thisnodes->next;
		}
	}
}





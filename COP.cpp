#include "COP.h"

namespace certFHE {

	COP::~COP() {

		try {

			while (nodes != 0 && nodes->current != 0) {

				nodes->current->downstream_reference_count -= 1;
				nodes->current->try_delete();

				nodes = nodes->next;
			}
		}
		catch (std::exception e) {

			std::cout << "ERROR in destructor of COP node: " << e.what() << '\n';
		}
	}

	COP::COP(const COP & other) : CNODE(other) {

		this->nodes = new CNODE_list;

		CNODE_list * othernodes = other.nodes;
		while (othernodes != 0 && othernodes->current != 0) {

			this->nodes->insert_next_element(othernodes->current);
			othernodes->current->downstream_reference_count += 1;
		}
	}

	COP::COP(const COP && other) : CNODE(other) {

		this->nodes = other.nodes;
	}

}





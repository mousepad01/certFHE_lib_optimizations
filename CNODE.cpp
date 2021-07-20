#include "CNODE.h"

namespace certFHE {

	CNODE::CNODE(const CNODE & other) {

		this->deflen_count = other.deflen_count;
		this->context = other.context;
		this->downstream_reference_count = 1;
	}

	CNODE::CNODE(const CNODE && other) {

		this->deflen_count = other.deflen_count;
		this->context = other.context;
		this->downstream_reference_count = other.downstream_reference_count;
	}

	void CNODE::try_delete() {

		if (this->downstream_reference_count == 1)
			delete this;

		else if (this->downstream_reference_count < 1)
			std::cout << "ERROR in try_delete: reference count smaller than 1 (nothing got deleted)\n";

		else
			this->downstream_reference_count -= 1;
	}

}


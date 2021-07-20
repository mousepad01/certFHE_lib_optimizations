#include "CADD.h"
#include "CMUL.h"

namespace certFHE {

	void CADD::upstream_merging() {

		if (this->nodes == 0 || this->nodes->current == 0)
			return;

		CNODE_list * node_i = this->nodes;
		while (node_i != 0 && node_i->next != 0) {

			CNODE_list * node_j = node_i->next;
			while (node_j != 0) {

				if (OPTValues::remove_duplicates_onadd && node_i != node_j && node_i->current == node_j->current) {

					node_i = node_i->pop_current_node();
					node_j = node_j->pop_current_node();

					continue;
				}

				CNODE * merged = CADD::upstream_merging(node_i->current, node_j->current);

				if (merged == 0) {

					node_j = node_j->next;
					continue;
				}

				/**
				 * try to delete current node 
				 * if there is another reference to it, it will remain in memory
				 * but in any case the current pointer will be overwritten with the new node
				**/
				node_i->current->try_delete();
				node_i->current = merged;

				node_j = node_j->pop_current_node(); // try_delete included
			}

			node_i = node_i->next;
		}

	}

	CNODE * CADD::make_copy() {

		return new CADD(*this);
	}

	CNODE * CADD::upstream_merging(CNODE * fst, CNODE * snd) {

		CCC * fst_c = dynamic_cast<CCC *>(fst);
		if (fst_c != 0) {

			CCC * snd_c = dynamic_cast<CCC *>(fst);
			if (snd_c != 0)
				return CADD::upstream_merging((CCC *)fst_c, (CCC *)snd_c);

			else {

				CADD * snd_c = dynamic_cast<CADD *>(fst);
				if (snd_c != 0)
					return CADD::upstream_merging((CADD *)snd_c, (CCC *)fst_c);

				else {

					CMUL * snd_c = dynamic_cast<CMUL *>(fst);
					return CADD::upstream_merging((CMUL *)snd_c, (CCC *)fst_c);
				}
			}
		}
		else {

			CADD * fst_c = dynamic_cast<CADD *>(fst);
			if (fst_c != 0) {

				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CADD::upstream_merging((CADD *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CADD::upstream_merging((CADD *)fst_c, (CADD *)snd_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CADD::upstream_merging((CADD *)fst_c, (CMUL *)snd_c);
					}
				}
			}
			else {

				CMUL * fst_c = dynamic_cast<CMUL *>(fst);
				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CADD::upstream_merging((CMUL *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CADD::upstream_merging((CADD *)snd_c, (CMUL *)fst_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CADD::upstream_merging((CMUL *)fst_c, (CMUL *)snd_c);
					}
				}
			}
		}
	}

	CNODE * CADD::__upstream_merging(CADD * fst, CADD * snd) { 

		CNODE_list * nodes_fst = fst->nodes;
		CNODE_list * nodes_snd = snd->nodes;

		/**
		 * When one of the input nodes is empty
		 * return the other one
		 * but the caller function will see it as a "different node"
		 * so also increase ref count
		 * (copy constructor avoided for efficiency)
		**/
		if (fst->nodes == 0 || fst->nodes->current == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		if (snd->nodes == 0 || snd->nodes->current == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}
			
		CADD * merged = new CADD(fst->context); // fst->context == snd->context assumed

		if (OPTValues::remove_duplicates_onadd) {

			std::unordered_map <CNODE *, int> freq;

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				if (freq.find(nodes_fst->current) == freq.end())
					freq[nodes_fst->current] = 1;

				else
					freq[nodes_fst->current] += 1;

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				if (freq.find(nodes_snd->current) == freq.end())
					freq[nodes_snd->current] = 1;

				else
					freq[nodes_snd->current] += 1;

				nodes_snd = nodes_snd->next;
			}

			nodes_fst = fst->nodes;
			nodes_snd = snd->nodes;

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				if (freq[nodes_fst->current] % 2) {

					CNODE * new_pointer_same_node = nodes_fst->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
				}

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				if (freq[nodes_snd->current] % 2) {

					CNODE * new_pointer_same_node = nodes_snd->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
				}

				nodes_fst = nodes_fst->next;
			}
		}
		else {

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				CNODE * new_pointer_same_node = nodes_fst->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				CNODE * new_pointer_same_node = nodes_snd->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;

				nodes_fst = nodes_fst->next;
			}
		}

		return merged;
	}

	CNODE * CADD::__upstream_merging(CADD * fst, CMUL * snd) { 


	
	}

	CNODE * CADD::__upstream_merging(CMUL * fst, CMUL * snd) { return 0; }

	CNODE * CADD::__upstream_merging(CADD * fst, CCC * snd) { return 0; }
	CNODE * CADD::__upstream_merging(CCC * fst, CCC * snd) { return 0; }
	CNODE * CADD::__upstream_merging(CMUL * fst, CCC * snd) { return 0; }
}


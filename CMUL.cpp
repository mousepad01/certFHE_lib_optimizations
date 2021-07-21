#include "CADD.h"
#include "CMUL.h"

namespace certFHE {

	void CMUL::upstream_merging() {

		CNODE_list * thisnodes = this->nodes->next; // skipping dummy element

		if (thisnodes == 0 || thisnodes->current == 0)
			return;

		/**
		 * Iterating through all upstream referenced nodes and trying to merge as much as possible
		**/
		CNODE_list * node_i = thisnodes;
		while (node_i != 0 && node_i->next != 0) {

			CNODE_list * node_j = node_i->next;
			while (node_j != 0 && node_i != 0) {

				/**
				 * (optional) Check for duplicate nodes to be removed (a + a = a)
				**/
				if (OPValues::remove_duplicates_onmul && node_i != node_j && node_i->current == node_j->current) {

					node_j = node_j->pop_current_node();
					continue;
				}

				CNODE * merged = CMUL::upstream_merging(node_i->current, node_j->current);

				/**
				 * If nothing has been returned, it means no merge happened, so everything stays the same
				**/
				if (merged == 0) {

					node_j = node_j->next;
					continue;
				}

				/**
				 * If merged has deflen_cnt = 0, it means
				 * that by multiplying by that node, you obtain 0
				 * so EVERY NODE IS REMOVED
				**/
				if (merged->deflen_count == 0) {

					this->deflen_count = 0;

					/**
					 * CCC can never have null deflen count,
					 * so it is a COP node 
					**/
					COP * merged_cop = dynamic_cast<COP *>(merged);
					while (merged_cop->nodes->next != 0) 
						merged_cop->nodes->next->pop_current_node();

					return;
				}

				/**
				 * try to delete the current node
				 * if there is another reference to it, it will remain in memory
				 * but in any case the current pointer will be overwritten with the new node
				**/
				node_i->current->try_delete();
				node_i->current = merged;

				node_j = node_j->pop_current_node(); // try_delete included
			}

			if (node_i != 0)
				node_i = node_i->next;
		}

		/**
		 * If at least one of the options is activated, size of any node can shrink when merging
		 * So the recalculation of deflen_cnt is necessary
		**/
		if (OPValues::remove_duplicates_onadd || OPValues::remove_duplicates_onmul) {

			thisnodes = this->nodes->next;

			this->deflen_count = 0;
			if (thisnodes != 0 && thisnodes->current != 0)
				this->deflen_count = 1;
			
			while (thisnodes != 0 && thisnodes->current != 0) {

				this->deflen_count *= thisnodes->current->deflen_count;  // =+ instead of =* 
				thisnodes = thisnodes->next;
			}
		}
	}

	CNODE * CMUL::make_copy() {

		return new CMUL(*this);
	}

	CNODE * CMUL::upstream_merging(CNODE * fst, CNODE * snd) {

		CCC * fst_c = dynamic_cast<CCC *>(fst);
		if (fst_c != 0) {

			CCC * snd_c = dynamic_cast<CCC *>(fst);
			if (snd_c != 0)
				return CMUL::__upstream_merging((CCC *)fst_c, (CCC *)snd_c);

			else {

				CADD * snd_c = dynamic_cast<CADD *>(fst);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CADD *)snd_c, (CCC *)fst_c);

				else {

					CMUL * snd_c = dynamic_cast<CMUL *>(fst);
					return CMUL::__upstream_merging((CMUL *)snd_c, (CCC *)fst_c);
				}
			}
		}
		else {

			CADD * fst_c = dynamic_cast<CADD *>(fst);
			if (fst_c != 0) {

				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CADD *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CMUL::__upstream_merging((CADD *)fst_c, (CADD *)snd_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CMUL::__upstream_merging((CADD *)fst_c, (CMUL *)snd_c);
					}
				}
			}
			else {

				CMUL * fst_c = dynamic_cast<CMUL *>(fst);
				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CMUL *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CMUL::__upstream_merging((CADD *)snd_c, (CMUL *)fst_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CMUL::__upstream_merging((CMUL *)fst_c, (CMUL *)snd_c);
					}
				}
			}
		}

		return 0;
	}

	CNODE * CMUL::__upstream_merging(CADD * fst, CADD * snd) { 

		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false || 
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		CNODE_list * fst_nodes = fst->nodes->next;
		CNODE_list * snd_nodes = snd->nodes->next;

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		distributed_mul->deflen_count = 1;

		while (fst_nodes != 0 && fst_nodes->current != 0) {

			while (snd_nodes != 0 && snd_nodes->current != 0) {

				CMUL * term_mul = new CMUL(fst->context);
				distributed_mul->nodes->insert_next_element(term_mul);

				CNODE * new_pointer_same_fst_node = fst_nodes->current;
				CNODE * new_pointer_same_snd_node = fst_nodes->current;

				new_pointer_same_fst_node->downstream_reference_count += 1;
				new_pointer_same_snd_node->downstream_reference_count += 1;

				term_mul->nodes->insert_next_element(new_pointer_same_fst_node);
				term_mul->nodes->insert_next_element(new_pointer_same_snd_node);

				term_mul->upstream_merging();

				distributed_mul->deflen_count *= term_mul->deflen_count;
			}
		}

		return distributed_mul;
	}

	CNODE * CMUL::__upstream_merging(CADD * fst, CMUL * snd) { 

		// almost identical to upstream merging (CADD, CCC) ?
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		CNODE_list * fst_nodes = fst->nodes->next;

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		distributed_mul->deflen_count = 1;

		while (fst_nodes != 0 && fst_nodes->current != 0) {

			CMUL * term_mul = new CMUL(fst->context);
			distributed_mul->nodes->insert_next_element(term_mul);

			CNODE * new_pointer_same_node = fst_nodes->current;

			new_pointer_same_node->downstream_reference_count += 1;
			snd->downstream_reference_count += 1;

			term_mul->nodes->insert_next_element(new_pointer_same_node);
			term_mul->nodes->insert_next_element(snd);

			term_mul->upstream_merging();

			distributed_mul->deflen_count *= term_mul->deflen_count;
		}

		return distributed_mul;
	}

	CNODE * CMUL::__upstream_merging(CMUL * fst, CMUL * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		CNODE_list * nodes_fst = fst->nodes->next; // skipping dummy elements
		CNODE_list * nodes_snd = snd->nodes->next;

		/**
		 * When one of the input nodes is empty
		 * return the empty one (0 * a = 0)
		 * but the caller function will see it as a "different node"
		 * so also increase ref count
		 * (copy constructor avoided for efficiency)
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		CMUL * merged = new CMUL(fst->context); // fst->context == snd->context assumed

		merged->deflen_count = 0;
		if ((nodes_fst != 0 && nodes_fst->current != 0) || (nodes_snd != 0 && nodes_snd->current != 0))
			merged->deflen_count = 1;

		if (OPValues::remove_duplicates_onmul) {

			std::unordered_set <CNODE *> freq;

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				if (freq.find(nodes_fst->current) == freq.end()) {

					CNODE * new_pointer_same_node = nodes_fst->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
					merged->deflen_count *= new_pointer_same_node->deflen_count;

					freq.insert(nodes_fst->current);
				}

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				if (freq.find(nodes_snd->current) == freq.end()) {

					CNODE * new_pointer_same_node = nodes_snd->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
					merged->deflen_count *= new_pointer_same_node->deflen_count;

					freq.insert(nodes_snd->current);
				}

				nodes_fst = nodes_fst->next;
			}
		}
		else {

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				CNODE * new_pointer_same_node = nodes_fst->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;
				merged->deflen_count *= new_pointer_same_node->deflen_count;

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				CNODE * new_pointer_same_node = nodes_snd->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;
				merged->deflen_count *= new_pointer_same_node->deflen_count;

				nodes_fst = nodes_fst->next;
			}
		}

		/**
		 * Recursive call that stops when max_merge_size < merging size
		**/
		merged->upstream_merging();

		return merged;
	}

	CNODE * CMUL::__upstream_merging(CADD * fst, CCC * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		CNODE_list * fst_nodes = fst->nodes->next;

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		distributed_mul->deflen_count = 1;

		while (fst_nodes != 0 && fst_nodes->current != 0) {

			CMUL * term_mul = new CMUL(fst->context);
			distributed_mul->nodes->insert_next_element(term_mul);

			CNODE * new_pointer_same_node = fst_nodes->current;

			new_pointer_same_node->downstream_reference_count += 1;
			snd->downstream_reference_count += 1;

			term_mul->nodes->insert_next_element(new_pointer_same_node);
			term_mul->nodes->insert_next_element(snd);

			term_mul->upstream_merging();

			distributed_mul->deflen_count *= term_mul->deflen_count;
		}

		return distributed_mul;
	}

	CNODE * CMUL::__upstream_merging(CCC * fst, CCC * snd) { 
		
		if (fst->deflen_count * snd->deflen_count > OPValues::max_ccc_deflen_size)
			return 0;

		else
			return CCC::multiply(fst, snd);
	}

	CNODE * CMUL::__upstream_merging(CMUL * fst, CCC * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		if (fst->nodes->next == 0 || fst->nodes->next->current == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		CMUL * merged;

		if (fst->downstream_reference_count == 1) {

			fst->downstream_reference_count += 1;

			snd->downstream_reference_count += 1;
			fst->nodes->insert_next_element(snd);
			fst->deflen_count += snd->deflen_count;

			merged = fst;
		}
		else {

			merged = new CMUL(*fst);

			snd->downstream_reference_count += 1;
			merged->nodes->insert_next_element(snd);
			merged->deflen_count += snd->deflen_count;
		}

		merged->upstream_merging();

		return merged;
	}
}



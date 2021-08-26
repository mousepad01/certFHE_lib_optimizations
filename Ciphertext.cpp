#include "Ciphertext.h"
#include "GlobalParams.h"
#include "Threadpool.h"
#include "SecretKey.h"
#include "Permutation.h"
#include "Plaintext.h"
#include "Context.h"
#include "CMUL.h"
#include "CADD.h"

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT
#include "CNODE_disjoint_set.h"
#endif

namespace certFHE{

#pragma region Public methods

	Plaintext Ciphertext::decrypt(const SecretKey & sk) const {

		return Plaintext(this->decrypt_raw(sk));
	}

	unsigned char * Ciphertext::serialize(const int ctxt_count, Ciphertext ** to_serialize_arr) {

		/**
		 * Serialization for:
		 *		Ciphertext: id 4 bytes, node id 4 bytes
		 *		CCC: id 4 bytes, deflen cnt 8 bytes, ctxt (deflen cnt * deflen to u64 * sizeof(u64)) bytes
		 *		CADD, CMUL: id 4 bytes, deflen cnt 8 bytes, upstream ref cnt 8 bytes, upstream ref IDs (sizeof(u32) * upstream ref cnt) bytes
		**/

		/**
		 * It contains the (temporary) IDs for a Ciphertext object
		 *
		 * ID restrictions:
		 *		CCC: first 2 bits 00
		 *		CADD: first 2 bits 01
		 *		CMUL: first 2 bits 10
		 *		Ciphertext: first 2 bits 11
		 * 
		 * NOTE: to conserve this restriction, the IDs will be incremented by 0b100
		**/
		static uint32_t temp_ctxt_id = 3; // 0b00....000 11

		/**
		 * Associates an (id, byte length) for every Ciphertext / CNODE (address)
		 * The associated id is local to the current serialization
		 * And the byte length is the size that node will occupy in the serialization
		 * It also helps to eliminate duplicates in the current serialization
		**/
		std::unordered_map <void *, std::pair <uint32_t, int>> addr_to_id;

		for (int i = 0; i < ctxt_count; i++) {

			if (addr_to_id.find(to_serialize_arr[i]) != addr_to_id.end()) 
				continue;

			addr_to_id[to_serialize_arr[i]] = { temp_ctxt_id, (int)(2 * sizeof(uint32_t)) }; // ID of the current Ciphertext, ID of its associated CNODE
			temp_ctxt_id += 0b100;

			to_serialize_arr[i]->node->serialize_recon(addr_to_id);
		}

		/**
		 * Serialization byte array total length
		 * It is incremented with the help of the "serialization recon" recursive calls
		**/
		int ser_byte_length = 0;

		/**
		 * First elements in a serialization array are ALWAYS its Ciphertext object count and context attributes
		**/
		ser_byte_length += sizeof(uint32_t) + 4 * sizeof(uint64_t);

		for (auto entry : addr_to_id) 
			ser_byte_length += entry.second.second;

		unsigned char * serialization = new unsigned char[ser_byte_length];

		uint32_t * ser_int32 = (uint32_t *)serialization;
		ser_int32[0] = (uint32_t)ctxt_count;

		Context * context = to_serialize_arr[0]->node->context;

		uint64_t * ser_int64 = (uint64_t *)(serialization + sizeof(uint32_t));

		ser_int64[0] = context->getN();
		ser_int64[1] = context->getD();
		ser_int64[2] = context->getS();
		ser_int64[3] = context->getDefaultN();

		int ser_offset = sizeof(uint32_t) + 4 * sizeof(uint64_t);
		int cntc = 0;
		for (auto entry : addr_to_id) {
			
			if (CERTFHE_CTXT_ID(entry.second.first)) {

				Ciphertext * ciphertext = (Ciphertext *)entry.first;
				cntc += 1;
				ser_int32 = (uint32_t *)(serialization + ser_offset);
				
				ser_int32[0] = entry.second.first;
				ser_int32[1] = addr_to_id[ciphertext->node].first;

				ser_offset += 2 * sizeof(uint32_t);
			}
			else {
				
				CNODE * node = (CNODE *)entry.first;

				node->serialize(serialization + ser_offset, addr_to_id);
				ser_offset += entry.second.second;
			}
		}

		return serialization;
	}

	std::pair <Ciphertext **, Context> Ciphertext::deserialize(unsigned char * serialization) {

		std::unordered_map <uint32_t, void *> id_to_addr;

		uint32_t * ser_int32 = (uint32_t *)serialization;
		int ctxt_cnt = (int)ser_int32[0];

		uint64_t * ser_int64 = (uint64_t *)(serialization + sizeof(uint32_t));
		Context context(ser_int64[0], ser_int64[1]);

		Ciphertext ** deserialized = new Ciphertext *[ctxt_cnt];

		/**
		 * Iterating two times through the serialization array
		 *
		 * The first time, it creates the corresponding Ciphertext / CNODE objects in memory,
		 * but does NOT link them
		 *
		 * The second time, it links the CNODE objects between them
		 * and also links Ciphertext objects with their nodes
		**/

		ser_int32 = (uint32_t *)(serialization + 9 * sizeof(uint32_t));
		int ser32_offset = 0;

		uint32_t current_id = ser_int32[0];
		int ctxt_i = 0;

		while (current_id != 0) {

			if (CERTFHE_CTXT_ID(current_id)) {

				deserialized[ctxt_i] = new Ciphertext();
				id_to_addr[current_id] = deserialized[ctxt_i];

				ser32_offset += 2; 
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;			
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, false);
				current_id = ser_int32[ser32_offset];
			}
		}

		ser_int32 = (uint32_t *)(serialization + 9 * sizeof(uint32_t));
		ser32_offset = 0;

		current_id = ser_int32[0];
		ctxt_i = 0;

		while (current_id != 0) {

			if (CERTFHE_CTXT_ID(current_id)) {

				uint32_t node_id = ser_int32[ser32_offset + 1];

				deserialized[ctxt_i]->node = (CNODE *)id_to_addr[node_id];
				deserialized[ctxt_i]->node->downstream_reference_count += 1;

				ser32_offset += 2;
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, context, true);
				current_id = ser_int32[ser32_offset];
			}
		}

		return { deserialized, context };
	}

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

	uint64_t Ciphertext::decrypt_raw(const SecretKey & sk) const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex> lock(this->concurrency_guard->get_root()->mtx);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *sk.getContext())
			throw std::runtime_error("ciphertext and secret key do not have the same context");

		uint64_t dec = this->node->decrypt(sk);
		return dec;
	}

	Ciphertext Ciphertext::applyPermutation(const Permutation & permutation) {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		// guard locked inside copy constructor
		Ciphertext permuted_ciphertext(*this);

		std::scoped_lock <std::mutex> lock(permuted_ciphertext.concurrency_guard->get_root()->mtx);

		if (permuted_ciphertext.node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = permuted_ciphertext.node->permute(permutation, true);

		permuted_ciphertext.node->try_delete();
		permuted_ciphertext.node = permuted;

		return permuted_ciphertext;
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex> lock(this->concurrency_guard->get_root()->mtx);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = this->node->permute(permutation, false);

		this->node->try_delete();
		this->node = permuted;
	}

	Ciphertext Ciphertext::make_deep_copy() const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex> lock(this->concurrency_guard->get_root()->mtx);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext deepcopy;
		deepcopy.node = this->node->make_deep_copy();

		return deepcopy;
	}

#else

	uint64_t Ciphertext::decrypt_raw(const SecretKey & sk) const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *sk.getContext())
			throw std::runtime_error("ciphertext and secret key do not have the same context");

		uint64_t dec = this->node->decrypt(sk);
		return dec;
	}

	Ciphertext Ciphertext::applyPermutation(const Permutation & permutation) {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext permuted_ciphertext(*this);

		CNODE * permuted = permuted_ciphertext.node->permute(permutation, true);

		permuted_ciphertext.node->try_delete();
		permuted_ciphertext.node = permuted;

		return permuted_ciphertext;
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = this->node->permute(permutation, false);
		
		this->node->try_delete();
		this->node = permuted;
	}

	Ciphertext Ciphertext::make_deep_copy() const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext deepcopy;
		deepcopy.node = this->node->make_deep_copy();

		return deepcopy;
	}

#endif

#pragma endregion

#pragma region Private methods

	CNODE * Ciphertext::add(CNODE * fst, CNODE * snd) {

		CADD * addition_result = new CADD(fst->context);

		/**
		 * From now on, fst and snd nodes
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		addition_result->nodes->insert_next_element(fst);
		addition_result->nodes->insert_next_element(snd);

		addition_result->deflen_count = fst->deflen_count + snd->deflen_count;

		addition_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = addition_result->upstream_shortening();
		if (shortened != 0) {

			addition_result->try_delete();
			return shortened;
		}

		return addition_result;
	}

	CNODE * Ciphertext::multiply(CNODE * fst, CNODE * snd) {

		CMUL * mul_result = new CMUL(fst->context);

		/**
		 * From now on, fst and snd nodes 
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		mul_result->nodes->insert_next_element(fst);
		mul_result->nodes->insert_next_element(snd);

		mul_result->deflen_count = fst->deflen_count * snd->deflen_count;

		mul_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = mul_result->upstream_shortening();
		if (shortened != 0) {

			mul_result->try_delete();
			return shortened;
		}

		return mul_result;
	}

#pragma endregion

#pragma region Operators

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::mutex & this_mtx = this->concurrency_guard->get_root()->mtx;
		std::mutex & c_mtx = c.concurrency_guard->get_root()->mtx;

		if (&this_mtx != &c_mtx) {
			
			std::scoped_lock <std::mutex, std::mutex> lock(this_mtx, c_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * addition_result;
			Ciphertext add_result_c;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			/**
			 * When two ctxt refer to a CCC, operations are performed directly
			 * NOTE: the result CCC is always a different one, so there is no need for concurrency_guard union
			**/
			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				addition_result = CCC::add(ccc_thisnode, ccc_othernode);

			else {

				/**
				 * The called method will treat arguments as different nodes
				 * So the reference count temporarily increases
				 * (although not necessary ???)
				**/
				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				addition_result = Ciphertext::add(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				add_result_c.concurrency_guard->set_union(this->concurrency_guard);
				add_result_c.concurrency_guard->set_union(c.concurrency_guard);
			}

			add_result_c.node = addition_result;
			return add_result_c;
		}
		else {
			
			std::scoped_lock <std::mutex> lock(this_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * addition_result;
			Ciphertext add_result_c;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			/**
			 * When two ctxt refer to a CCC, operations are performed directly
			**/
			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				addition_result = CCC::add(ccc_thisnode, ccc_othernode);

			else {

				/**
				 * The called method will treat arguments as different nodes
				 * So the reference count temporarily increases
				 * (although not necessary ???)
				**/
				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				addition_result = Ciphertext::add(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				add_result_c.concurrency_guard->set_union(this->concurrency_guard);
			}

			add_result_c.node = addition_result;
			return add_result_c;
		}
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no concurrency guard");

		std::mutex & this_mtx = this->concurrency_guard->get_root()->mtx;
		std::mutex & c_mtx = c.concurrency_guard->get_root()->mtx;

		if (&this_mtx != &c_mtx) {

			std::scoped_lock <std::mutex, std::mutex> lock(this_mtx, c_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * mul_result;
			Ciphertext mul_result_c;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				mul_result = Ciphertext::multiply(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				mul_result_c.concurrency_guard->set_union(this->concurrency_guard);
				mul_result_c.concurrency_guard->set_union(c.concurrency_guard);
			}

			mul_result_c.node = mul_result;
			return mul_result_c;
		}
		else {

			std::scoped_lock <std::mutex> lock(this_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * mul_result;
			Ciphertext mul_result_c;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				mul_result = Ciphertext::multiply(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				mul_result_c.concurrency_guard->set_union(this->concurrency_guard);
			}

			mul_result_c.node = mul_result;
			return mul_result_c;
		}

		
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no concurrency guard");

		std::mutex & this_mtx = this->concurrency_guard->get_root()->mtx;
		std::mutex & c_mtx = c.concurrency_guard->get_root()->mtx;

		if (&this_mtx != &c_mtx) {

			std::scoped_lock <std::mutex, std::mutex> lock(this_mtx, c_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * addition_result;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				addition_result = CCC::add(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				addition_result = Ciphertext::add(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				this->concurrency_guard->set_union(c.concurrency_guard);
			}

			this->node->try_delete();
			this->node = addition_result;

			return *this;
		}
		else {

			std::scoped_lock <std::mutex> lock(this_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * addition_result;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				addition_result = CCC::add(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				addition_result = Ciphertext::add(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;
			}

			this->node->try_delete();
			this->node = addition_result;

			return *this;
		}

		
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no concurrency guard");

		std::mutex & this_mtx = this->concurrency_guard->get_root()->mtx;
		std::mutex & c_mtx = c.concurrency_guard->get_root()->mtx;

		if (&this_mtx != &c_mtx) {

			std::scoped_lock <std::mutex, std::mutex> lock(this_mtx, c_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * mul_result;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				mul_result = Ciphertext::multiply(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;

				this->concurrency_guard->set_union(c.concurrency_guard);
			}

			this->node->try_delete();
			this->node = mul_result;

			return *this;
		}
		else {

			std::scoped_lock <std::mutex> lock(this_mtx);

			if (c.node == 0 || this->node == 0)
				throw std::invalid_argument("Cannot operate on ciphertext with no value");

			if (*this->node->context != *c.node->context)
				throw std::runtime_error("ciphertexts do not have the same context");

			CNODE * mul_result;

			CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
			CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

			if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
				mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

			else {

				if (this->node == c.node)
					this->node->downstream_reference_count += 1;

				mul_result = Ciphertext::multiply(this->node, c.node);

				if (this->node == c.node)
					this->node->downstream_reference_count -= 1;
			}

			this->node->try_delete();
			this->node = mul_result;

			return *this;
		}

		
	}

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		if (c.concurrency_guard == 0) 
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex> lock(c.concurrency_guard->get_root()->mtx);

		if (c.node == 0)
			out << "EMPTY CIPHERTEXT";

		CCC * ccc_node = dynamic_cast <CCC *> (c.node);
		if (ccc_node != 0)
			out << *ccc_node << '\n';

		else {

			COP * cop_node = dynamic_cast <COP *> (c.node);
			if (cop_node != 0)
				out << *cop_node << '\n';
		}

		return out;
	}
	
	Ciphertext & Ciphertext::operator = (const Ciphertext & c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (this->concurrency_guard == 0 || c.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::mutex & this_mtx = this->concurrency_guard->get_root()->mtx;
		std::mutex & c_mtx = c.concurrency_guard->get_root()->mtx;

		if (&this_mtx != &c_mtx) {

			CNODE_disjoint_set * removed;

			{
				std::scoped_lock <std::mutex, std::mutex> lock(this_mtx, c_mtx);

				if (this->node != 0)
					this->node->try_delete();

				if (c.node != 0)
					c.node->downstream_reference_count += 1;

				this->node = c.node;

				removed = this->concurrency_guard->remove_from_set();

				this->concurrency_guard = new CNODE_disjoint_set(this);
				this->concurrency_guard->set_union(c.concurrency_guard);
			}

			delete removed;

			return *this;
		}
		else
			return *this;
	}
	
	Ciphertext & Ciphertext::operator = (Ciphertext && c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");
		
		if (this->concurrency_guard == 0 || c.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		CNODE_disjoint_set * removed;

		{	
			std::scoped_lock <std::mutex> lock(this->concurrency_guard->get_root()->mtx);

			if (this->node != 0)
				this->node->try_delete();

			removed = this->concurrency_guard->remove_from_set();

			this->node = c.node;
			this->concurrency_guard = c.concurrency_guard;
			this->concurrency_guard->current = this;

			c.node = 0;
			c.concurrency_guard = 0;
		}
		
		delete removed;
		
		return *this;
	}

#else

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * addition_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else 
			addition_result = Ciphertext::add(this->node, c.node);

		Ciphertext add_result_c;
		add_result_c.node = addition_result;

		return add_result_c;
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * mul_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else 
			mul_result = Ciphertext::multiply(this->node, c.node);

		Ciphertext mul_result_c;
		mul_result_c.node = mul_result;

		return mul_result_c;
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * addition_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else 
			addition_result = Ciphertext::add(this->node, c.node);

		this->node->try_delete();
		this->node = addition_result;

		return *this;
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * mul_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else 
			mul_result = Ciphertext::multiply(this->node, c.node);

		this->node->try_delete();
		this->node = mul_result;

		return *this;
	}

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		if (c.node == 0)
			out << "EMPTY CIPHERTEXT";

		CCC * ccc_node = dynamic_cast <CCC *> (c.node);
		if (ccc_node != 0)
			out << *ccc_node << '\n';

		else {

			COP * cop_node = dynamic_cast <COP *> (c.node);
			if (cop_node != 0)
				out << *cop_node << '\n';
		}

		return out;
	}

	Ciphertext & Ciphertext::operator = (const Ciphertext & c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (&c == this)
			return *this;

		if (this->node != 0)
			this->node->try_delete();

		if (c.node != 0)
			c.node->downstream_reference_count += 1;

		this->node = c.node;

		return *this;
	}

	Ciphertext & Ciphertext::operator = (Ciphertext && c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (this->node != 0)
			this->node->try_delete();

		this->node = c.node;
		c.node = 0;

		return *this;
	}

#endif

#pragma endregion

#pragma region Constructors and destructor

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

	Ciphertext::Ciphertext() : node(0), concurrency_guard(new CNODE_disjoint_set(this)) {}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif
		
		this->concurrency_guard = new CNODE_disjoint_set(this);
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);
#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif

		this->concurrency_guard = new CNODE_disjoint_set(this);
	}

	Ciphertext::Ciphertext(const Ciphertext & ctxt) {

		if (ctxt.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex> lock(ctxt.concurrency_guard->get_root()->mtx);

		if (ctxt.node != 0) {

			ctxt.node->downstream_reference_count += 1;

			this->node = ctxt.node;

			this->concurrency_guard = new CNODE_disjoint_set(this);
			this->concurrency_guard->set_union(ctxt.concurrency_guard);
		}
		else
			this->node = 0;
	}

	Ciphertext::Ciphertext(Ciphertext && ctxt) {

		this->node = ctxt.node;
		this->concurrency_guard = ctxt.concurrency_guard;
		this->concurrency_guard->current = this;

		ctxt.node = 0;
		ctxt.concurrency_guard = 0;
	}

	Ciphertext::~Ciphertext() {
		
		if (this->concurrency_guard != 0) {
			
			CNODE_disjoint_set * removed;
			
			{
				std::scoped_lock <std::mutex> lock(this->concurrency_guard->get_root()->mtx);

				if (this->node != 0)
					this->node->try_delete();

				removed = this->concurrency_guard->remove_from_set();
			}

			/**
			 * In the case the set only has one element, the lock needs to be released 
			 * before it can be deleted with the entire node
			 * so the delete statement is outside the scoped_lock scope
			**/
			delete removed;
		}
		else if (this->node != 0)
			std::cout << "concurrency guard is null but node is not null (check the rest of the code)";
	}

#else

	Ciphertext::Ciphertext() : node(0) {}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif
	}

	Ciphertext::Ciphertext(const Ciphertext & ctxt) {

		if (ctxt.node != 0)
			ctxt.node->downstream_reference_count += 1;

		this->node = ctxt.node;
	}

	Ciphertext::Ciphertext(Ciphertext && ctxt) {

		this->node = ctxt.node;
		ctxt.node = 0;
	}

	Ciphertext::~Ciphertext() {

		if (this->node != 0)
			this->node->try_delete();
	}

#endif
	
#pragma endregion

#pragma region Getters

	uint64_t Ciphertext::getLen() const {

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex>(this->concurrency_guard->get_root()->mtx);

#endif

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getDeflenCnt();
	}

	Context Ciphertext::getContext() const {

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::scoped_lock <std::mutex>(this->concurrency_guard->get_root()->mtx);

#endif

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getContext();
	}

#pragma endregion

}


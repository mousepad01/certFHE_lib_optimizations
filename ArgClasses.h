#ifndef ARG_CLASSES_H
#define ARG_CLASSES_H

#include "utils.h"

namespace certFHE{

	/**
	 * Base structure used for passing arguments
	**/
	class Args {

	public:

		bool task_is_done;
		std::condition_variable done;
		std::mutex done_mutex;

		Args(): task_is_done(false){}

		~Args(){}
	};

	/**
	 * Structure for addition multithreading function
	**/
	class AddArgs : public Args {

	public:

		uint64_t * fst_chunk;
		uint64_t * snd_chunk;

		uint64_t * result;

		uint64_t fst_len;

		uint64_t res_fst_deflen_pos;
		uint64_t res_snd_deflen_pos;

		~AddArgs(){}
	};

	/*
	 * Structure for multiplication multithreading function
	*/
	class MulArgs : public Args{

	public:

		uint64_t * fst_chunk;
		uint64_t * snd_chunk;

		uint64_t * result;

		uint64_t snd_chlen;

		uint64_t default_len;

		uint64_t res_fst_deflen_pos;
		uint64_t res_snd_deflen_pos;

		~MulArgs(){}
	};

	/*
	 * Structure for decryption multithreading function
	*/
	class DecArgs : public Args {

	public:

		uint64_t * to_decrypt;
		uint64_t * sk_mask;

		uint64_t default_len;
		uint64_t d;

		uint64_t fst_deflen_pos;
		uint64_t snd_deflen_pos;

		uint64_t * decrypted;

		~DecArgs(){}
	};

	/**
	 * Structure for retaining permutations as inversions
	**/
	class CtxtInversion {

	public:

		uint64_t fst_u64_ch;
		uint64_t snd_u64_ch;
		uint64_t fst_u64_r;
		uint64_t snd_u64_r;
	};

	/*
	 * Structure for permuting multithreading function
	*/
	class PermArgs : public Args {

	public:

		CtxtInversion * perm_invs;
		uint64_t inv_cnt;

		uint64_t * ctxt;

		uint64_t fst_deflen_pos;
		uint64_t snd_deflen_pos;

		uint64_t default_len;

		~PermArgs(){}
	};

	/*
	 * Structure for uint64_t array copying multithreading
	*/
	class U64CpyArgs : public Args {

	public:

		const uint64_t * src;
		uint64_t * dest;

		uint64_t fst_u64_pos;
		uint64_t snd_u64_pos;

		~U64CpyArgs(){}
	};

}

#endif
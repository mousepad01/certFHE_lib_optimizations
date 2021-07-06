#ifndef HELPERS_H
#define HELPERS_H

#include "utils.h"
#include "Threadpool.hpp"

namespace certFHE{

	/**
	 * Base structure used for passing arguments
	**/
	class Args {

	public:

		bool task_is_done;
		std::condition_variable done;
		std::mutex done_mutex;

		~Args(){}
	};

	/**
	 * Structure for addition multithreading function
	**/
	class AddArgs : public Args {

	public:

		uint64_t * fst_chunk;
		uint64_t * snd_chunk;
		uint64_t * fst_input_bitlen;
		uint64_t * snd_input_bitlen;

		uint64_t * result;
		uint64_t * result_bitlen;

		uint64_t fst_len;
		uint64_t snd_len;

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
		uint64_t * input_bitlen;

		uint64_t * result;
		uint64_t * result_bitlen;

		uint64_t fst_chlen;
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
		uint64_t * sk;

		uint64_t default_len;
		uint64_t d;
		uint64_t n;

		uint64_t fst_deflen_pos;
		uint64_t snd_deflen_pos;

		uint64_t * decrypted;

		~DecArgs(){}
	};

    /**
     * Library clased, used to perform operations at the library level, such as library initialization
    **/
    class Library{

        private:

            Library() {}

			/**
			 * Threadpool for multithreading multiplication at the library level
			**/
			static Threadpool <Args *> * threadpool;

        public:

        /**
         * Initialize the library by seeding the PRNG with local time
        **/
        static void initializeLibrary();

		static void initializeLibrary(bool initPools);

		/**
		 * Getter for multiplication threadpool
		**/
		static Threadpool <Args *> * getThreadpool();

    };

    /**
     * Helper class
    **/
    class Helper{
    
    private:

        Helper() {}
    public:

        /**
         * Static function to validate if a vector contains a specific value
        **/
        static bool exists(const uint64_t*v,const uint64_t len, const uint64_t value);

        /**
         * Deletes a pointer allocated through the certFHE library
        **/
        static void deletePointer(void* pointer, bool isArray);
    };

}

#endif
#ifndef HELPERS_H
#define HELPERS_H

#include "utils.h"
#include "Threadpool.hpp"

namespace certFHE{

	/**
	 * Structure used for passing arguments
	 * to the multiplying function in the multithreading multiplication context
	**/
	struct MulArgs {

		uint64_t * fst_chunk;
		uint64_t * snd_chunk;
		uint64_t * input_bitlen;

		uint64_t * result;
		uint64_t * result_bitlen;

		uint64_t fst_chlen;
		uint64_t snd_chlen;

		uint64_t default_len;

		int res_fst_deflen_pos;
		int res_snd_deflen_pos;

		bool task_is_done;
		std::condition_variable done;
		std::mutex done_mutex;
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
			static Threadpool <MulArgs *> * mulThreadpool;

        public:

        /**
         * Initialize the library by seeding the PRNG with local time
        **/
        static void initializeLibrary();

		static void initializeLibrary(bool initPools);

		/**
		 * Getter for multiplication threadpool
		**/
		static Threadpool <MulArgs *> * getMulThreadpool();

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
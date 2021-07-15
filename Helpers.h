#ifndef HELPERS_H
#define HELPERS_H

#include "utils.h"
#include "ArgClasses.h"
#include "Threadpool.hpp"

namespace certFHE{

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
		static void initializeLibrary(bool initPools = true);

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

		static void u64_chunk_cpy(Args * raw_args);

		static void u64_multithread_cpy(const uint64_t * src, uint64_t * dest, uint64_t to_cpy_len);
    };

}

#endif
#ifndef CUDA_INTERFACE_H
#define CUDA_INTERFACE_H

/**
 * Macro to enable(parametrized) CUDA for CCC operations and storage on VRAM
 * !!!!!!!!!! CURRENTLY SUPPORTS ONLY ONE DEVICE !!!!!!!!!!
**/
#define CERTFHE_USE_CUDA true

#if CERTFHE_USE_CUDA

#include <stdint.h>

/**
 * !!!!!!!!!! CURRENTLY SUPPORTS ONLY ONE DEVICE !!!!!!!!!!
 *
 * Class that provides (the complete) interface for any GPU operation or Video RAM manipulation
 * inside the certFHE namespace 
**/
class CUDA_interface {

public:

	/**
	 * NOTES: -> ALL functions declared below are HOST functions
	 *		  -> VRAM refers only to Video RAM (and not virtual memory)
	 *		  -> RAM refers to "normal" / "host" virtual memory or physical memory
	 *		  -> in this class (only), ciphertext generally refers to raw ciphertext array chunk,
	 *			 stored in either RAM or VRAM
	**/

	/**
	 * Function that initializez the CUDA internal interface
	 * Should be called (currently and only) from Library class
	**/
	static void init_CUDA_interface();

	/**
	 * allocate VRAM and copy values to it from RAM
	 * calls the method with the same name from CUDA_internal_interface with sync always true
	**/
	static uint64_t * RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool delete_original);

	/**
	 * allocate RAM and copy values to it from VRAM
	 * calls the method with the same name from CUDA_internal_interface with sync always true
	**/
	static uint64_t * VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool delete_original);

	/**
	 * allocate VRAM and copy values to it from VRAM
	 * calls the method with the same name from CUDA_internal_interface with sync always true
	**/
	static uint64_t * VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool delete_original);

	/**
	 * Wrapper around cudaFree, that deallocates memory from VRAM
	 * it ASSUMES the argument pointer refers to VRAM, without any kind of checks
	**/
	static void VRAM_delete_ciphertext(uint64_t * vram_address);

	static void VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
		uint64_t * result, const uint64_t * fst, const uint64_t * snd);

	static int VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask);
};

#endif
#endif
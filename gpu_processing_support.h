#ifndef GPU_PROCESSING_SUPPORT_H
#define GPU_PROCESSING_SUPPORT_H

/**
 * Macro to enable CUDA for CCC operations on ciphertext array chunks:
 * addition, multiplication, etc
**/
#define CERTFHE_USE_CUDA false

#if CERTFHE_USE_CUDA

#include <stdint.h>

// TODO: extern functions to be called from CCC class

// multiply, decrypt, permute

void CUDA_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
	uint64_t * result, const uint64_t * fst, const uint64_t * snd);

#endif
#endif

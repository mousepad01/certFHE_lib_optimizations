#include "gpu_processing_support.h"

#if CERTFHE_USE_CUDA

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "device_functions.h"

#include <iostream>

const int MAX_BLOCK_PER_GRID_COUNT = 65535;
const int MAX_THREADS_PER_BLOCK = 1024;

/**
 * Device function
 * Each thread operates on default length chunks
**/
__global__ void ctxt_multiply_kernel(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t snd_deflen_cnt,
	uint64_t * result, const uint64_t * fst, const uint64_t * snd) {

	int result_deflen_offset = blockDim.x * blockIdx.x + threadIdx.x;
	int result_deflen_stride = blockDim.x * gridDim.x;

	for (int result_deflen_i = result_deflen_offset; result_deflen_i < result_deflen_cnt; result_deflen_i += result_deflen_stride) {

		int fst_deflen_i = (result_deflen_i / snd_deflen_cnt) * deflen_to_uint64;
		int snd_deflen_i = (result_deflen_i % snd_deflen_cnt) * deflen_to_uint64;

		for (int i = 0; i < deflen_to_uint64; i++)
			result[i + result_deflen_i * deflen_to_uint64] = fst[i + fst_deflen_i] & snd[i + snd_deflen_i];
	}
}

__global__ void ctxt_decrypt_kernel(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask,
									int * decryption_result) {

	int to_decrypt_deflen_offset = blockDim.x * blockIdx.x + threadIdx.x;
	int to_decrypt_deflen_stride = blockDim.x * gridDim.x;

	int local_decryption_result = 1;

	for (int to_decrypt_deflen_i = to_decrypt_deflen_offset; to_decrypt_deflen_i < to_decrypt_deflen_cnt; to_decrypt_deflen_i += to_decrypt_deflen_stride) {

		for (int i = 0; i < deflen_to_uint64; i++)
			local_decryption_result &= ((to_decrypt[to_decrypt_deflen_i * deflen_to_uint64 + i] & sk_mask[i]) ^ sk_mask[i]) == (uint64_t)0;
		
		(void)atomicXor(decryption_result, local_decryption_result);
	}
}

/**
 * called from CCC class, linked with extern specifier
 * receives as argument the WHOLE ciphertexts
**/
__host__ void CUDA_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
	uint64_t * result, const uint64_t * fst, const uint64_t * snd) {

	uint64_t * VRAM_result;
	uint64_t * VRAM_fst;
	uint64_t * VRAM_snd;

	cudaMalloc(&VRAM_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));
	cudaMalloc(&VRAM_fst, (uint64_t)fst_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));
	cudaMalloc(&VRAM_snd, (uint64_t)snd_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));

	cudaMemcpy(VRAM_result, result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaMemcpy(VRAM_fst, fst, (uint64_t)fst_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaMemcpy(VRAM_snd, snd, (uint64_t)snd_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);

	int threads_per_block = result_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)result_deflen_cnt;

	int block_cnt = (int)(result_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (result_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_multiply_kernel <<< block_cnt, threads_per_block >>> (deflen_to_uint64, result_deflen_cnt, snd_deflen_cnt, VRAM_result, VRAM_fst, VRAM_snd);
	cudaDeviceSynchronize();

	cudaMemcpy(result, VRAM_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);

	cudaFree(VRAM_result);
	cudaFree(VRAM_fst);
	cudaFree(VRAM_snd);
}

__host__ int CUDA_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask) {

	uint64_t * VRAM_to_decrypt;
	uint64_t * VRAM_sk_mask;

	int * VRAM_decryption_result;

	cudaMalloc(&VRAM_to_decrypt, to_decrypt_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));
	cudaMalloc(&VRAM_sk_mask, deflen_to_uint64 * sizeof(uint64_t));

	cudaMalloc(&VRAM_decryption_result, sizeof(int));

	cudaMemcpy(VRAM_to_decrypt, to_decrypt, to_decrypt_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaMemcpy(VRAM_sk_mask, sk_mask, deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);

	int threads_per_block = to_decrypt_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)to_decrypt_deflen_cnt;

	int block_cnt = (int)(to_decrypt_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (to_decrypt_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_decrypt_kernel <<< block_cnt, threads_per_block >>> (deflen_to_uint64, to_decrypt_deflen_cnt, VRAM_to_decrypt, VRAM_sk_mask, VRAM_decryption_result);
	cudaDeviceSynchronize();

	int decryption_result;

	cudaMemcpy(&decryption_result, VRAM_decryption_result, sizeof(int), cudaMemcpyDeviceToHost);

	cudaFree(VRAM_to_decrypt);
	cudaFree(VRAM_sk_mask);
	cudaFree(VRAM_decryption_result);

	return decryption_result;
}

#endif
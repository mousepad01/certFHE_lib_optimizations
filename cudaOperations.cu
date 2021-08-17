#include "gpu_processing_support.h"

#if CERTFHE_USE_CUDA

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

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

	int threads_per_block = result_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : result_deflen_cnt;

	int block_cnt = result_deflen_cnt / MAX_THREADS_PER_BLOCK;
	if (result_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_multiply_kernel <<< 1024, 256 >>> (deflen_to_uint64, result_deflen_cnt, snd_deflen_cnt, VRAM_result, VRAM_fst, VRAM_snd);
	cudaDeviceSynchronize();

	cudaMemcpy(result, VRAM_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);

	cudaFree(VRAM_result);
	cudaFree(VRAM_fst);
	cudaFree(VRAM_snd);
}

#endif
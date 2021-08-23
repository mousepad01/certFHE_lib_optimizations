#include "CUDA_interface.h"

#if CERTFHE_USE_CUDA

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <iostream>

const int CUDA_interface::MAX_THREADS_PER_BLOCK = 256;

/****************** GPU KERNEL FUNCTIONS ******************/

/**
 * Device function
 * Each thread operates on default length chunks
**/
__global__ static void ctxt_multiply_kernel(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t snd_deflen_cnt,
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
 * Device function
 * Each thread operates on default length chunks
**/
__global__ static void ctxt_decrypt_kernel(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask,
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

/****************** CUDA INTERFACE METHODS ******************/

__host__ uint64_t * CUDA_interface::RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, uint64_t * vram_address) { 

	if (!vram_address)
		cudaMalloc(&vram_address, size_to_copy * sizeof(uint64_t));

	cudaMemcpy(vram_address, ram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaDeviceSynchronize();

	return vram_address;
}

__host__ uint64_t * CUDA_interface::VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, uint64_t * ram_address) {

	if (!ram_address)
		ram_address = new uint64_t[size_to_copy];

	cudaMemcpy(ram_address, vram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyDeviceToHost);
	cudaDeviceSynchronize();

	return ram_address;
}

__host__ uint64_t * CUDA_interface::VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, uint64_t * vram_new_address) {

	if (!vram_new_address)
		cudaMalloc(&vram_new_address, size_to_copy * sizeof(uint64_t));

	cudaMemcpy(vram_new_address, vram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyDeviceToDevice);
	cudaDeviceSynchronize();

	return vram_new_address;
}

__host__ void CUDA_interface::VRAM_delete(uint64_t * vram_address) { cudaFree(vram_address); }

__host__ uint64_t * CUDA_interface::VRAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		 const uint64_t * fst, const uint64_t * snd) {

	uint64_t result_deflen_cnt = fst_deflen_cnt * snd_deflen_cnt;

	uint64_t * vram_result;
	cudaMalloc(&vram_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));

	int threads_per_block = result_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)result_deflen_cnt;

	int block_cnt = (int)(result_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (result_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_multiply_kernel <<< block_cnt, threads_per_block >>> (deflen_to_uint64, result_deflen_cnt, snd_deflen_cnt, vram_result, fst, snd);
	cudaDeviceSynchronize();

	return vram_result;
}

__host__ uint64_t * CUDA_interface::RAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64,  uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * vram_fst = CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt  * deflen_to_uint64, 0);
	uint64_t * mul_result = CUDA_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, fst_deflen_cnt, snd_deflen_cnt, vram_fst, snd);

	cudaFree(vram_fst);

	return mul_result;
}

__host__ uint64_t * CUDA_interface::RAM_RAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * vram_fst = CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * deflen_to_uint64, 0);
	uint64_t * vram_snd = CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)snd, snd_deflen_cnt * deflen_to_uint64, 0);

	uint64_t * mul_result = CUDA_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, fst_deflen_cnt, snd_deflen_cnt, vram_fst, vram_snd);

	cudaFree(vram_fst);
	cudaFree(vram_snd);

	return mul_result;
}

__host__ uint64_t * CUDA_interface::VRAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, (fst_deflen_cnt + snd_deflen_cnt) * deflen_to_uint64 * sizeof(uint64_t));

	CUDA_interface::VRAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * deflen_to_uint64, add_result);
	CUDA_interface::VRAM_TO_VRAM_ciphertext_copy((uint64_t *)snd, snd_deflen_cnt * deflen_to_uint64, add_result + fst_deflen_cnt * deflen_to_uint64);

	return add_result;
}

__host__ uint64_t * CUDA_interface::RAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, (fst_deflen_cnt + snd_deflen_cnt) * deflen_to_uint64 * sizeof(uint64_t));

	CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * deflen_to_uint64, add_result);
	CUDA_interface::VRAM_TO_VRAM_ciphertext_copy((uint64_t *)snd, snd_deflen_cnt * deflen_to_uint64, add_result + fst_deflen_cnt * deflen_to_uint64);

	return add_result;
}

__host__ uint64_t * CUDA_interface::RAM_RAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, (fst_deflen_cnt + snd_deflen_cnt) * deflen_to_uint64 * sizeof(uint64_t));

	CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * deflen_to_uint64, add_result);
	CUDA_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)snd, snd_deflen_cnt * deflen_to_uint64, add_result + fst_deflen_cnt * deflen_to_uint64);

	return add_result;
}

__host__ int CUDA_interface::VRAM_ciphertext_decryption(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask) {

	int * vram_decryption_result;

	cudaMalloc(&vram_decryption_result, sizeof(int));
	cudaMemset(vram_decryption_result, 0, sizeof(int));

	cudaDeviceSynchronize();

	int threads_per_block = to_decrypt_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)to_decrypt_deflen_cnt;

	int block_cnt = (int)(to_decrypt_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (to_decrypt_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_decrypt_kernel <<< block_cnt, threads_per_block >>> (deflen_to_uint64, to_decrypt_deflen_cnt, to_decrypt, sk_mask, vram_decryption_result);
	cudaDeviceSynchronize();

	int decryption_result;

	cudaMemcpy(&decryption_result, vram_decryption_result, sizeof(int), cudaMemcpyDeviceToHost);
	cudaDeviceSynchronize();

	cudaFree(vram_decryption_result);

	return decryption_result;
}

#endif
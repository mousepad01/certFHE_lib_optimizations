#include "CUDA_interface.h"

#if CERTFHE_USE_CUDA

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <iostream>

class CUDA_internal_interface {

	static const int MAX_BLOCK_PER_GRID_COUNT;
	static const int MAX_THREADS_PER_BLOCK;

	/**
	 * Properties of the device in cause - CURRENTLY SUPPORTS ONLY ONE DEVICE
	**/
	static cudaDeviceProp device_props;

	/**
	 * Streams for (more) concurrent processing
	**/
	static cudaStream_t * streams;

	/**
	 * Number of streams used
	 * Currently initialized with device_props.asyncEngineCount
	**/
	static int streams_cnt;

	static void init();

	/**
	 * allocate VRAM and copy values to it from RAM
	 * this function ASSUMES the pointer from which to copy is on RAM
	 * returns VRAM address inside uint64_t value
	 * delete_original -> deallocate original buffer
	 * sync -> wait for the operations to be done before exit or not
	 * if sync is TRUE, the HOST memory is left PINNED
	 *
	 * NOTE: this function does NOT check vram usage upper limit,
	 * checks should be done by the caller
	**/
	static uint64_t * RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool sync);

	/**
	 * allocate RAM and copy values to it from VRAM
	 * this function ASSUMES the pointer from which to copy is on VRAM
	 * returns RAM address inside uint64_t value
	 * delete_original -> deallocate original buffer
	 * sync -> wait for the operations to be done before exit or not
	 * if sync is TRUE, the HOST memory is left PINNED
	**/
	static uint64_t * VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync);

	/**
	 * allocate VRAM and copy values to it from VRAM
	 * this function ASSUMES the pointer from which to copy is on VRAM
	 * returns VRAM address inside uint64_t value
	 * delete_original -> deallocate original buffer
	 * sync -> wait for the operations to be done before exit or not
	 *
	 * NOTE: this function does NOT check vram usage upper limit,
	 * checks should be done by the caller
	**/
	static uint64_t * VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync);

	static void VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
		uint64_t * result, const uint64_t * fst, const uint64_t * snd);

	static int VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask);

	/**
	 * Wrapper around cudaFree, that deallocates memory from VRAM
	 * it ASSUMES the argument pointer refers to VRAM, without any kind of checks
	**/
	static void VRAM_delete_ciphertext(uint64_t * vram_address);

	friend class CUDA_interface;
};

const int CUDA_internal_interface::MAX_BLOCK_PER_GRID_COUNT = 65535;
const int CUDA_internal_interface::MAX_THREADS_PER_BLOCK = 1024;

cudaDeviceProp CUDA_internal_interface::device_props;
cudaStream_t * CUDA_internal_interface::streams;

int CUDA_internal_interface::streams_cnt = 1;

/****************** CUDA INTERFACE METHODS ******************/

__host__ void CUDA_interface::init_CUDA_interface() {
	CUDA_internal_interface::init();
}

__host__ uint64_t * CUDA_interface::RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool delete_original) { 

	uint64_t * to_return = CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(ram_address, size_to_copy, true);

	if (delete_original)
		delete[] ram_address;
}

__host__ uint64_t * CUDA_interface::VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool delete_original) {

	uint64_t * to_return = CUDA_internal_interface::VRAM_TO_RAM_ciphertext_copy(vram_address, size_to_copy, true);

	if (delete_original)
		cudaFree(vram_address);

	return to_return;
}

__host__ uint64_t * CUDA_interface::VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool delete_original) {

	uint64_t * to_return = CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(vram_address, size_to_copy, true);

	if (delete_original)
		cudaFree(vram_address);

	return to_return;
}

__host__ void CUDA_interface::VRAM_delete_ciphertext(uint64_t * vram_address) { CUDA_internal_interface::VRAM_delete_ciphertext(vram_address); }

__host__ void CUDA_interface::VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
	uint64_t * result, const uint64_t * fst, const uint64_t * snd) {

	return CUDA_internal_interface::VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, result_deflen_cnt, fst_deflen_cnt, snd_deflen_cnt, result, fst, snd);
}

__host__ int CUDA_interface::VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask) {
	return CUDA_internal_interface::VRAM_ciphertext_decrpytion(deflen_to_uint64, to_decrypt_deflen_cnt, to_decrypt, sk_mask);
}


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


/****************** CUDA INTERNAL INTERFACE METHODS ******************/

__host__ void CUDA_internal_interface::init() {

	int device;

	cudaGetDevice(&device);
	cudaGetDeviceProperties(&device_props, device);

	streams_cnt = device_props.asyncEngineCount;
	streams = new cudaStream_t[streams_cnt];

	for (int i = 0; i < streams_cnt; i++)
		cudaStreamCreate(streams + i);
}

__host__ void CUDA_internal_interface::VRAM_delete_ciphertext(uint64_t * vram_address) { cudaFree(vram_address); }

__host__ uint64_t * CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool sync) {

	uint64_t * vram_address;
	cudaMalloc(&vram_address, size_to_copy);

	cudaHostRegister(ram_address, size_to_copy, 0);

	for (int i = 0; i < streams_cnt; i++) 
		cudaMemcpyAsync(vram_address, ram_address, size_to_copy, cudaMemcpyHostToDevice, streams[i]);
	
	if (sync) {

		cudaDeviceSynchronize();
		cudaHostUnregister(ram_address);
	}

	return vram_address;
}

__host__ uint64_t * CUDA_internal_interface::VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync) { 

	uint64_t * ram_address = new uint64_t[size_to_copy];
	cudaHostRegister(ram_address, size_to_copy, 0);

	for (int i = 0; i < streams_cnt; i++)
		cudaMemcpyAsync(ram_address, vram_address, size_to_copy, cudaMemcpyDeviceToHost, streams[i]);

	if (sync) {

		cudaDeviceSynchronize();
		cudaHostUnregister(ram_address);
	}

	return ram_address;
}

__host__ uint64_t * CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync) { 
	
	uint64_t * vram_new_address;
	cudaMalloc(&vram_new_address, size_to_copy);

	for (int i = 0; i < streams_cnt; i++)
		cudaMemcpyAsync(vram_new_address, vram_address, size_to_copy, cudaMemcpyDeviceToDevice, streams[i]);

	if (sync) 
		cudaDeviceSynchronize();

	return vram_new_address;
}

// TODO
__host__ void CUDA_internal_interface::VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t result_deflen_cnt, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
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

	int threads_per_block = result_deflen_cnt > CUDA_internal_interface::MAX_THREADS_PER_BLOCK ? CUDA_internal_interface::MAX_THREADS_PER_BLOCK : (int)result_deflen_cnt;

	int block_cnt = (int)(result_deflen_cnt / CUDA_internal_interface::MAX_THREADS_PER_BLOCK);
	if (result_deflen_cnt % CUDA_internal_interface::MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_multiply_kernel << < block_cnt, threads_per_block >> > (deflen_to_uint64, result_deflen_cnt, snd_deflen_cnt, VRAM_result, VRAM_fst, VRAM_snd);
	cudaDeviceSynchronize();

	cudaMemcpy(result, VRAM_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyDeviceToHost);

	cudaFree(VRAM_result);
	cudaFree(VRAM_fst);
	cudaFree(VRAM_snd);
}

// TODO
__host__ int CUDA_internal_interface::VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask) {

	uint64_t * VRAM_to_decrypt;
	uint64_t * VRAM_sk_mask;

	int * VRAM_decryption_result;

	cudaMalloc(&VRAM_to_decrypt, to_decrypt_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));
	cudaMalloc(&VRAM_sk_mask, deflen_to_uint64 * sizeof(uint64_t));

	cudaMalloc(&VRAM_decryption_result, sizeof(int));

	cudaMemcpy(VRAM_to_decrypt, to_decrypt, to_decrypt_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);
	cudaMemcpy(VRAM_sk_mask, sk_mask, deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice);

	int threads_per_block = to_decrypt_deflen_cnt > CUDA_internal_interface:: MAX_THREADS_PER_BLOCK ? CUDA_internal_interface::MAX_THREADS_PER_BLOCK : (int)to_decrypt_deflen_cnt;

	int block_cnt = (int)(to_decrypt_deflen_cnt / CUDA_internal_interface::MAX_THREADS_PER_BLOCK);
	if (to_decrypt_deflen_cnt % CUDA_internal_interface::MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	ctxt_decrypt_kernel << < block_cnt, threads_per_block >> > (deflen_to_uint64, to_decrypt_deflen_cnt, VRAM_to_decrypt, VRAM_sk_mask, VRAM_decryption_result);
	cudaDeviceSynchronize();

	int decryption_result;

	cudaMemcpy(&decryption_result, VRAM_decryption_result, sizeof(int), cudaMemcpyDeviceToHost);

	cudaFree(VRAM_to_decrypt);
	cudaFree(VRAM_sk_mask);
	cudaFree(VRAM_decryption_result);

	return decryption_result;
}

#endif
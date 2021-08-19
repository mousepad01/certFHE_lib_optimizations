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
	 * The last stream should be used for auxiliary small copies, 
	 * to make sure every time there is a stream available for small copies, 
	 * and that it that does not need to be waited for long
	**/
	static cudaStream_t * streams;

	/**
	 * Number of streams used
	 * Currently initialized with device_props.asyncEngineCount + 1
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

	static uint64_t * VRAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
															 const uint64_t * fst, const uint64_t * snd);

	static int VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask);

	friend class CUDA_interface;
};

const int CUDA_internal_interface::MAX_BLOCK_PER_GRID_COUNT = 65535;
const int CUDA_internal_interface::MAX_THREADS_PER_BLOCK = 1024;

cudaDeviceProp CUDA_internal_interface::device_props;
cudaStream_t * CUDA_internal_interface::streams;

int CUDA_internal_interface::streams_cnt = 2;

/****************** CUDA INTERFACE METHODS ******************/

__host__ void CUDA_interface::init_CUDA_interface() {
	CUDA_internal_interface::init();
}

__host__ uint64_t * CUDA_interface::RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool delete_original) { 

	uint64_t * to_return = CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(ram_address, size_to_copy, true);

	if (delete_original)
		delete[] ram_address;

	return to_return;
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

__host__ void CUDA_interface::VRAM_delete_ciphertext(uint64_t * vram_address) { cudaFree(vram_address); }

__host__ uint64_t * CUDA_interface::VRAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		 const uint64_t * fst, const uint64_t * snd) {

	return CUDA_internal_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, fst_deflen_cnt, snd_deflen_cnt, fst, snd);
}

__host__ uint64_t * CUDA_interface::RAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64,  uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * vram_fst = CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * sizeof(uint64_t), true);
	uint64_t * mul_result = CUDA_internal_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, fst_deflen_cnt, snd_deflen_cnt, vram_fst, snd);

	cudaFree(vram_fst);

	return mul_result;
}

__host__ uint64_t * CUDA_interface::RAM_RAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * vram_fst = CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)fst, fst_deflen_cnt * sizeof(uint64_t), true);
	uint64_t * vram_snd = CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy((uint64_t *)snd, snd_deflen_cnt * sizeof(uint64_t), true);

	uint64_t * mul_result = CUDA_internal_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_uint64, fst_deflen_cnt, snd_deflen_cnt, vram_fst, snd);

	cudaFree(vram_fst);
	cudaFree(vram_snd);

	return mul_result;
}

__host__ uint64_t * CUDA_interface::VRAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, fst_deflen_cnt + snd_deflen_cnt);

	CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(add_result, fst_deflen_cnt, false);
	CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(add_result + fst_deflen_cnt, snd_deflen_cnt, false);

	for (int i = 0; i < CUDA_internal_interface::streams_cnt; i++)
		cudaStreamSynchronize(CUDA_internal_interface::streams[i]);

	return add_result;
}

__host__ uint64_t * CUDA_interface::RAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, fst_deflen_cnt + snd_deflen_cnt);

	CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(add_result, fst_deflen_cnt, false);
	CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(add_result + fst_deflen_cnt, snd_deflen_cnt, false);

	for (int i = 0; i < CUDA_internal_interface::streams_cnt; i++)
		cudaStreamSynchronize(CUDA_internal_interface::streams[i]);

	return add_result;
}

__host__ uint64_t * CUDA_interface::RAM_RAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																		const uint64_t * fst, const uint64_t * snd) {

	uint64_t * add_result;
	cudaMalloc(&add_result, fst_deflen_cnt + snd_deflen_cnt);

	CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(add_result, fst_deflen_cnt, false);
	CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(add_result + fst_deflen_cnt, snd_deflen_cnt, false);

	for (int i = 0; i < CUDA_internal_interface::streams_cnt; i++)
		cudaStreamSynchronize(CUDA_internal_interface::streams[i]);

	return add_result;
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
	streams = new cudaStream_t[streams_cnt + 1];

	for (int i = 0; i < streams_cnt; i++)
		cudaStreamCreate(streams + i);
}

__host__ uint64_t * CUDA_internal_interface::RAM_TO_VRAM_ciphertext_copy(uint64_t * ram_address, uint64_t size_to_copy, bool sync) {

	uint64_t * vram_address;
	cudaMalloc(&vram_address, size_to_copy * sizeof(uint64_t));

	cudaHostRegister(ram_address, size_to_copy * sizeof(uint64_t), 0);

	if (size_to_copy < streams_cnt) {

		cudaMemcpyAsync(vram_address, ram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyHostToDevice, streams[streams_cnt]); // the "small copies" stream used

		if (sync) {

			cudaStreamSynchronize(streams[streams_cnt]);
			cudaHostUnregister(ram_address);
		}
	}
	else {

		/**
		 * streams_cnt - 1 (non default) streams will copy the same quantity
		 * the last (non default) stream will also copy the remaining quantity
		**/

		size_t offset = 0;
		size_t qty_per_stream = size_to_copy / streams_cnt;
		size_t remainder_qty = size_to_copy % streams_cnt;

		for (int i = 0; i < streams_cnt - 1; i++) {

			cudaMemcpyAsync(vram_address + offset, ram_address + offset, qty_per_stream * sizeof(uint64_t), cudaMemcpyHostToDevice, streams[i]);
			offset += qty_per_stream * sizeof(uint64_t);
		}
		cudaMemcpyAsync(vram_address + offset, ram_address + offset, (remainder_qty + qty_per_stream) * sizeof(uint64_t), cudaMemcpyHostToDevice, streams[streams_cnt - 1]);

		if (sync) {

			for (int i = 0; i < streams_cnt; i++)
				cudaStreamSynchronize(streams[i]);

			cudaHostUnregister(ram_address);
		}	
	}

	return vram_address;
}

__host__ uint64_t * CUDA_internal_interface::VRAM_TO_RAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync) { 

	uint64_t * ram_address = new uint64_t[size_to_copy];
	cudaHostRegister(ram_address, size_to_copy * sizeof(uint64_t), 0);

	if (size_to_copy < streams_cnt) {

		cudaMemcpyAsync(ram_address, vram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyDeviceToHost, streams[streams_cnt]); // NOT the default stream, but the first created

		if (sync) {

			cudaStreamSynchronize(streams[streams_cnt]);
			cudaHostUnregister(ram_address);
		}
	}
	else {

		/**
		 * streams_cnt - 1 (non default) streams will copy the same quantity
		 * the last (non default) stream will also copy the remaining quantity
		**/

		size_t offset = 0;
		size_t qty_per_stream = size_to_copy / streams_cnt;
		size_t remainder_qty = size_to_copy % streams_cnt;

		for (int i = 0; i < streams_cnt - 1; i++) {

			cudaMemcpyAsync(ram_address + offset, vram_address + offset, qty_per_stream * sizeof(uint64_t), cudaMemcpyDeviceToHost, streams[i]);
			offset += qty_per_stream * sizeof(uint64_t);
		}
		cudaMemcpyAsync(ram_address + offset, vram_address + offset, (remainder_qty + qty_per_stream) * sizeof(uint64_t), cudaMemcpyDeviceToHost, streams[streams_cnt - 1]);

		if (sync) {

			for (int i = 0; i < streams_cnt; i++)
				cudaStreamSynchronize(streams[i]);

			cudaHostUnregister(ram_address);
		}
	}

	return ram_address;
}

__host__ uint64_t * CUDA_internal_interface::VRAM_TO_VRAM_ciphertext_copy(uint64_t * vram_address, uint64_t size_to_copy, bool sync) { 
	
	uint64_t * vram_new_address;
	cudaMalloc(&vram_new_address, size_to_copy * sizeof(uint64_t));

	if (size_to_copy < streams_cnt) {
	
		cudaMemcpyAsync(vram_new_address, vram_address, size_to_copy * sizeof(uint64_t), cudaMemcpyDeviceToDevice, streams[streams_cnt]); // NOT the default stream, but the first created

		if (sync)
			cudaStreamSynchronize(streams[streams_cnt]);
	}
	else {

		/**
		 * streams_cnt - 1 (non default) streams will copy the same quantity
		 * the last (non default) stream will also copy the remaining quantity
		**/

		size_t offset = 0;
		size_t qty_per_stream = size_to_copy / streams_cnt;
		size_t remainder_qty = size_to_copy % streams_cnt;

		for (int i = 0; i < streams_cnt - 1; i++) {

			cudaMemcpyAsync(vram_new_address + offset, vram_address + offset, qty_per_stream * sizeof(uint64_t), cudaMemcpyDeviceToDevice, streams[i]);
			offset += qty_per_stream * sizeof(uint64_t);
		}
		cudaMemcpyAsync(vram_new_address + offset, vram_address + offset, (remainder_qty + qty_per_stream) * sizeof(uint64_t), cudaMemcpyDeviceToDevice, streams[streams_cnt - 1]);

		if (sync)
			for (int i = 0; i < streams_cnt; i++)
				cudaStreamSynchronize(streams[i]);
	}

	return vram_new_address;
}

__host__ uint64_t * CUDA_internal_interface::VRAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
																					const uint64_t * fst, const uint64_t * snd) {

	uint64_t result_deflen_cnt = fst_deflen_cnt * snd_deflen_cnt;

	uint64_t * vram_result;
	cudaMalloc(&vram_result, (uint64_t)result_deflen_cnt * deflen_to_uint64 * sizeof(uint64_t));

	/**
	 * There is no copying to be done, everything is in VRAM already
	 * But the kernels will still be launched on multiple streams
	 * (to avoid running on the default stream ???)
	**/

	int threads_per_block = result_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)result_deflen_cnt;

	int block_cnt = (int)(result_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (result_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	if (block_cnt < streams_cnt) {

		ctxt_multiply_kernel <<< block_cnt, threads_per_block, 0, streams[streams_cnt] >>> (deflen_to_uint64, result_deflen_cnt, snd_deflen_cnt, vram_result, fst, snd);
		cudaStreamSynchronize(streams[streams_cnt]);
	}
	else {

		size_t deflen_offset = 0;
		size_t block_qty_per_stream = block_cnt / streams_cnt;
		size_t remainder = block_cnt % streams_cnt;

		for (int i = 0; i < streams_cnt - 1; i++) {

			ctxt_multiply_kernel <<< block_cnt, threads_per_block, 0, streams[i] >>> (deflen_to_uint64, block_qty_per_stream * threads_per_block, snd_deflen_cnt,
																						vram_result + deflen_offset * deflen_to_uint64, fst, snd);
			deflen_offset += block_qty_per_stream * threads_per_block;
		}
		ctxt_multiply_kernel <<< block_cnt, threads_per_block, 0, streams[streams_cnt - 1] >>> (deflen_to_uint64, result_deflen_cnt - deflen_offset, snd_deflen_cnt,
																								vram_result + deflen_offset * deflen_to_uint64, fst, snd);

		for (int i = 0; i < streams_cnt; i++)
			cudaStreamSynchronize(streams[i]);
	}

	return vram_result;
}

__host__ int CUDA_internal_interface::VRAM_ciphertext_decrpytion(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask) {

	uint64_t * vram_sk_mask;
	int * vram_decryption_result;

	cudaMalloc(&vram_sk_mask, deflen_to_uint64 * sizeof(uint64_t));
	cudaMalloc(&vram_decryption_result, sizeof(int));

	cudaMemset(vram_decryption_result, 0, sizeof(int));
	cudaMemcpyAsync(vram_sk_mask, sk_mask, deflen_to_uint64 * sizeof(uint64_t), cudaMemcpyHostToDevice, streams[streams_cnt]);

	cudaStreamSynchronize(streams[streams_cnt]);

	int threads_per_block = to_decrypt_deflen_cnt > MAX_THREADS_PER_BLOCK ? MAX_THREADS_PER_BLOCK : (int)to_decrypt_deflen_cnt;

	int block_cnt = (int)(to_decrypt_deflen_cnt / MAX_THREADS_PER_BLOCK);
	if (to_decrypt_deflen_cnt % MAX_THREADS_PER_BLOCK)
		block_cnt += 1;

	//---

	if (block_cnt < streams_cnt) {

		ctxt_decrypt_kernel <<< block_cnt, threads_per_block, 0, streams[streams_cnt] >>> (deflen_to_uint64, to_decrypt_deflen_cnt, to_decrypt, vram_sk_mask, vram_decryption_result);
		cudaStreamSynchronize(streams[streams_cnt]);
	}
	else {

		size_t deflen_offset = 0;
		size_t block_qty_per_stream = block_cnt / streams_cnt;
		size_t remainder = block_cnt % streams_cnt;

		for (int i = 0; i < streams_cnt - 1; i++) {

			ctxt_decrypt_kernel <<< block_cnt, threads_per_block, 0, streams[i] >>> (deflen_to_uint64, block_qty_per_stream * threads_per_block, to_decrypt + deflen_offset * deflen_to_uint64, vram_sk_mask, vram_decryption_result);
			deflen_offset += block_qty_per_stream * threads_per_block;
		}
		ctxt_decrypt_kernel <<< block_cnt, threads_per_block, 0, streams[streams_cnt - 1] >>> (deflen_to_uint64, to_decrypt_deflen_cnt - deflen_offset, to_decrypt + deflen_offset * deflen_to_uint64, vram_sk_mask, vram_decryption_result);

		for (int i = 0; i < streams_cnt; i++)
			cudaStreamSynchronize(streams[i]);
	}

	//---

	int decryption_result;
	cudaMemcpyAsync(&decryption_result, vram_decryption_result, sizeof(int), cudaMemcpyDeviceToHost, streams[streams_cnt]);

	cudaStreamSynchronize(streams[streams_cnt]);

	cudaFree(vram_sk_mask);
	cudaFree(vram_decryption_result);

	return decryption_result;
}

#endif
#include "CCC.h"

namespace certFHE {

	CCC::CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt) : CNODE(context) {

		if (deflen_cnt > OPValues::max_ccc_deflen_size) {

			std::cout << "ERROR creating CCC node: deflen " << deflen_cnt
				<< " exceeds limit " << OPValues::max_ccc_deflen_size << "\n";

			throw new std::invalid_argument("ERROR creating CCC node: deflen exceeds limit");
		}
		else {

			this->deflen_count = deflen_cnt;
			this->ctxt = ctxt;
		}
			
		/*uint64_t fingerprint = 0;
		uint64_t deflen_u64_cnt = context->getDefaultN();

		uint64_t * current = ctxt;

		for (uint64_t i = 0; i < deflen_cnt; i++) {

			uint64_t hash_buffer[4] = {0, 0, 0, 0};
			SHA256((unsigned char *)current, sizeof(uint64_t) * deflen_u64_cnt, (unsigned char *)hash_buffer);

			fingerprint += hash_buffer[0];  // overflow does not matter, it is considered MOD 2^64

			current += deflen_u64_cnt;
		}*/
	}

	CCC::CCC(const CCC & other) : CNODE(other) {

		if (other.ctxt != 0 && other.deflen_count > 0) {

			uint64_t u64_length = this->deflen_count * this->context->getDefaultN();
			this->ctxt = new uint64_t[u64_length];

			for (int i = 0; i < u64_length; i++)
				this->ctxt[i] = other.ctxt[i];
		}
		else
			this->ctxt = 0;
	}

	CCC::CCC(const CCC && other) : CNODE(other) {

		this->deflen_count = other.deflen_count;
		this->ctxt = other.ctxt;
	}

	CNODE * CCC::make_copy() {

		return new CCC(*this);
	}

	CCC * CCC::add(CCC * fst, CCC * snd) {

		//TODO: addition as in original Ciphertext.cpp

	}
}

/*
void SHA256(unsigned char * msg, size_t msg_byte_size, unsigned char * digest_buffer) {

	size_t msg_bit_size = 8 * msg_byte_size;

	size_t msg_padded_bit_size = 512;

	while (msg_padded_bit_size < msg_bit_size + 1 + 64) /// sau msg_bit_size + 8 + 64, datorita lungimii multiplu de 8 de start
		msg_padded_bit_size += 512;

	unsigned char * padded_msg = new unsigned char[msg_padded_bit_size / 8];

	/// padding

	size_t pos;

	for (pos = 0; pos < msg_byte_size; pos++)
		padded_msg[pos] = msg[pos];

	padded_msg[pos] = (unsigned char)(1 << 7);
	pos++;

	size_t msg_padded_byte_size = msg_padded_bit_size / 8;

	for (; pos < msg_padded_byte_size - 8; pos++)
		padded_msg[pos] = 0;

	for (; pos < msg_padded_byte_size - 4; pos++)
		padded_msg[pos] = 0;

	size_t aux_m_bit_size = msg_bit_size;

	for (int i = 3; i >= 0; i--) {

		padded_msg[pos + i] = aux_m_bit_size & 255;
		aux_m_bit_size >>= 8;
	}

	uint32_t h[8];
	h[0] = 0x6a09e667;
	h[1] = 0xbb67ae85;
	h[2] = 0x3c6ef372;
	h[3] = 0xa54ff53a;
	h[4] = 0x510e527f;
	h[5] = 0x9b05688c;
	h[6] = 0x1f83d9ab;
	h[7] = 0x5be0cd19;

	uint32_t k[64] =
	{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	size_t chunk_cnt = msg_padded_bit_size / 512;

	for (uint32_t chunk = 0; chunk < chunk_cnt; chunk++) {

		/// w array processing

		size_t chunk_pos = 0;

		uint32_t * w = new uint32_t[64];

		size_t w_pos = 0;

		for (; w_pos < 16; w_pos++) {

			w[w_pos] = (uint32_t)(MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos] << 24)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 1] << 16)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 2] << 8)) |
				MODPOW32((uint32_t)(padded_msg[chunk * 64 + chunk_pos + 3])));

			chunk_pos += 4;
		}

		for (; w_pos < 64; w_pos++) {

			uint32_t s0 = ROTR32(w[w_pos - 15], 7) ^ ROTR32(w[w_pos - 15], 18) ^ MODPOW32(w[w_pos - 15] >> 3);
			uint32_t s1 = ROTR32(w[w_pos - 2], 17) ^ ROTR32(w[w_pos - 2], 19) ^ MODPOW32(w[w_pos - 2] >> 10);

			w[w_pos] = MODPOW32(w[w_pos - 16] + s0 + w[w_pos - 7] + s1);

		}

		/// compress

		uint32_t a = h[0];
		uint32_t b = h[1];
		uint32_t c = h[2];
		uint32_t d = h[3];
		uint32_t e = h[4];
		uint32_t f = h[5];
		uint32_t g = h[6];
		uint32_t hh = h[7];

		for (w_pos = 0; w_pos < 64; w_pos++) {

			uint32_t s1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = MODPOW32(hh + s1 + ch + k[w_pos] + w[w_pos]);
			uint32_t s0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = MODPOW32(s0 + maj);

			hh = g;
			g = f;
			f = e;
			e = MODPOW32(d + temp1);
			d = c;
			c = b;
			b = a;
			a = MODPOW32(temp1 + temp2);

		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += hh;

		delete[] w;
	}

	for (pos = 0; pos < 8; pos++) {

		for (int i = 3; i >= 0; i--) {

			digest_buffer[pos * 4 + i] = h[pos] & 255;
			h[pos] >>= 8;
		}
	}

	delete[] padded_msg;
}*/



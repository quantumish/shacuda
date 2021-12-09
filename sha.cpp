#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <array>
#include <bit>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <ios>
#include <string>
#include <vector>
#include <fmt/format.h>

using Hash = std::array<uint8_t, 256>;

template<typename T>
void dump_array(T* bytes, size_t len) {
    for (size_t i = 1; i < len+1; i++) {
	auto str = "{:0"+std::to_string(sizeof(T)*8)+"b} ";
	std::cout << fmt::vformat(str, fmt::make_format_args(*(bytes+i-1)));
	if (i % (64/(sizeof(T)*8)) == 0) std::cout << '\n';
    }
    std::cout << '\n';
}



// Blatantly adapted from https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
void sha_256(char* bytes, uint32_t len) {
    size_t content_len = len + 1 + 4;
    size_t buffer_len = 0;
    while (true) {
	buffer_len += 64;
	if (buffer_len > content_len) break;
    }
    uint8_t* buffer = (uint8_t*)calloc(buffer_len, sizeof(uint8_t));
    memcpy(buffer, bytes, len);
    std::cout << len << " " << buffer_len << "\n";
    buffer[len] = 0b10000000;
    
    *((uint32_t*)buffer + buffer_len/4 - 1) = __builtin_bswap32(len);

//    *((0x0B000000_t*)buffer + buffer_len/4 - 1) = be32(len);
    for (int i = 0; i < 4; i++) {
	buffer[buffer_len-i] = std::rotr(buffer[buffer_len-i], 5);
    }

    // auto c_buffer = const_cast<const uint8_t*>(buffer);
    dump_array<uint8_t>(buffer, buffer_len);
    //std::cout << buffer_len << '\n';
    uint32_t h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    const uint64_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };


    for (int i = 0; i < buffer_len; i += 64) {
	size_t wlen = 64;
	uint32_t* w = (uint32_t*)calloc(wlen, sizeof(uint32_t));
	memcpy(w, buffer+i, 64);
	for (int i = 0; i < wlen; i++) {
	    w[i] = __builtin_bswap32(w[i]); 
	}

	// Likely not the problem - doesn't vary across chunks 
	for (int i = 16; i < wlen; i++) {
	    uint32_t s0 = (std::rotr(w[i-15], 7) ^ std::rotr(w[i-15], 18) ^ (w[i-15] >> 3));
	    uint32_t s1 = (std::rotr(w[i-2], 17) ^ std::rotr(w[i-2], 19)  ^ (w[i-2] >> 10));
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	dump_array<uint32_t>(w, wlen);

	// Cast to constant so nothing can frick with it - just for paranoia's sake.
	auto c_w = const_cast<const uint32_t*>(w);

	uint32_t a[8];
	memcpy(a, h, sizeof(uint32_t)*8);
	for (int i = 0; i < 64; i++) {
	    uint32_t s1 = (std::rotr(a[4], 6) ^ std::rotr(a[4], 11) ^ std::rotr(a[4], 25));
	    uint32_t ch = (a[4] & a[5]) ^ ((~a[4]) & a[6]);
	    uint32_t temp1 = a[7] + s1 + ch + k[i] + c_w[i];
	    uint32_t s0 = (std::rotr(a[0], 2) ^ std::rotr(a[0], 13) ^ std::rotr(a[0], 22));
	    uint32_t maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
	    uint32_t temp2 = s0 + maj;
	    a[7] = a[6];
	    a[6] = a[5];
	    a[5] = a[4];
	    a[4] = a[3] + temp1;
	    a[3] = a[2];
	    a[2] = a[1];
	    a[1] = a[0];
	    a[0] = temp1 + temp2;
	}
	for (int i = 0; i < 8; i++) h[i] = h[i] + a[i];
	free(w);
    }

    char out[32] = {0};
    memcpy(out, h, sizeof(uint32_t)*8);
    
    for (int i = 0; i < 8; i++) {
	*(((uint32_t*)out)+i) = __builtin_bswap32(*(((uint32_t*)out)+i));
    }
    
    for (int i = 0; i < 32; i++) {
	std::cout << fmt::format("{:02x}", (uint8_t)out[i]);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
	std::cout << "usage: ./sha <path>" << "\n";
	exit(0);
    }
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    char* buf = (char*)malloc(size);
    file.read(buf, size);
    sha_256(buf, size);
    std::cout << "  " << argv[1] << "\n";
}

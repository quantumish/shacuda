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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <fmt/format.h>
#include <cuda_runtime_api.h>
#include <cuda.h>

#define rotr(a,b) (((a) >> (b)) | ((a) << (32-(b))))

template<typename T>
void dump_array(T* bytes, size_t len) {
    for (size_t i = 1; i < len+1; i++) {
	auto str = "{:0"+std::to_string(sizeof(T)*8)+"b} ";
	std::cout << fmt::vformat(str, fmt::make_format_args(*(bytes+i-1)));
	if (i % (64/(sizeof(T)*8)) == 0) std::cout << '\n';
    }
    std::cout << '\n';
}

using Hash = std::unique_ptr<uint8_t[]>;

struct sha_ctx {
    // std::unique_ptr<uint8_t[]> buffer;
    uint32_t* hash;
    uint64_t len;
    
    sha_ctx(uint64_t len);
    void process(uint8_t* bytes);
    void finalize(uint8_t* bytes);
    void dump_hash();
};

sha_ctx::sha_ctx(uint64_t length) :len(length) {
    cudaMallocManaged((void**)&hash, 8*sizeof(uint32_t));    
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;
}

#define NUM_CHUNKS 8192

__global__
void process(uint8_t* bytes, uint32_t* hash) {
    for (int i = 0; i < NUM_CHUNKS; i += 1) {
	uint64_t k[64] = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	
	uint32_t w[64] = {0};
	memcpy(w, bytes+(i*64), 64);
	for (int i = 0; i < 16; i++) w[i] = __builtin_bswap32(w[i]);

	for (int i = 16; i < 64; i++) {
	    uint32_t s0 = (rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3));
	    uint32_t s1 = (rotr(w[i-2], 17) ^ rotr(w[i-2], 19)  ^ (w[i-2] >> 10));
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	uint32_t a[8] = {0};
	memcpy(a, hash, sizeof(uint32_t)*8);

	for (int i = 0; i < 64; i++) {
	    uint32_t s1 = (rotr(a[4], 6) ^ rotr(a[4], 11) ^ rotr(a[4], 25));
	    uint32_t ch = (a[4] & a[5]) ^ ((~a[4]) & a[6]);
	    uint32_t temp1 = a[7] + s1 + ch + k[i] + w[i];
	    uint32_t s0 = (rotr(a[0], 2) ^ rotr(a[0], 13) ^ rotr(a[0], 22));
	    uint32_t maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
	    uint32_t temp2 = s0 + maj;
	    for (int i = 7; i > 0; i--) a[i] = a[i-1];
	    a[4] += temp1;
	    a[0] = temp1 + temp2;
	}	
	for (int i = 0; i < 8; i++) hash[i] = hash[i] + a[i];
    }
}


void std_read(const char* path) {
    sha_ctx sha(100);    
    constexpr size_t BUFFER_SIZE = 512 * 1024;
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    // fcntl(fd, F_RDADVISE);
    uint8_t* buf;
    cudaMallocManaged((void**)&buf, BUFFER_SIZE);
    while(size_t bytes_read = read(fd, buf, BUFFER_SIZE))
    {
        if(bytes_read == (size_t)-1) {
            printf("bytes_read == (size_t)-1\n");
            exit(1);
        }
        if (!bytes_read) break;
	process<<<1, 1>>>(buf, sha.hash);
    }
}

int main(int argc, char** argv) {
    // if (argc != 2) {
    // 	std::cout << "usage: ./sha <path>" << "\n";
    // 	exit(0);
    // }
    std_read("/home/quantumish/events.gif");
    // std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    // std::streamsize size = file.tellg();
    // file.seekg(0, std::ios::beg);
    // char* buf = (char*)malloc(size);
    // file.read(buf, size);
    // auto hash = sha_256(buf, size);
    // for (int i = 0; i < 32; i++) {
    // 	std::cout << fmt::format("{:02x}", static_cast<uint8_t>(hash[i]));
    // }
    // std::cout << "  " << argv[1] << "\n";
}

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
#include <stdio.h>

#define rotr(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// Hacky %b for printf from stackoverflow
//https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
//https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format/25108449#25108449
#define PRINTF_BINARY_SEPARATOR ""
#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c%c%c"
#define PRINTF_BYTE_TO_BINARY_INT8(i)    \
    (((i) & 0x80ll) ? '1' : '0'), \
    (((i) & 0x40ll) ? '1' : '0'), \
    (((i) & 0x20ll) ? '1' : '0'), \
    (((i) & 0x10ll) ? '1' : '0'), \
    (((i) & 0x08ll) ? '1' : '0'), \
    (((i) & 0x04ll) ? '1' : '0'), \
    (((i) & 0x02ll) ? '1' : '0'), \
    (((i) & 0x01ll) ? '1' : '0')

#define PRINTF_BINARY_PATTERN_INT16 \
    PRINTF_BINARY_PATTERN_INT8               PRINTF_BINARY_SEPARATOR              PRINTF_BINARY_PATTERN_INT8
#define PRINTF_BYTE_TO_BINARY_INT16(i) \
    PRINTF_BYTE_TO_BINARY_INT8((i) >> 8),   PRINTF_BYTE_TO_BINARY_INT8(i)
#define PRINTF_BINARY_PATTERN_INT32 \
    PRINTF_BINARY_PATTERN_INT16              PRINTF_BINARY_SEPARATOR              PRINTF_BINARY_PATTERN_INT16
#define PRINTF_BYTE_TO_BINARY_INT32(i) \
    PRINTF_BYTE_TO_BINARY_INT16((i) >> 16), PRINTF_BYTE_TO_BINARY_INT16(i)
#define PRINTF_BINARY_PATTERN_INT64    \
    PRINTF_BINARY_PATTERN_INT32              PRINTF_BINARY_SEPARATOR              PRINTF_BINARY_PATTERN_INT32
#define PRINTF_BYTE_TO_BINARY_INT64(i) \
    PRINTF_BYTE_TO_BINARY_INT32((i) >> 32), PRINTF_BYTE_TO_BINARY_INT32(i)

#define dump_array32(arr, len) for (size_t i = 1; i < len+1; i++) { \
	printf("" PRINTF_BINARY_PATTERN_INT32 " ", PRINTF_BYTE_TO_BINARY_INT32(*(arr+i-1))); \
	if (i % 2 == 0) printf("\n");					\
    }									\
    printf("\n")

#define dump_array8(arr, len) for (size_t i = 1; i < len+1; i++) { \
	printf("" PRINTF_BINARY_PATTERN_INT8 " ", PRINTF_BYTE_TO_BINARY_INT8(*(arr+i-1))); \
	if (i % 8 == 0) printf("\n");					\
    }									\
    printf("\n")


__constant__ uint64_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

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

__global__ void process(uint8_t* bytes, uint32_t* hash) {
    uint32_t w[64] = {0};
    memcpy(w, bytes+(threadIdx.x*64), 64);
    dump_array32(w, 64);
    for (int i = 0; i < 16; i++) {
	// bswap32
	w[i] = ((w[i]>>24)&0xff) | // move byte 3 to byte 0
	    ((w[i]<<8)&0xff0000) | // move byte 1 to byte 2
	    ((w[i]>>8)&0xff00) | // move byte 2 to byte 1
	    ((w[i]<<24)&0xff000000); // byte 0 to byte 3
    }
    dump_array32(w, 64);
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
    for (int i = 0; i < 8; i++) atomicAdd(hash+i, a[i]);
}

int main(int argc, char** argv) {
    sha_ctx sha(10);
    constexpr size_t BUFFER_SIZE = 32*1024;
    int fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    uint8_t* buf;
    cudaMallocManaged((void**)&buf, BUFFER_SIZE);
    size_t bytes_read = read(fd, buf, BUFFER_SIZE);
    do {
	if(bytes_read == (size_t)-1) {
	    printf("Error reading file.");
	    exit(1);
	}
	if (!bytes_read) break;
	else if (bytes_read < BUFFER_SIZE) {
	    buf[bytes_read] = 0b10000000;
	    size_t buffer_len = 64 * (((bytes_read + 9) / 64) + 1);
	    for (int i = 1; i <= 8; i++) buf[buffer_len-i] = sha.len*8 >> (i-1)*8;
	    process<<<1, buffer_len/64>>>(buf, sha.hash);
	}
	else {
	  process<<<1, 512>>>(buf, sha.hash);
	}
	cudaDeviceSynchronize();
    } while (bytes_read = read(fd, buf, BUFFER_SIZE));
    for (int i = 0; i < 8; i++) sha.hash[i] = __builtin_bswap32(sha.hash[i]);
    auto u8_ptr = reinterpret_cast<uint8_t*>(sha.hash);
    for (int i = 0; i < 32; i++) {
	std::cout << fmt::format("{:02x}", u8_ptr[i]);
    }
    std::cout << " " << argv[1] << "\n";
}

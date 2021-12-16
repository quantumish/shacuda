#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cuda_runtime_api.h>
#include <cuda.h>

// 32-bit bit right rotation
#define rotr(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// 32-bit byte swap
#define bswap32(x) ((x>>24)&0xff) |		\
    ((x<<8)&0xff0000) |				\
    ((x>>8)&0xff00) |				\
    ((x<<24)&0xff000000)			\

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

struct sha_ctx {
    uint32_t hash[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    uint64_t len;
    
    sha_ctx(uint64_t len);
    void compress(uint32_t* w);
    void dump_hash();
};

sha_ctx::sha_ctx(uint64_t length) :len(length) {}

__global__ void process(const uint8_t* bytes, uint32_t* w, uint32_t iters) {
    const size_t start_chunk = (blockIdx.y*gridDim.x*blockDim.x)+(blockIdx.x*blockDim.x)+threadIdx.x;
    for (int off = 0; off < iters; off++) {
	uint32_t* w_adj = w+(((start_chunk*iters)+off)*64);
	memcpy(w_adj, bytes+(((start_chunk*iters)+off)*64), 64);
	for (int i = 0; i < 16; i++) w_adj[i] = bswap32(w_adj[i]);
	for (int i = 16; i < 64; i++) {
	    uint32_t s0 = (rotr(w_adj[i-15], 7) ^ rotr(w_adj[i-15], 18) ^ (w_adj[i-15] >> 3));
	    uint32_t s1 = (rotr(w_adj[i-2], 17) ^ rotr(w_adj[i-2], 19)  ^ (w_adj[i-2] >> 10));
	    w_adj[i] = w_adj[i-16] + s0 + w_adj[i-7] + s1;
	}
    }
}

void sha_ctx::compress(uint32_t* w) {
    uint32_t a[8] = {0};
    memcpy(a, hash, 8*sizeof(uint32_t));
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
    for (int i = 0; i < 8; i++) hash[i] += a[i];
}

void sha_ctx::dump_hash() {
    uint32_t temp_hash[8];
    memcpy(temp_hash, hash, 8*sizeof(uint32_t));
    for (int i = 0; i < 8; i++) temp_hash[i] = bswap32(temp_hash[i]);
    auto u8_ptr = reinterpret_cast<uint8_t*>(temp_hash);
    for (int i = 0; i < 32; i++) printf("%02x", u8_ptr[i]);
}

int main(int argc, char** argv) {
    int fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    struct stat stat;
    fstat(fd, &stat);
    sha_ctx sha(stat.st_size);
    
    const size_t BUFFER_SIZE = 268435456; // 2 GiB
    uint8_t* buf; 
    cudaMallocManaged(&buf, BUFFER_SIZE);
    uint32_t* w;
    cudaMallocManaged(&w, BUFFER_SIZE*4);
    size_t bytes_read = read(fd, buf, BUFFER_SIZE);    
    bool padded = false;

    do {
	if (bytes_read == (size_t)-1) {
	    printf("Error reading file.");
	    exit(1);
	}
	if (!bytes_read) break;
	else if (bytes_read < BUFFER_SIZE) {
	    size_t buffer_len = 64 * (((bytes_read + 9) / 64) + 1);
	    for (size_t i = bytes_read; i < buffer_len; i++) buf[i] = 0;
	    buf[bytes_read] = 0b10000000;
	    for (int i = 1; i <= 8; i++) buf[buffer_len-i] = sha.len*8 >> (i-1)*8;
	    int threads[3] = {1024, 128, 1024};
	    int iters[3] = {1024, 1024, 1};
	    size_t remaining = buffer_len/64;
	    size_t shift = 0;
	    for (int i = 0; i < 3; i++) {
		size_t num_groups = remaining/(threads[i]*iters[i]);
		remaining = remaining % (threads[i]*iters[i]);
		for (int j = 0; j < num_groups; j++) {
		    process<<<1, threads[i]>>>(buf+shift, w+shift, iters[i]);
		    shift += threads[i]*iters[i]*64;
		}
	    }
	    process<<<1, remaining>>>(buf+shift, w+shift, 1);
	    cudaDeviceSynchronize();
	    for (int i = 0; i < buffer_len/64; i++) sha.compress(w+(i*64));
	    padded=true;
	} else {
	    process<<<dim3{8,8,1}, 64>>>(buf, w, 1024);
	    cudaDeviceSynchronize();
	    for (int i = 0; i < BUFFER_SIZE/64; i++) sha.compress(w+(i*64));
	}
    } while ((bytes_read = read(fd, buf, BUFFER_SIZE)));
    if (padded == false) {
	for (size_t i = 0; i < 64; i++) buf[i] = 0;
	buf[0] = 0b10000000;
	for (int i = 1; i <= 8; i++) buf[64-i] = sha.len*8 >> (i-1)*8;
	memcpy(w, buf, 64);
	for (int i = 0; i < 16; i++) w[i] = bswap32(w[i]);
	for (int i = 16; i < 64; i++) {
	    uint32_t s0 = (rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3));
	    uint32_t s1 = (rotr(w[i-2], 17) ^ rotr(w[i-2], 19)  ^ (w[i-2] >> 10));
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	sha.compress(w);
    }
    sha.dump_hash();
    printf("  %s\n", argv[1]);
}

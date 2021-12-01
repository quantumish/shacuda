#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <bit>
#include <iostream>
#include <iomanip>
#include <fmt/format.h> 

using Hash = std::array<uint8_t, 256>;

// Blatantly adapted from https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
void sha_256(char* bytes, size_t len) {
    size_t content_len = len + 64 + 1;
    size_t buffer_len = 0;
    while (true) {
	buffer_len += 512;
	if (buffer_len > content_len) break;
    }
    uint8_t buffer[buffer_len];
    memcpy(buffer, bytes, len);
    buffer[len+1] = 0b1000'0000;
    memcpy(buffer+buffer_len-64, &len, sizeof(size_t));

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    for (int i = 0; i < buffer_len; i += 512) {    
	size_t wlen = 512/4 + 48;
	uint32_t w[wlen];
	memcpy(buffer+i, &w, 512);
	
	for (int i = buffer_len; i < wlen; i++) {
	    uint32_t s0 = (std::rotr(w[i-15], 7) ^ std::rotr(w[i-15], 18) ^ std::rotr(w[i-15], 3));
	    uint32_t s1 = (std::rotr(w[i-2], 17) ^ std::rotr(w[i-2], 19)  ^ std::rotr(w[i-2], 10));
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
	for (int i = 0; i < 64; i++) {
	    uint32_t s1 = (std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25));
	    uint32_t ch = (e & f) ^ ((~e) & g);
	    uint32_t temp1 = h + s1 + ch + k[i] + w[i];
	    uint32_t s0 = (std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22));
	    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
	    uint32_t temp2 = s0 + maj;
	    h = g;
	    g = f;
	    f = e;
	    e = d + temp1;
	    d = c;
	    c = b;
	    b = a;
	    a = temp1 + temp2;
	}

	h0 += a;
	h1 += b;
	h2 += c;
	h3 += d;
	h4 += e;
	h5 += f;
	h6 += g;
	h7 += h;

	char out[32];
	memcpy(out, &h0, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*1, &h1, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*2, &h2, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*3, &h3, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*4, &h4, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*5, &h5, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*6, &h6, sizeof(uint32_t));
	memcpy(out+sizeof(uint32_t)*7, &h7, sizeof(uint32_t));

	for (int i = 0; i < 32; i++) {
	    std::cout << fmt::format("{:02x}", (uint8_t)out[i]);
	}
	std::cout << '\n';
    }    
}

int main() {
    sha_256(const_cast<char*>("hello world"), 11);
}

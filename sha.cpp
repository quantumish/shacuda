#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <array>
#include <bit>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fmt/format.h> 

using Hash = std::array<uint8_t, 256>;

template<typename T> 
void dump_array(T* bytes, size_t len) {
    for (size_t i = 1; i < len+1; i++) {
	auto str = "{:0"+std::to_string(sizeof(T)*8)+"b} ";
	std::cout << fmt::vformat(str, fmt::make_format_args(*(bytes+i-1))); 
	if (i % (128/(sizeof(T)*8)) == 0) std::cout << '\n';
    }
    std::cout << '\n';
}

// Blatantly adapted from https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
void sha_256(char* bytes, uint32_t len) {
    size_t content_len = len + 1 + 1;
    size_t buffer_len = 0;
    while (true) {
	buffer_len += 64;
	if (buffer_len > content_len) break;
    }
    uint8_t buffer[buffer_len] = {0};
    memcpy(buffer, bytes, len);
    buffer[len] = 0b1000'0000;
    //memcpy(buffer+buffer_len-4, &len, sizeof(uint32_t));
    buffer[buffer_len-1] = 0b0101'1000;
    std::cout << buffer_len << '\n';
    dump_array<uint8_t>(&buffer[0], buffer_len);
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

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

    uint32_t expected_w[] = {
	0b01101000011001010110110001101100, 0b01101111001000000111011101101111,
	0b01110010011011000110010010000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
	0b00000000000000000000000000000000, 0b00000000000000000000000001011000,
	0b00110111010001110000001000110111, 0b10000110110100001100000000110001,
	0b00110111010001110000001000110111, 0b10000110101111111110011100110001
	0b11010011101111010001000100001011, 0b01111000001111110100011110000010,
	0b00101010100100000111110011101101, 0b01001011001011110111110011001001,
	0b00110001111000011001010001011101, 0b10001001001101100100100101100100,
	0b01111111011110100000011011011010, 0b11000001011110011010100100111010,
	0b10111011111010001111011001010101, 0b00001100000110101110001111100110,
	0b10110000111111100000110101111101, 0b01011111011011100101010110010011,
	0b00000000100010011001101101010010, 0b00000111111100011100101010010100,
	0b00111011010111111110010111010110, 0b01101000011001010110001011100110,
	0b11001000010011100000101010011110, 0b00000110101011111001101100100101,
	0b10010010111011110110010011010111, 0b01100011111110010101111001011010,
	0b11100011000101100110011111010111, 0b10000100001110111101111000010110,
	0b11101110111011001010100001011011, 0b10100000010011111111001000100001,
	0b11111001000110001010110110111000, 0b00010100101010001001001000011001,
	0b00010000100001000101001100011101, 0b01100000100100111110000011001101,
	0b10000011000000110101111111101001, 0b11010101101011100111100100111000,
	0b00111001001111110000010110101101, 0b11111011010010110001101111101111,
	0b11101011011101011111111100101001, 0b01101010001101101001010100110100,
	0b00100010111111001001110011011000, 0b10101001011101000000110100101011,
	0b01100000110011110011100010000101, 0b11000100101011001001100000111010,
	0b00010001010000101111110110101101, 0b10110000101100000001110111011001,
	0b10011000111100001100001101101111, 0b01110010000101111011100000011110,
	0b10100010110101000110011110011010, 0b00000001000011111001100101111011,
	0b11111100000101110100111100001010, 0b11000010110000101110101100010110,
    };

    for (int i = 0; i < buffer_len; i += 512) {    	
	size_t wlen = 16 + 48;       
	uint32_t w[wlen] = {0};
        memcpy(w, buffer, 64);
	w[buffer_len/4 - 1] = 0b01011000;
	for (int i = 0; i < wlen; i++) {
	    w[i] = __builtin_bswap32(w[i]);
	}
	dump_array<uint8_t>((uint8_t*)&w, wlen);
        
	
	for (int i = buffer_len/4; i < wlen; i++) {
	    // std::cout << fmt::format("{:032b} ", w[i-15]) << fmt::format("{:032b} ", std::rotr(w[i-15], 7)) << fmt::format("{:032b} ", std::rotr(w[i-15], 18)) << fmt::format("{:032b}\n", (w[i-15]>>3));
	    uint32_t s0 = (std::rotr(w[i-15], 7) ^ std::rotr(w[i-15], 18) ^ (w[i-15] >> 3));
	    uint32_t s1 = (std::rotr(w[i-2], 17) ^ std::rotr(w[i-2], 19)  ^ (w[i-2] >> 10));
	    std::cout << fmt::format("{:032b} ", s0) << fmt::format("{:032b}\n", s1);
	    std::cout << fmt::format("{:032b} ", w[i-16]) << fmt::format("{:032b}\n", w[i-7]);
	    std::cout << "\n";
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	}	       
	dump_array<uint32_t>(w, wlen);
	int cmp = memcmp(w, expected_w, wlen);
	std::cout << cmp << "\n";
	std::cout << fmt::format("{:032b}\n", w[-cmp/4]);
	std::cout << fmt::format("{:032b}\n", w[-cmp/4]);
	assert(cmp == 0);
	
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

	char out[32] = {0};
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

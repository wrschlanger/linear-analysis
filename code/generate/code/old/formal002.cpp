// formal002.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// To build:
//    g++ -std=c++11 -o formal002.out formal002.cpp -O9
// --------------------------------------------------------------------------------
// This program computes a hash and generates output after every 8 rounds. This is
// intended to assist with debugging, and to validate the 'matrix' header files.
// --------------------------------------------------------------------------------
// This program uses these header files: hs0.h, hs1.h, ks0.h, and ks1.h.
// (Those files are created by formal001.cpp).
// ================================================================================

/* output:
4092FEF0 263500F6 48BD3A9B E8A5BEE6 F662B089 96D7DCE6 30390A6E 51EFD3EA [8]
F6FEA097 241DA176 018401FD 7029A783 74866420 4242CAF1 86B6906D 7E3EF42F [16]
C5D60ADA 8ADCF131 1DA993BC A1460DBC 493C24FA 11145185 9F3F5F47 3CA160F8 [24]
5C1DE77E E5C56410 F9937A39 BF5F5F4C D6E5F802 1A8FB422 72401439 A94AB795 [32]
85454A4A BB363DB5 F69AEA15 28588B34 3B1B5DCF D330022C 63FDD7F5 2535D2F4 [40]
FBD318B4 C80A34D1 289D43E4 2B400C18 8BC0FE27 F292BC76 6702F299 A7D043E8 [48]
3407105C 0B72A53B F02BCE70 E9603A20 41541D57 81AEFD0D 3355EFF2 35F375C9 [56]
9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 [64]
9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 (target)
*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <random>
#include <iostream>
#include <fstream>
#include <cstdio>

#include "ks0.h"
#include "ks1.h"
#include "hs0.h"
#include "hs1.h"

enum { NUM_ROUNDS = 64 };

inline uint32_t ROTL32(uint32_t x, uint32_t y)
{
    y &= 31;
    
    uint32_t left = x << y;
    
    
    y = (32 - y) & 31;
    uint32_t right = x >> y;
    
    return left | right;
}

inline uint32_t ROTR32(uint32_t x, uint32_t y)
{
    y &= 31;
    
    uint32_t left = x >> y;
    
    y = (32 - y) & 31;
    
    uint32_t right = x << y;
    
    return left | right;
}

// bitquest(s, x, y) returns ((s) ? x : y) for each bit, in a bitwise way.
inline uint32_t bitquest(uint32_t s, uint32_t x, uint32_t y)
{
    // The two terms being xor'd together here are mutually exclusive,
    // so for example, | could be used instead of | here.
    return (s & x) ^ (y & ~s);
}

inline uint32_t comp_ch(uint32_t e, uint32_t f, uint32_t g)
{
    // an example alternate form for this is: return g + (e & f) - (e & g);
    return bitquest(e, f, g);
}

inline uint32_t comp_maj(uint32_t a, uint32_t b, uint32_t c)
{
    // original form:  return (a & b) ^ (a & c) ^ (b & c);
    // alternate form: return bitquest(a, b | c, b & c);
    return bitquest(b ^ c, a, b);
}

// This exploits the fact that e.g. ks0(1 ^ 2 ^ 8) = ks0(1) ^ ks0(2) ^ ks0(8)
// together with the fact that ks0(0) = 0.
inline uint32_t lookup(uint32_t table[32], uint32_t value)
{
	uint32_t result = 0;
	
	for(uint32_t i = 0; i < 32; ++i, value >>= 1)
	{
		if((value & 1u) != 0)
		{
			result ^= table[i];
		}
	}
	
	return result;
}

inline uint32_t hs0(uint32_t x)
{
	return lookup(table_hs0, x);
}

inline uint32_t hs1(uint32_t x)
{
	return lookup(table_hs1, x);
}

inline uint32_t ks0(uint32_t x)
{
	return lookup(table_ks0, x);
}

inline uint32_t ks1(uint32_t x)
{
	return lookup(table_ks1, x);
}

static const uint32_t sha256_initial_h[8] =
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

static const uint32_t sha256_table_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// This does not modify 'w_entry'. The input 'h_entry' is transformed into the output 'h_entry'
// using 'w_entry'.
static void sha2_256(uint32_t h_entry[8], uint32_t w_entry[16])
{
    enum { A, B, C, D, E, F, G, H };
    
    uint32_t w[16];
    
    uint32_t h[8];
    
    for(size_t i = 0; i < 16; ++i)
    {
        w[i] = w_entry[i];
    }
    
    for(size_t i = 0; i < 8; ++i)
    {
        h[i] = h_entry[i];
    }
    
    for(size_t i = 0; i < NUM_ROUNDS; ++i)
    {
#undef VAR
#define VAR(x) h[((x) - i) & 7]
        VAR(H) += hs1(VAR(E)) + comp_ch(VAR(E), VAR(F), VAR(G)) + sha256_table_k[i] + w[i & 15];
        
        VAR(D) += VAR(H);
        
        VAR(H) += hs0(VAR(A)) + comp_maj(VAR(A), VAR(B), VAR(C));
        
        /* debugging
        if(i == 0)
        {
        	std::cout << "D' = 0x" << std::hex << VAR(D) << std::dec << std::endl;
        	std::cout << "H' = 0x" << std::hex << VAR(H) << std::dec << std::endl;
        }
        */

        w[i & 15] += ks0(w[(i + 1) & 15]) + w[(i + 9) & 15] + ks1(w[(i + 14) & 15]);
#undef VAR

	if((i & 7) == 7)
	{
		for(uint32_t i = 0; i < 8; ++i)
		{
		    char s[32 + 1];
		    
		    std::sprintf(s, "%08X ", (unsigned int)(h[i] + h_entry[i]));
		        
		    std::cout << s;
		}        
		std::cout << "[" << (i + 1) << "]" << std::endl;
	}
    }
    
    for(size_t i = 0; i < 8; ++i)
    {
        h_entry[i] += h[i];
    }
}

int main()
{
        //  The following string is the result of running the command "gpg --print-md sha256 <t.txt" where t.txt contains "test" without a new-line at the end.
        uint32_t h[8];
        uint32_t w[16];
        
        for(uint32_t i = 0; i < 8; ++i)
        {
        	h[i] = sha256_initial_h[i];
        }
        
        for(uint32_t i = 0; i < 16; ++i)
        {
        	w[i] = 0;
        }
        w[0] = ('t' << 0) + ('s' << 8) + ('e' << 16) + ('t' << 24);	// message to digest ("test")
        w[1] = 0x80000000u;						// marker bit
        w[15] = (4 * 8);						// message length, low 32 bits
        
        sha2_256(h, w);

        std::cout << "9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 (target)" << std::endl;

	return 0;
}


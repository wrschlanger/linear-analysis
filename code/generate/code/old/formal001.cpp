// formal001.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// To build:
//    g++ -std=c++11 -o formal001.out formal001.cpp -O9
// --------------------------------------------------------------------------------
// This program creates matrices for all first-order equations (hs0/hs1/ks0/ks1)
// and provides some useful output.
// --------------------------------------------------------------------------------
// This program creates the following files: hs0.h, hs1.h, ks0.h, and ks1.h.
// ================================================================================

/* Output:
w[0] = 0x74657374
w[1] = 0x80000000
w[2] = 0x0
w[3] = 0x0
w[4] = 0x0
w[5] = 0x0
w[6] = 0x0
w[7] = 0x0
w[8] = 0x0
w[9] = 0x0
w[10] = 0x0
w[11] = 0x0
w[12] = 0x0
w[13] = 0x0
w[14] = 0x0
w[15] = 0x20
w[16] = 0x85659374
w[17] = 0x80140000
w[18] = 0x7bf58b7a
w[19] = 0x80205508
w[20] = 0x74cc8fe6
w[21] = 0x20055801
w[22] = 0xd612c7fc
w[23] = 0x8c6e48c8
w[24] = 0xbb48757a
w[25] = 0x6953d7a2
w[26] = 0xb45d2dd8
w[27] = 0x60bbd5c
w[28] = 0x537fb3ef
w[29] = 0x7f16c927
w[30] = 0xfc14e508
w[31] = 0x166c6386
w[32] = 0xedd657cc
w[33] = 0x8b7f453f
w[34] = 0x776c519d
w[35] = 0xff4489c8
w[36] = 0xe705110d
w[37] = 0x448e3765
w[38] = 0x29c4f03b
w[39] = 0x56d4fa86
w[40] = 0xe8e882ae
w[41] = 0xaf5bb0c4
w[42] = 0x5c74ac3c
w[43] = 0xd394c0d8
w[44] = 0x4ef1cf66
w[45] = 0xd857da58
w[46] = 0x4737038f
w[47] = 0x2738a62e
w[48] = 0xbe10843f
w[49] = 0x50331a18
w[50] = 0x4a1ce75b
w[51] = 0x7fff59c9
w[52] = 0xfe72c27a
w[53] = 0x22ed8860
w[54] = 0xc321f5c0
w[55] = 0xea81a878
w[56] = 0x6e0938fe
w[57] = 0x32bbcc5b
w[58] = 0x33d3040f
w[59] = 0x284c1f19
w[60] = 0xb0964602
w[61] = 0xfe6ad1fb
w[62] = 0x8ec8c416
w[63] = 0x11f0d783
9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 (actual)
9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 (target)
Generating header files... done
*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <random>
#include <iostream>
#include <fstream>
#include <cstdio>

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

inline uint32_t hs0(uint32_t a)
{
	return ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
}

inline uint32_t hs1(uint32_t e)
{
	return ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
}

inline uint32_t ks0(uint32_t x)
{
	return ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3);
}

inline uint32_t ks1(uint32_t x)
{
	return ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10);
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
    
    for(size_t i = 0; i < 64; ++i)
    {
#undef VAR
#define VAR(x) h[((x) - i) & 7]
        VAR(H) += hs1(VAR(E)) + comp_ch(VAR(E), VAR(F), VAR(G)) + sha256_table_k[i] + w[i & 15];
        
        VAR(D) += VAR(H);
        
        VAR(H) += hs0(VAR(A)) + comp_maj(VAR(A), VAR(B), VAR(C));
        
        std::cout << "w[" << i << "] = 0x" << std::hex << w[i & 15] << std::dec << std::endl;

        w[i & 15] += ks0(w[(i + 1) & 15]) + w[(i + 9) & 15] + ks1(w[(i + 14) & 15]);
#undef VAR
    }
    
    for(size_t i = 0; i < 8; ++i)
    {
        h_entry[i] += h[i];
    }
}

void write(uint32_t value[32], std::ostream &os, const char *name)
{
	os << "static uint32_t table_" << name << "[] = {\n";
	for(uint32_t i = 0; i < 32; ++i)
	{
		os << "\t0x" << std::hex << value[i] << std::dec;
		if(i + 1 != 32)
		{
			os << ",";
		}
		os << "\n";
	}
	os << "};" << std::endl;
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

        for(uint32_t i = 0; i < 8; ++i)
        {
            char s[32 + 1];
            
            std::sprintf(s, "%08X ", h[i]);
                
            std::cout << s;
        }        
        std::cout << "(actual)" << std::endl;
        std::cout << "9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 (target)" << std::endl;

	uint32_t ks0data[32], ks1data[32], hs0data[32], hs1data[32];
        
        for(uint32_t i = 0; i < 32; ++i)
        {
        	ks0data[i] = ks0(1u << i);
        	ks1data[i] = ks1(1u << i);
        	hs0data[i] = hs0(1u << i);
        	hs1data[i] = hs1(1u << i);
        }
        
        std::cout << "Generating header files... " << std::flush;
        
        std::ofstream fks0("ks0.h");
        write(ks0data, fks0, "ks0");
        fks0.close();
        
        std::ofstream fks1("ks1.h");
        write(ks1data, fks1, "ks1");
        fks1.close();
        
        std::ofstream fhs0("hs0.h");
        write(hs0data, fhs0, "hs0");
        fhs0.close();
        
        std::ofstream fhs1("hs1.h");
        write(hs1data, fhs1, "hs1");
        fhs1.close();
        
        std::cout << "done" << std::endl;

	return 0;
}


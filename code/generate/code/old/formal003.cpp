// formal003.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// To build:
//    g++ -std=c++11 -o formal003.out formal003.cpp formcrypto.cpp -O9 -lgmp -lgmpxx
// --------------------------------------------------------------------------------
// This program was used to derive "linear" formulas for Maj and Ch. They use the
// non-linear operator T(x) = (x mod 2). In this formal system:
// 1. T(x) = (x mod 2)
// 2. 2 * Ch(e, f, g)  = f + g + T(e + g) - T(e + f)
// 3. 2 * Maj(a, b, c) = a + b + c - T(a + b + c)
// 4. Let's define S(X) = X / 2, which is allowed only when X is provably even
//    regardless of what values (0 or 1) are used for the "input" boolean variables.
//    So as a reminder, S(X) is undefined for odd X and isn't allowed if it's
//    possible X could be odd for some input variable combination.
//    (Capitalized variables represent arbitrary-precision/rational scalars;
///   lowercase-named variables represent boolean variables that are either 0 or 1).
//
//    Note: only boolean variables actually exist from an external point of view.
//    That is, the user is only ever expected to provide boolean variables; they
//    serve as our input and output, and there are temporaries in-between which
//    are introduced whenever we use a 'T' operator. The 'S' operator doesn't
//    trigger the requirement for a new variable, by itself.
//
// So we can XOR boolean variables via T(x1 + x2 + x3). Once done, we might want to
// "gather" together the bits into an intermediate (scalar) variable.
// Also, we can "scatter" apart an intermediate variable into 32 separate boolean
// variables:
// 5. x0' = T(X)
//    x1' = T(S(X - x0'))
//    x2' = T(S^2(X - 2 * x1' - x0'))
//        [The notation S^2(u) means S(S(u)) = u*2^-2; we allow rational coefficients].
// This process might be needed if after doing an addition, we need boolean
// variables again, either for the final answer or because we need to do an XOR op.
// ================================================================================

//#include "formcrypto.h"

#include <iostream>

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

// T(x) = (x mod 2). This will be our so-called "nonlinear" operator.
inline uint32_t T(uint32_t x)
{
	return x & 1;
}

int main()
{
	std::ostream &os = std::cout;

	os << "Ch:" << std::endl;
	for(int a = 0; a < 2; ++a)
	{
		for(int b = 0; b < 2; ++b)
		{
			for(int c = 0; c < 2; ++c)
			{
				os << a << " " << b << " " << c << " : ";
				os << comp_ch(a, b, c);
				os << " ";
				
				/*
				double aa = 1.0 - 2.0 * a;
				double bb = 1.0 - 2.0 * b;
				double cc = 1.0 - 2.0 * c;
				double dd = 0.5 * (cc + aa*cc - aa*bb + bb);
				double value = 0.5 - 0.5 * dd;				
				os << value;
				os << " ";
				*/
				
				double value = 0.5 * c + 0.5 * b + 0.5 * T(a + c) - 0.5 * T(a + b);	// T is being used for xor
				os << value;
				
				os << std::endl;
			}
		}
	}
	
	os << "\nMaj:" << std::endl;
	for(int a = 0; a < 2; ++a)
	{
		for(int b = 0; b < 2; ++b)
		{
			for(int c = 0; c < 2; ++c)
			{
				os << a << " " << b << " " << c << " : ";
				os << comp_maj(a, b, c);
				os << " ";
				
				/*
				double aa = (1.0 - 2.0 * b) * (1.0 - 2.0 * c);
				double bb = 1.0 - 2.0 * a;
				double cc = 1.0 - 2.0 * b;
				double dd = 0.5 * (cc + aa*cc - aa*bb + bb);
				double value = 0.5 - 0.5 * dd;				
				os << value;
				os << " ";
				*/
				
				double value = 0.5 * b + 0.5 * a + 0.5 * c - 0.5 * T(c + b + a);	// T is being used for xor
				os << value;
				
				os << std::endl;
			}
		}
	}

	return 0;
}


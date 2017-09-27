// formal005.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// To build:
//   g++ -std=c++11 -o formal005.out formal005.cpp formcrypto.cpp formsha256.cpp -lgmp -lgmpxx -O9
// --------------------------------------------------------------------------------
// Formal representation for SHA-256 (presently applied only once). This program
// demonstrates correctness and viability of the computational model that
// represents a stateless machine (such as a cryptosystem like SHA-256) as a system
// of linear equations modulo 2. [But note we allow rational coefficients like 1/2,
// even though we promise prior to doing the modulo 2 we'll have an integer for any
// unknown input variable and consistent temporary variable combination; this in
// fact is what allows us to linearlize a nonlinear problem !]
// --------------------------------------------------------------------------------
// Some equations 'define' a temporary variable and some are 'output' equations that
// are supposed to be 0. There are various kinds of variables that are used but not
// defined, such as "inputs" (unknown variables we need to solve for), and "constants".
// --------------------------------------------------------------------------------
// All equations are initially taken modulo 2, which is being demonstrated here.
// In a formal system, one could imagine we have e.g. t0 = ... - 2 * (lambda0)
// where (lambda0) is some unspecified integer. For any valid input (meaning for
// any combination of unknown input bits), all temporary values will have, when
// computed, an integer [which is then taken modulo 2]. Thus we never wind up
// taking 1.5 mod 2 or anything like that, if we start with a possible input
// (all unknown bits can be 0 or 1) and use a consistent set of values for the
// temporaries (i.e. they must be 0 or 1 also, but which one depends ultimately
// on the unknown input values used and the constant values provided).
// --------------------------------------------------------------------------------
// We can change the above "formal" equation from t0 = ... - 2 * (lambda0) to
// C * t0 = ... - C * 2 * (lambda0) for some power of two value for C. This will
// let us remove fractions (which always have a power of 2 in their denominator),
// thus making them integers (but we'll no longer be modulo 2 exclusively).
// --------------------------------------------------------------------------------
// [Done] the next step is to ensure our output is all 0s. We need that because the
// flattening process will assume our 'targetOp' values are correct, and we set
// those presently to all 0s (we can change an operand value if we need a nonzero
// expected output value for one or more bit(s)). We should also implement the
// whole "applied two or more times" code -- must be done properly !
// --------------------------------------------------------------------------------
// Sunday, April 5, 2015. What I just did was modify the flattening process to have
// a post-processing step where each numerator now has its magnitude taken modulo
// twice its denominator, to avoid memory usage creep. This needs to be verified to
// be valid after the binary version of the equations is written to disk and read
// back in another program for analysis. It sounds solid since the operand value
// itself is modulo 2, and it keeps our memory usage down (even below 2GB or so !)
// --------------------------------------------------------------------------------
// We need to check our equations (generate a binary version and study !)
// + Based on a quick glance, it looks like we'll wind up being modulo 2^33 again
//   (!) [At least for the worst-case equations]. This is based on the largest
//   denominator I saw via manual inspection being 2^32 (for the denominator magnitude).
// ================================================================================
// Monday, April 6, 2015. Equation set validated, ready to write binary version to
// disk! OK, all done with this program (formal005.cpp -- generates output binary
// files and they check out OK !!!)
// ================================================================================

// [obsolete code deleted].


// formsha256.h - by Willow Schlanger. Released to the Public Domain in August of 2017.
// --------------------------------------------------------------------------------
// Formal representation for SHA-256.
// ================================================================================

#ifndef l_formsha256_h__included_formal_crypto
#define l_formsha256_h__included_formal_crypto

#include "formcrypto.h"

#include <gmpxx.h>

#include <stdint.h>
#include <string.h>

#include <iostream>
#include <memory>
#include <vector>
#include <map>

namespace formal_crypto
{

// This generates a formal definition (equation set) for SHA-256.
//
// 'unknownW' refers to the number of W-variables we don't know, starting with w[0]. 2 is a typical number to use here.
// 'targetH' refers to the number of output H bits we need. the rest will be discarded. 256 is for a complete hash output.
// 'applyCount' is the number of times we're applying the SHA-256 algorithm (usually 1).
// 'numRounds' is the number of rounds (the SHA-256 algorithm itself requires precisely 64 be used here, but we allow
// this to be any integral multiply of 8 between 8 and 64 inclusive -- allows for testing on a reduced system !)
//
// c[] = constant variables, to have a value provided by the user.
// x[] = (unknown) input variables, to be solved for.
// t[] = temporary variables. some of these are "user outputs". the first 256 "user outputs" (some may be simply wired to 0,
//       if targetH isn't 256), repesent the final output h's. the remaining "user outputs" are simply things that "must be 0",
//       created if appropriate. see also CCryptosystem::autoTempOperandOutputPositions[] in formcrypto.h.
// c[1..512] represent the input W values. use 0 for the first 'unknownW' bits (those won't be used, anyway).
// c[513..513+256-1] represents the input H values.
// c[513+256..513+256+256-1] is reserved for the expected output H values. use 0 for discarded output H's (see 'targetH').
// x[0..'unknownW'-1] are the bits we're trying to solve for.
// see note above regarding t[].
class CFormalSha256
{
public:
	CFormalSha256(CCryptosystem &cSystem, uint32_t unknownW, uint32_t targetH, uint32_t applyCount = 1, uint32_t numRounds = 64);

private:
	void Sha256Update(CCryptosystem &cSystem, CWord h[8], CWord w[64], uint32_t numRounds);
	void ExpandW(CCryptosystem &cSystem, CWord w[64], uint32_t numRounds);
	CWord Sha256Ch(CCryptosystem &cSystem, CWord &e, CWord &f, CWord &g);
	CWord Sha256Maj(CCryptosystem &cSystem, CWord &a, CWord &b, CWord &c);
};

}	// namespace formal_crypto

#endif	// l_formsha256_h__included_formal_crypto


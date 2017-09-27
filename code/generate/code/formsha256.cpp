// formsha256.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// --------------------------------------------------------------------------------
// Formal representation for SHA-256 (applied one or more times).
// ================================================================================

#include "formcrypto.h"
#include "formsha256.h"

namespace formal_crypto
{
// ================================================================================

// This generates a formal definition (equation set) for SHA-256, possibly applied multiple times.
//
// 'unknownW' exists for historical purposes and should be 0 (an effort to cryptanalyze SHA2-256 with an effective number
// of rounds of only 2 was made; note that there are better ways to 'break' SHA2-256 once it's been reduced to only two
// rounds, and the full spec specifies 64 rounds).
// 'targetH' refers to the number of output H bits we need. the rest will be discarded. 256 is for a complete hash output.
// 'applyCount' is the number of times we're applying the SHA-256 algorithm. 1 means we're doing a straight-forward hash.
// many of these variables exist for historical reasons only, and aren't too useful in actuality as they'd take us into
// P vs. NP terrotiroy, an area we'd like not to venture. =)
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
CFormalSha256::CFormalSha256(CCryptosystem &cSystem, uint32_t unknownW /*bits*/, uint32_t targetH /*bits*/, uint32_t applyCount /*= 1*/, uint32_t numRounds /*= 64*/)
{
	if(unknownW > 512 || targetH > 256 || applyCount == 0 || numRounds > 64)
	{
		throw std::runtime_error("CFormalSha256::CFormalSha256(): invalid configuration detected.");
	}
	
	// Let's start by creating our initial w[] words.
	CWord w[64];
	ROperator wBits[512];	
	for(uint32_t i = 0; i < 512; ++i)
	{
		cSystem.constantOperands.push_back(cSystem.CreateOperand(E_OPERAND_CONSTANT, i + 1));	// constant 0 is unity (built-in to the system)
		wBits[i] = cSystem.CreateOperator(cSystem.constantOperands.back());
	}
	// note: above code created 512 'constant' operands. user is expected to set the first 'unknownW' of these to 0, as we won't be using those variables.
	for(uint32_t i = 0; i < unknownW; ++i)
	{
		cSystem.inputOperands.push_back(cSystem.CreateOperand(E_OPERAND_INPUT, i));
		wBits[i] = cSystem.CreateOperator(cSystem.inputOperands.back());
	}
	for(uint32_t i = 0; i < 16; ++i)
	{
		w[i] = CWord::Gather(cSystem, wBits + 32 * i, 32);
	}
	
	// Next, let's create the initial h[] words.
	CWord h[8];
	
	ROperator hBits[256];
	for(uint32_t i = 0; i < 256; ++i)
	{
		cSystem.constantOperands.push_back(cSystem.CreateOperand(E_OPERAND_CONSTANT, i + 512 + 1));
		hBits[i] = cSystem.CreateOperator(cSystem.constantOperands.back());
	}
	for(uint32_t i = 0; i < 8; ++i)
	{
		h[i] = CWord::Gather(cSystem, hBits + 32 * i, 32);
	}
	
	// Let's allow the user to provide 256 "expected" output values. They should just use 0 for discarded output bits, e.g. any bits after the first targetH.
	ROperand hTargetOperand[256];
	for(uint32_t i = 0; i < 256; ++i)
	{
		hTargetOperand[i] = cSystem.CreateOperand(E_OPERAND_CONSTANT, i + 512 + 1 + 256);
		cSystem.constantOperands.push_back(hTargetOperand[i]);
	}
	
	// Let's create our output operands now.
	std::vector<ROperand> outH(256);
	
	for(uint32_t i = 0; i < 256; ++i)
	{
		outH[i] = cSystem.CreateOperand(E_OPERAND_TEMP, i);
		outH[i]->sourceOp = cSystem.GetZero();	// to be overwritten by the code below
	}
	
	
	// Let's do SHA-256 !
	for(uint32_t n = 0; n < applyCount; ++n)
	{
		// Our next step is to expand the W array.
		this->ExpandW(cSystem, w, numRounds);

		this->Sha256Update(cSystem, h, w, numRounds);
		
		if(n + 1 < applyCount)
		{
			// Prepare for next iteration.
			for(uint32_t i = 0; i < 8; ++i)
			{
				ROperator bits[32];				
				for(uint32_t j = 0; j < 32; ++j)
				{
					bits[j] = h[i].GetBit(j);
				}
				w[i] = CWord::Gather(cSystem, bits, 32);
				
				//@w[i] = h[i];				// copy h[0..7] to w[0..7] -- doesn't work, "node creep"

				w[i + 8] = CWord(cSystem, 0);		// zero out w[8..15]
			}
			w[8] = CWord(cSystem, 0x80000000u);		// marker bit
			w[15] = CWord(cSystem, 256);			// message length (always 256 bits -- same as hash output length in bits)

			for(uint32_t i = 0; i < 8; ++i)
			{
				h[i] = CWord(cSystem, CUtilSha256::GetInitialH(i));
			}
		}
	}
	
	// Discard "don't care" outH[] bits (set to 0). Note: this likely requires taking into account the proper target endian-ness scheme.
	// That is to say, it can only be considered 'correct' as it presently is, if targetH is a multiple of 32; otherwise we need to do some shuffling here.
	for(uint32_t i = 0; i < 256; ++i)
	{
		bool discard = (i >= targetH);		// this line is WRONG! TODO, needs to be reworked once target endianness is better understood.
		
		outH[i]->sourceOp = (discard) ? cSystem.GetZero() : h[i / 32].GetBit(i & 31);
	}
	
	// Accept output operands.
	for(uint32_t i = 0; i < outH.size(); ++i)
	{
		if(false)
		{
		outH[i]->targetOp = cSystem.GetZero();					// when codebreaking, we "expect" all outputs to be 0
		outH[i]->sourceOp = cSystem.CreateOperator(outH[i]->sourceOp);		// honor our "immutable until flattened" model
		outH[i]->sourceOp->AddOperand(hTargetOperand[i]);
		}
		
		cSystem.userOutputOperands.push_back(outH[i]);
	}
}

// ================================================================================

CWord CFormalSha256::Sha256Ch(CCryptosystem &cSystem, CWord &e, CWord &f, CWord &g)
{
	// 2 * Ch(e, f, g)  = f + g + T(e + g) - T(e + f)
	// T(x) means (x mod 2)
	
	ROperator dest[32];

	for(uint32_t i = 0; i < 32; ++i)
	{
		ROperator tempFG = cSystem.CreateOperator();
		tempFG->Add(f.GetBit(i), mpq_class(1, 2));
		tempFG->Add(g.GetBit(i), mpq_class(1, 2));

		ROperator tempEG = cSystem.CreateOperator();
		tempEG->Add(e.GetBit(i));
		tempEG->Add(g.GetBit(i));

		ROperator tempEF = cSystem.CreateOperator();
		tempEF->Add(e.GetBit(i));
		tempEF->Add(f.GetBit(i));
		
		dest[i] = cSystem.CreateOperator(tempFG);
		
		ROperand tempEG1 = cSystem.CreateOperand(E_OPERAND_TEMP);
		tempEG1->sourceOp = tempEG;
		dest[i]->AddOperand(tempEG1, mpq_class(1, 2));
		
		ROperand tempEF1 = cSystem.CreateOperand(E_OPERAND_TEMP);
		tempEF1->sourceOp = tempEF;
		dest[i]->AddOperand(tempEF1, mpq_class(-1, 2));
	}

	CWord result = CWord::Gather(cSystem, dest, 32);
	
	return result;
}

CWord CFormalSha256::Sha256Maj(CCryptosystem &cSystem, CWord &a, CWord &b, CWord &c)
{
	// 2 * Maj(a, b, c) = a + b + c - T(a + b + c)
	// T(x) means (x mod 2)
	
	ROperator dest[32];

	for(uint32_t i = 0; i < 32; ++i)
	{
		ROperator temp = cSystem.CreateOperator();
		temp->Add(a.GetBit(i));
		temp->Add(b.GetBit(i));
		temp->Add(c.GetBit(i));
		
		ROperand tempT = cSystem.CreateOperand(E_OPERAND_TEMP);
		tempT->sourceOp = cSystem.CreateOperator(temp);
		
		dest[i] = cSystem.CreateOperator();
		dest[i]->AddOperand(tempT, -mpq_class(1, 2));
		dest[i]->Add(a.GetBit(i), mpq_class(1, 2));
		dest[i]->Add(b.GetBit(i), mpq_class(1, 2));
		dest[i]->Add(c.GetBit(i), mpq_class(1, 2));
	}

	CWord result = CWord::Gather(cSystem, dest, 32);
	
	return result;
}

// ================================================================================

// After this runs, hEntry[] will be updated to contain the hash output. On entry, hEntry[] contains the
// h[] array's initial values and w[0..63] is to contain the expanded w-values.
// numRounds should be 64 for SHA-256 (we allow any integral multiple of 8 between 8 and 64 inclusive,
// though, to help with testing purposes). [If not a multiple of 8, output words will be incorrectly permuted.]
void CFormalSha256::Sha256Update(CCryptosystem &cSystem, CWord hEntry[8], CWord w[64], uint32_t numRounds)
{
	CWord h[8];
	
	for(uint32_t i = 0; i < 8; ++i)
	{
		h[i] = hEntry[i];
	}
	
	for(uint32_t i = 0; i < numRounds; ++i)
	{
		enum { A, B, C, D, E, F, G, H };
#undef VAR
#define VAR(x) (((x) - i) & 7)
		CWord newH = h[VAR(H)];
		CWord newD = h[VAR(D)];
		
		newH = newH.AddUnary32Bits(h[VAR(E)], CUtilSha256::GetTableHs1(), 32);
		
		CWord valueCh = Sha256Ch(cSystem, h[VAR(E)], h[VAR(F)], h[VAR(G)]);
		newH = newH.AddIdentity(valueCh);
		
		// H += K[i]
		newH = newH.AddIdentity(CWord(cSystem, CUtilSha256::GetEntryK(i)));

		// H += W[i]
		newH = newH.AddIdentity(w[i]);
		
		newD = newD.AddIdentity(newH);
		
		newH = newH.AddUnary32Bits(h[VAR(A)], CUtilSha256::GetTableHs0(), 32);

		CWord valueMaj = Sha256Maj(cSystem, h[VAR(A)], h[VAR(B)], h[VAR(C)]);
		newH = newH.AddIdentity(valueMaj);
		
		h[VAR(H)] = newH;
		h[VAR(D)] = newD;
#undef VAR
	}
	
	for(uint32_t i = 0; i < 8; ++i)
	{
		hEntry[i] = hEntry[i].AddIdentity(h[i]);
	}
}

// ================================================================================

void CFormalSha256::ExpandW(CCryptosystem &cSystem, CWord w[64], uint32_t numRounds)
{
	// Our job is to set w[i] to operandPrevious + Identity(operandIdentity) +
	// 	ks0(operandKs0) + ks1(operandKs1).
	
	for(uint64_t i = 16; i < numRounds; ++i)
	{
		w[i] = w[i - 16].AddIdentity(w[i - 16 + 9]);
		
		CWord operandKs0 = w[i - 16 + 1];
		CWord operandKs1 = w[i - 16 + 14];

		w[i] = w[i].AddUnary32Bits(operandKs0, CUtilSha256::GetTableKs0(), 32);

		w[i] = w[i].AddUnary32Bits(operandKs1, CUtilSha256::GetTableKs1(), 32);
	}
}

// ================================================================================
}	// namespace formal_crypto


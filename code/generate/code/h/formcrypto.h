// formcrypto.h - by Willow Schlanger. Released to the Public Domain in August of 2017.
// --------------------------------------------------------------------------------
// Formal analysis.
// ================================================================================

#ifndef l_formcrypto_h__included_formal_crypto
#define l_formcrypto_h__included_formal_crypto

#include <gmpxx.h>

#include <stdint.h>
#include <string.h>

#include <iostream>
#include <memory>
#include <vector>
#include <map>

namespace formal_crypto
{

enum	// this should be no less than 32 and should be increased only if necessary
{
	WORD_SIZE_BITS_MAX = 32
};

class CUtilSha256
{
public:
	static uint32_t GetInitialH(uint32_t n);	// 0 <= n < 8
	static uint32_t GetEntryK(uint32_t n);		// 0 <= n < 64
	static const uint32_t *GetTableHs0();		// there are 32 elements in the returned array
	static const uint32_t *GetTableHs1();		// there are 32 elements in the returned array
	static const uint32_t *GetTableKs0();		// there are 32 elements in the returned array
	static const uint32_t *GetTableKs1();		// there are 32 elements in the returned array
	static uint32_t Comp32Hs0(uint32_t x);
	static uint32_t Comp32Hs1(uint32_t x);
	static uint32_t Comp32Ks0(uint32_t x);
	static uint32_t Comp32Ks1(uint32_t x);
	
	// This updates h_entry[] to contain the result of hashing w_entry using the input h_entry initial
	// values. numRounds shall be a multiple of 8.
	static void CompSha256(uint32_t h_entry[8], const uint32_t w_entry[16], uint32_t numRounds = 64);
	
	// This tests the SHA-256 implementation. numRounds shall be a multiple of 8.
	static void SelfTest(std::ostream &os, uint32_t numRounds = 64);
	
	// Diagnostic function.
	static void WriteH(std::ostream &os, uint32_t h[8], bool cStyle = false);
};

// Rotate-left function.
inline uint32_t Comp32ROTL(uint32_t x, uint32_t y)
{
    y &= 31;
    
    uint32_t left = x << y;
    
    
    y = (32 - y) & 31;
    uint32_t right = x >> y;
    
    return left | right;
}

// Rotate-right function.
inline uint32_t Comp32ROTR(uint32_t x, uint32_t y)
{
    y &= 31;
    
    uint32_t left = x >> y;
    
    y = (32 - y) & 31;
    
    uint32_t right = x << y;
    
    return left | right;
}

// S(X) = (X >> 1). Only allowed if (X mod 2) is 0. "Shift" operator.
// This operates on a single bit.
inline uint32_t Comp32S(uint32_t x)
{
	return x >> 1;
}

// T(X) = (X mod 2). This is our so-called "nonlinear" operator.
// This operates on a single bit.
inline uint32_t Comp32T(uint32_t x)
{
	return x & 1;
}

// This is the same as Comp32Ch(), but it operates on a single bit.
inline uint32_t Comp32ChBit(uint32_t e, uint32_t f, uint32_t g)
{
    return Comp32S(f + g + Comp32T(e + g) - Comp32T(e + f));
}

// This is the same as Comp32Maj() function, but it operates on a single bit.
inline uint32_t Comp32MajBit(uint32_t a, uint32_t b, uint32_t c)
{
    return Comp32S(a + b + c - Comp32T(a + b + c));
}

// Comp32BitQuest(s, x, y) returns ((s) ? x : y) for each bit, in a bitwise way.
inline uint32_t Comp32BitQuest(uint32_t s, uint32_t x, uint32_t y)
{
    // The two terms being xor'd together here are mutually exclusive,
    // so for example, | could be used instead of | here.
    return (s & x) ^ (y & ~s);
}

// Alternative definition: 2 * Ch(e, f, g)  = f + g + T(e + g) - T(e + f)
inline uint32_t Comp32Ch(uint32_t e, uint32_t f, uint32_t g)
{
    // an example alternate form for this is: return g + (e & f) - (e & g);
    return Comp32BitQuest(e, f, g);
}

// Alternative definition: 2 * Maj(a, b, c) = a + b + c - T(a + b + c)
inline uint32_t Comp32Maj(uint32_t a, uint32_t b, uint32_t c)
{
    // original form:  return (a & b) ^ (a & c) ^ (b & c);
    // alternate form: return bitquest(a, b | c, b & c);
    return Comp32BitQuest(b ^ c, a, b);
}

// ================================================================================

// Constants: unity is a constant; so are the known input variables.
// Inputs: these refer to the unknown input variables we want to solve for.
// Temporaries and outputs: these are computed from known values. Temporaries are
// intermediate variables that resulted from the use of a "T operator" (mod 2).
// "Outputs" are temporaries with a "target value" (so we know what we want for it).
// When operating normally, columns are labeled in evaluation
// order meaning any column can refer to any value defined previously (to the left)
// but not any values defined to the right.
enum { E_OPERAND_CONSTANT, E_OPERAND_INPUT, E_OPERAND_TEMP, E__OPERAND_COUNT };

class COperand;
class COperator;

typedef std::shared_ptr<COperand> ROperand;

typedef std::shared_ptr<COperator> ROperator;

// This base class is responsible for tracking unique identifiers.
class CCryptosystemBase
{
protected:
	ROperand unity;
	ROperator zero;
	ROperator one;
	uint32_t wordSizeBits;

public:
	ROperator GetZero() const
	{
		return this->zero;
	}
	
	ROperator GetOne() const
	{
		return this->one;
	}
	
	ROperand GetUnity() const
	{
		return this->unity;
	}

	CCryptosystemBase(uint32_t wordSizeBitsT) :
		wordSizeBits(wordSizeBitsT)
	{
		this->nextUid[0] = 1;
		this->nextUid[1] = 0;
		
		if(wordSizeBitsT > WORD_SIZE_BITS_MAX)
		{
			throw std::runtime_error("CCryptosystemBase::CCryptosystemBase(): attempt to instantiate with more than WORD_SIZE_BITS_MAX bits. Increase the enum value.");
		}
		
		if(wordSizeBitsT == 0)
		{
			throw std::runtime_error("CCryptosystemBase::CCryptosystemBase(): attempt to instantiate with a 0 word-size. Must be at least 1.");
		}
	}

	virtual ~CCryptosystemBase()
	{
	}

	uint64_t nextUid[2];
	
	const uint32_t WordSizeBits() const
	{
		return this->wordSizeBits;
	}
};

// This class represents a locally-unique identifier.
class CUniversalId
{
	uint64_t uid[2];
public:
	uint64_t Get(uint32_t n) const
	{
		return this->uid[n];
	}

	CUniversalId()
	{
		this->uid[0] = 0;
		this->uid[1] = 0;
	}
	
	CUniversalId(CCryptosystemBase &src)
	{
		this->uid[0] = src.nextUid[0];
		this->uid[1] = src.nextUid[1];
	
		++src.nextUid[0];
		
		if(src.nextUid[0] == 0)
		{
			++src.nextUid[1];
		}
	}
	
	bool operator==(const CUniversalId &src) const
	{
		return this->uid[0] == src.uid[0] && this->uid[1] == src.uid[1];
	}
	
	bool operator!=(const CUniversalId &src) const
	{
		return this->uid[0] != src.uid[0] || this->uid[1] != src.uid[1];
	}
	
	bool operator<(const CUniversalId &src) const
	{
		return memcmp(this->uid, src.uid, sizeof(uint64_t) * 2) < 0;
	}
};

// This represents a constant, unknown input, or temporary variable/operand (a temporary
// variable can have a required target value, thus also making it an "output" variable).
class COperand
{
public:
	CUniversalId uid;
	
	int operandType;

	// 'bitIndexLabel' is intended to be -1 for all constants.
	// for an input, it identifies the input bit the operand refers to.
	// for a temporary, it's -1 unless it's an output in which case the output bit
	//	refered to is indicated.
	int32_t bitIndexLabel;
	
	// After flattening, temporary operands get their index into 'autoTempOperands'
	// set via this variable.
	int64_t physicalPositionIndex;
	
	// This is 'nullptr' for constant and input operands. For temporary (including
	// "output") operands, this refers to the operator that determines the operand's
	// value. Recall that our operands always have a value of 0 or 1.
	ROperator sourceOp;
	
	// If this is an "output" temporary, the operand's value is to match 'targetOp'.
	// The latter is allowed to be a function only of constants (such as unity or
	// the known input variables); and (in an acyclic way) other temporary operands
	// with a 'targetOp'. This is used for instance to set required outputs.
	ROperator targetOp;
	
	COperand(CCryptosystemBase &csBase, int operandTypeT, int32_t bitIndexLabelT = -1) :
		uid(csBase),
		operandType(operandTypeT),
		bitIndexLabel(bitIndexLabelT),
		physicalPositionIndex(-1LL)
	{
	}
};

class COperatorBase
{
public:
	std::map<CUniversalId, std::pair<ROperand, mpq_class> > childOperands;
	CCryptosystemBase &csBase;
	CUniversalId uid;
	
	struct
	{
		bool visited;
		mpq_class evaluateValue;
	}	flags;
	
	COperatorBase(CCryptosystemBase &csBaseT) :
		csBase(csBaseT),
		uid(csBaseT)
	{
		this->ClearFlags();
	}
	
	virtual ~COperatorBase()
	{
	}
	
	void ClearFlags()
	{
		this->flags.visited = false;

		this->flags.evaluateValue = 0;
	}

	void AddOperand(ROperand src, mpq_class scalar = 1, bool isMod2 = false)
	{
		scalar.canonicalize();
	
		if(scalar == 0)
		{
			return;
		}
		
		if(childOperands.find(src->uid) == childOperands.end())
		{
			childOperands[src->uid].first = src;
			childOperands[src->uid].second = 0;
		}
		
		childOperands[src->uid].second = DoNormalize(childOperands[src->uid].second + scalar, isMod2);
		
		if(childOperands[src->uid].second == 0)
		{
			childOperands.erase(src->uid);
		}
	}
	
protected:	
	mpq_class DoNormalize(mpq_class src, bool isMod2 = false)
	{
		src.canonicalize();
	
		if(isMod2 == true)
		{
			src = mpq_class(src.get_num() % (src.get_den() * 2), src.get_den());
		}
		else
		{
			src = mpq_class(src.get_num() % (src.get_den() * (mpz_class(1) << WORD_SIZE_BITS_MAX/*was 32*/)), src.get_den());
		}
		
		src.canonicalize();
		
		return src;
	}
};

// When we're done constructing all operands and their operator sources have been all assigned,
// the next step is to "flatten" the operators. If operand 'x' has source operator 'y', one can
// form an equation from y's "flattened operator" counterpart. For example we might begin with
//   x0 = (0.5 + 0.5 u) mod 2.
//   x1 = (1 + x0) mod 2
//  In this case, the operand 'x1' has (1 + x0) as its source operator, and it's understood
//  we have to take this value modulo 2 before obtaining x1. The "flattened" version of x1's
//  source operator is then obtained from
//   2 x0 = (1 + u) mod 4		e.g. x0 = (1 + u)/2 mod 2
//   2 x1 = (2 + 2 x0) mod 4		e.g. x1 = (1 + x0)/1 mod 2
//  so we obtain
//   2 x1 = (3 + u) mod 4
//  and finally can write
//   x1 = (3 + u)/2 mod 2.
//  We ensure that for any possible "input" combination, we'll never wind up dividing with a
//  remainder. In fact, the value being divided is either 0 or equal to the divisor at all times.
//  Note: the above can be written as 2 x1 - 3 - u + 4 (lambda) = 0.
//  Note also that if you begin at an operand and then wind up back at an operand with a non-nullptr
//  'targetOp' (but that's not the operator you started with), then we can simply replace the operand
//  with 'targetOp' (provided it's a 0 or 1 literal) in the operator edge that refers to it. A case
//  will already exist for ensuring the former, so this wouldn't affect our solution set.
// Once flattening is done, one has an 'acceptor' and generally doesn't do computations, just checks
// them.
class CFlattenedOperator :
	public COperatorBase
{
public:
	// Our divisor is (1 << divisorShift). The operand we're defining must have a value of precisely
	// (1 << divisorShift) or 0 so that after we right-shift by 'divisorShift', we get 0 or 1 without
	// the possibility of a remainder after dividing. This begins as 0 in the state where child
	// operand coefficients can have a denominator. The intent is that later we can multiply through
	// (by shifting all coefficients left) by some quantity, 'divisorShift'. This also scales the
	// modulo, which becomes a larger power of 2. All denominators are allowed only to be a power of 2.
	uint64_t divisorShift;

	CFlattenedOperator(CCryptosystemBase &cBaseT) :
		COperatorBase(cBaseT),
		divisorShift(0)
	{
	}
};

typedef std::shared_ptr<CFlattenedOperator> RFlattenedOperator;

// When an operator is assigned to an operand, it's generally taken modulo 2. Otherwise, operators
// represent arbitrary-precision "rational" linear equations.
class COperator :
	public COperatorBase
{
public:
	
	std::map<CUniversalId, std::pair<ROperator, mpq_class> > childOperators;
	RFlattenedOperator flattenedVersion;

	COperator(CCryptosystemBase &cBaseT) :
		COperatorBase(cBaseT)
	{
	}

	bool IsZero() const
	{
		return this->childOperators.empty() == true && this->childOperands.empty() == true;
	}
	
	void Add(ROperator src, mpq_class scalar = 1)
	{
		scalar.canonicalize();
	
		if(scalar == 0)
		{
			return;
		}
	
		if(childOperators.find(src->uid) == childOperators.end())
		{
			childOperators[src->uid].first = src;
			childOperators[src->uid].second = 0;
		}
		
		childOperators[src->uid].second = DoNormalize(childOperators[src->uid].second + scalar);
		
		if(childOperators[src->uid].second == 0)
		{
			childOperators.erase(src->uid);
		}
	}
};

class CCryptosystem :
	public CCryptosystemBase
{
public:
	RFlattenedOperator flattenedZero;
	RFlattenedOperator flattenedOne;

	std::vector<ROperand> constantOperands;
	std::vector<ROperand> inputOperands;
	std::vector<ROperand> userOutputOperands;		// these are the output operands created by the user
	
	// Flatten() adds needed 'temporary' operands here. See the operand's 'sourceOp->flattenedVersion' variable.
	std::vector<ROperand> autoTempOperands;
	
	// autoTempOperandOutputPositions[n] provides an index into autoTempOperands for user output operand 'n'.
	std::vector<int64_t> autoTempOperandOutputPositions;

	CCryptosystem(uint32_t wordSizeBitsT = 32);

	virtual ~CCryptosystem();
	
	void UnvisitAll();
	
	ROperator CreateOperator()
	{
		return std::make_shared<COperator>(*this);
	}
	
	ROperator CreateOperator(ROperator src, mpq_class scalar = 1)
	{
		ROperator result = std::make_shared<COperator>(*this);
		
		result->Add(src, scalar);
		
		return result;
	}
	
	ROperator CreateOperator(ROperand src, mpq_class scalar = 1)
	{
		ROperator result = std::make_shared<COperator>(*this);
		
		result->AddOperand(src, scalar);
		
		return result;
	}
	
	ROperand CreateOperand(int operandTypeT, int32_t bitIndexLabelT = -1)
	{
		return std::make_shared<COperand>(*this, operandTypeT, bitIndexLabelT);
	}
	
	// Returns true if successful, false otherwise.
	bool Compute(std::vector<bool> &inputValues, std::vector<bool> &constantValues, std::vector<bool> &outputValues);

	// Returns true if successful, false otherwise.	
	bool Flatten(std::ostream &os);
	
	// Returns true if successful, false otherwise.
	bool FinalizeEquationsBinary(FILE *fo, std::ostream &os);
	
	bool WriteEquationsText(std::ostream &os, bool showUids = false);
	bool WriteEquationsBinary(std::FILE *fo);
	bool CheckEquations(std::ostream &os, std::vector<bool> &savedInputValues, std::vector<bool> &savedConstantValues);

private:
	void DoAddFlattened(RFlattenedOperator dest, RFlattenedOperator src, mpq_class scalar);
	void DoUnvisit(ROperator node);
	void DoFlatten(ROperand rootOperand, ROperator currentNode = nullptr);
	mpq_class DoCompute(ROperator node, std::vector<bool> &inputValues, std::vector<bool> &constantValues, std::vector<bool> &outputValues);
};

// ================================================================================

// This represents a vector of 'CCryptosystemBase::WordSizeBits()' operators, each
// of which is to have a value of 0 or 1. This is managed and used only by CWord.
class CScatterWord
{
public:
	ROperator bits[WORD_SIZE_BITS_MAX];
	
	CScatterWord(CCryptosystemBase &cSystem)
	{
		for(uint32_t i = 0; i < WORD_SIZE_BITS_MAX; ++i)
		{
			this->bits[i] = cSystem.GetZero();
		}
	}
	
	virtual ~CScatterWord()
	{
	}
};

// This represents an "immutable" word of 'CCryptosystemBase::WordSizeBits()' bits.
class CWord
{
	CCryptosystem *cSystem;

	// When the word is used as a whole (e.g. a word), we use this value.
	ROperator gatherNode;
	
	// When we need to access individual [scattered] bits of the word, we use this one.
	std::shared_ptr<CScatterWord> scatterNode;

public:
	CWord() :
		cSystem(nullptr)
	{
	}
	
	// This creates a new word, either initialized to 0 or to an arbitrary literal value.
	CWord(CCryptosystem &cSystemT, mpz_class literalValue = 0) :
		cSystem(&cSystemT)
	{
		mpz_class mask = (mpz_class(1) << cSystemT.WordSizeBits()) - 1;
		literalValue &= mask;

		// Create the variable that's going to store our scattered variables
		// (i.e. individual bits).
		this->scatterNode = std::make_shared<CScatterWord>(cSystemT);

		// Create a new 'gather node' with the indicated value.
		this->gatherNode = cSystemT.CreateOperator();

		if(literalValue != 0)
		{
			//this->gatherNode->AddOperand(cSystemT.GetUnity(), mpq_class(literalValue, mpz_class(1) << 31));
		
			// Let's create the scatter bits as well.
			for(uint32_t i = 0; i < cSystemT.WordSizeBits(); ++i)
			{
				int value = ((literalValue >> i) & 1) != 0;

				this->scatterNode->bits[i] = (value == 0) ? cSystemT.GetZero() : cSystemT.GetOne();
			}
			
			this->DoGather();
		}
	}
	
	virtual ~CWord()
	{
	}

	CWord &operator=(const CWord &src)
	{
		this->cSystem = src.cSystem;
	
		this->scatterNode = src.scatterNode;
		
		this->gatherNode = src.gatherNode;
		
		return *this;
	}
	
	CWord(const CWord &src) :
		cSystem(src.cSystem)
	{
		this->scatterNode = src.scatterNode;
		
		this->gatherNode = src.gatherNode;
	}
	
	ROperator GetBit(uint32_t index) const
	{
		return this->scatterNode->bits[index];
	}

	// Given a gather 'operator' (variable with a full range of allowed values),
	// this returns a new 'CWord' with that given gathered value, and also sets
	// the scatter bits appropriately for that word.
	static CWord Scatter(CCryptosystem &cSystemT, ROperator gatherSrc)
	{
		CWord result(cSystemT);
		
		result.gatherNode = gatherSrc;
		
		result.DoScatter();
		
		return result;
	}
	
	// This returns a new 'CWord' whose value is obtained from the given 'bits' array.
	static CWord Gather(CCryptosystem &cSystemT, ROperator bits[], uint32_t providedWordSizeBits)
	{
		CWord result(cSystemT);
		
		// A new scatter node by default has all bits cleared to 0.
		result.scatterNode = std::make_shared<CScatterWord>(cSystemT);
		
		if(providedWordSizeBits > cSystemT.WordSizeBits())
		{
			providedWordSizeBits = cSystemT.WordSizeBits();
		}
		
		for(uint32_t i = 0; i < providedWordSizeBits; ++i)
		{
			result.scatterNode->bits[i] = bits[i];
		}
		
		result.DoGather();
		
		return result;
	}

	// Given the current word and a second source word, this adds the source times 'scalar' to the current word and returns the sum.
	CWord AddIdentity(CWord srcT, mpz_class scalar = 1) const
	{
		CWord result(*cSystem);
		
		result.gatherNode = cSystem->CreateOperator(this->gatherNode);
		
		result.gatherNode->Add(srcT.gatherNode, scalar);
		
		result.DoScatter();
		
		return result;
	}

	// This is designed specifically for 32-bit lookup tables.
	CWord AddUnary32Bits(CWord src, const uint32_t table[], uint32_t tableSizeBits) const
	{
		ROperator values[WORD_SIZE_BITS_MAX];
		
		for(uint32_t i = 0; i < WORD_SIZE_BITS_MAX; ++i)
		{
			values[i] = cSystem->GetZero();
		}
		
		if(tableSizeBits > cSystem->WordSizeBits())
		{
			tableSizeBits = cSystem->WordSizeBits();
		}
	
		for(uint32_t y = 0; y < tableSizeBits; ++y)
		{
			ROperator temp = cSystem->CreateOperator();	// we start with a new operator of value 0
			
			for(uint32_t x = 0; x < tableSizeBits; ++x)
			{
				uint32_t value = (table[x] >> y) & 1u;
				
				if(value == 0)
				{
					continue;
				}
				
				temp->Add(src.GetBit(x));
			}
			
			// Our final step is to introduce an 'operand' and use its value (i.e. effectively do modulo 2).
			ROperand tempOperand = this->cSystem->CreateOperand(E_OPERAND_TEMP);
			tempOperand->sourceOp = temp;
			
			values[y] = this->cSystem->CreateOperator();
			values[y]->AddOperand(tempOperand);
		}

		CWord result = Gather(*this->cSystem, values, tableSizeBits);
		
		return this->AddIdentity(result);	// return the sum of the current value and the result
	}

private:
	// This is not too exciting, just computes x0 + 2 x1 + 4 x2 + 8 x3 ...
	void DoGather()
	{
		this->gatherNode = this->cSystem->CreateOperator();
	
		for(uint32_t i = 0; i < this->cSystem->WordSizeBits(); ++i)
		{
			this->gatherNode->Add(this->scatterNode->bits[i], mpq_class((mpz_class(1) << i), mpz_class(1) << 31));
		}
	}
	
	// This is the inverse operation of DoGather().
	void DoScatter()
	{
		this->scatterNode = std::make_shared<CScatterWord>(*this->cSystem);
		
		ROperand tempOperand = this->cSystem->CreateOperand(E_OPERAND_TEMP);
		tempOperand->sourceOp = this->cSystem->CreateOperator(this->gatherNode, mpz_class(1) << 31);

		this->scatterNode->bits[0] = this->cSystem->CreateOperator();
		this->scatterNode->bits[0]->AddOperand(tempOperand);
		
		for(uint32_t i = 1; i < this->cSystem->WordSizeBits(); ++i)
		{
			ROperator temp = this->cSystem->CreateOperator(this->gatherNode, mpz_class(1) << (31 - i));
			for(uint32_t j = 0; j < i; ++j)
			{
				temp->Add(this->scatterNode->bits[j], mpq_class(-1, mpz_class(1) << (i - j))); // @
			}
		
			tempOperand = this->cSystem->CreateOperand(E_OPERAND_TEMP);

			tempOperand->sourceOp = this->cSystem->CreateOperator(temp);
			this->scatterNode->bits[i] = this->cSystem->CreateOperator();
			this->scatterNode->bits[i]->AddOperand(tempOperand);
		}
	}
};

// ================================================================================

}	// namespace formal_crypto

#endif	// l_formcrypto_h__included_formal_crypto


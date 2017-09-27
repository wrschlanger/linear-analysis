// formproblem.h - by Willow Schlanger. Released to the Public Domain in August of 2017.
// =========================================================================

#ifndef l_formproblem_h__included_formal
#define l_formproblem_h__included_formal

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <iostream>
#include <string>
#include <vector>
#include <list>

#include <gmpxx.h>

#include <cstdio>

namespace formal_crypto
{

// ========================================================================

class CGenerationOperand
{
public:
	// '1' = unity
	// 'x' = unknown input variable
	// 'c' = constant variable
	// 't' = temporary variable
	uint64_t type : 8;
	
	// For 'x' or 'c' this is the variable label number.
	// For 't' this is the temporary position / equation number.
	uint64_t pos : 64 - 8;
	
	uint64_t GetFullValue() const
	{
		union
		{
			struct
			{
				uint64_t type : 8;
				uint64_t pos : 64 - 8;
			}	s;
			uint64_t x;
		}	u;
		
		u.s.type = type;
		u.s.pos = pos;
		
		return u.x;
	}
};

class CGenerationEquation
{
public:
	// The modulo is (1 << divisorShift). So 1 means we're modulo 4
	// and the equation will have a value of precisely 0 or 2.
	uint64_t divisorShift;
	
	// If true, the equation does not define a new variable but 'must
	// be zero'. Note: this is always 'false' at the time AcceptNextEquation()
	// is called. The user must set this to true if they need it to be valid.
	bool zeroTarget;
	
	std::list<std::pair<CGenerationOperand, mpq_class> > operands;
};

class CProblemAcceptor
{
public:
	virtual ~CProblemAcceptor()  { }
	virtual bool Initialize(std::vector<bool> &constantValues, std::vector<uint64_t> &targetOutputTemps, uint64_t numUnknownInputs, uint64_t numEquations, std::string magicSignature) = 0;
	virtual bool AcceptNextEquation(const CGenerationEquation &equation, int64_t position) = 0;
	virtual bool Finish() = 0;
};

class CProblemReader
{
public:
	// returns true on success, false in case of failure.
	static bool ReadProblem(const char *fn, CProblemAcceptor &acceptor);
};

// ========================================================================

/*	// sample code follows
class CGeneralProblemAcceptor :
	public CProblemAcceptor
{
public:
	virtual ~CGeneralProblemAcceptor()
	{
	}
	
	// returns true on success, false in case of failure.
	virtual bool Initialize(std::vector<bool> &constantValues, std::vector<uint64_t> &targetOutputTemps, uint64_t numUnknownInputs, uint64_t numEquations, std::string magicSignature)
	{
		return true;
	}

	// returns true on success, false in case of failure.
	virtual bool AcceptNextEquation(const CGenerationEquation &equation)
	{
		return true;
	}
	
	virtual bool Finish()
	{
		return true;
	}
};
*/

// ========================================================================

}	// namespace formal_crypto

#endif	// l_formproblem_h__included_formal


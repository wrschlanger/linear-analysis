// formcrypto.cpp - Released to the Public Domain in August of 2017.
// --------------------------------------------------------------------------------
// Formal analysis.
// ================================================================================

#include "formcrypto.h"

#include <cstdio>

namespace formal_crypto
{

#include "ks0.h"
#include "ks1.h"
#include "hs0.h"
#include "hs1.h"

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

uint32_t CUtilSha256::GetInitialH(uint32_t n)	// 0 <= n < 8
{
	return sha256_initial_h[n];
}

uint32_t CUtilSha256::GetEntryK(uint32_t n)		// 0 <= n < 64
{
	return sha256_table_k[n];
}

// This exploits the fact that e.g. ks0(1 ^ 2 ^ 8) = ks0(1) ^ ks0(2) ^ ks0(8)
// together with the fact that ks0(0) = 0.
inline uint32_t Comp32Lookup(uint32_t table[32], uint32_t value)
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

const uint32_t *CUtilSha256::GetTableHs0()
{
	return table_hs0;
}

const uint32_t *CUtilSha256::GetTableHs1()
{
	return table_hs1;
}

const uint32_t *CUtilSha256::GetTableKs0()
{
	return table_ks0;
}

const uint32_t *CUtilSha256::GetTableKs1()
{
	return table_ks1;
}

uint32_t CUtilSha256::Comp32Hs0(uint32_t x)
{
	return Comp32Lookup(table_hs0, x);
}

uint32_t CUtilSha256::Comp32Hs1(uint32_t x)
{
	return Comp32Lookup(table_hs1, x);
}

uint32_t CUtilSha256::Comp32Ks0(uint32_t x)
{
	return Comp32Lookup(table_ks0, x);
}

uint32_t CUtilSha256::Comp32Ks1(uint32_t x)
{
	return Comp32Lookup(table_ks1, x);
}

// numRounds shall be a multiple of 8, with 64 being the full standard.
void CUtilSha256::CompSha256(uint32_t h_entry[8], const uint32_t w_entry[16], uint32_t numRounds /*= 64*/)
{
	enum { A, B, C, D, E, F, G, H };

	uint32_t w[64];

	uint32_t h[8];

	for(uint32_t i = 0; i < 16; ++i)
	{
		w[i] = w_entry[i];
	}

	for(uint32_t i = 16; i < 64; ++i)
	{
		w[i] = w[i - 16] + Comp32Ks0(w[(i + 1) - 16]) + w[(i + 9) - 16] + Comp32Ks1(w[(i + 14) - 16]);
	}

	for(uint32_t i = 0; i < 8; ++i)
	{
		h[i] = h_entry[i];
	}

	for(uint32_t i = 0; i < numRounds; ++i)
	{
#undef VAR
#define VAR(x) h[((x) - i) & 7]
		VAR(H) += Comp32Hs1(VAR(E)) + Comp32Ch(VAR(E), VAR(F), VAR(G)) + sha256_table_k[i] + w[i];

		VAR(D) += VAR(H);

		VAR(H) += Comp32Hs0(VAR(A)) + Comp32Maj(VAR(A), VAR(B), VAR(C));
#undef VAR
	}

	for(uint32_t i = 0; i < 8; ++i)
	{
		h_entry[i] += h[i];
	}
}

void CUtilSha256::WriteH(std::ostream &os, uint32_t h[8], bool cStyle /*= false*/)
{
	for(uint32_t i = 0; i < 8; ++i)
	{
		char s[32 + 1];

		std::sprintf(s, "%08X", (unsigned int)(h[i]));

		if(cStyle == true)
		{
			os << "0x";
		}
		os << s;
		
		if(i != 7)
		{
			if(cStyle == true)
				os << ",";
			else
				os << " ";
		}
	}        
	os << std::endl;
}

void CUtilSha256::SelfTest(std::ostream &os, uint32_t numRounds /*= 64*/)
{
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
        
        CompSha256(h, w);

	os << "4092FEF0 263500F6 48BD3A9B E8A5BEE6 F662B089 96D7DCE6 30390A6E 51EFD3EA [8]\n";
	os << "F6FEA097 241DA176 018401FD 7029A783 74866420 4242CAF1 86B6906D 7E3EF42F [16]\n";
	os << "C5D60ADA 8ADCF131 1DA993BC A1460DBC 493C24FA 11145185 9F3F5F47 3CA160F8 [24]\n";
	os << "5C1DE77E E5C56410 F9937A39 BF5F5F4C D6E5F802 1A8FB422 72401439 A94AB795 [32]\n";
	os << "85454A4A BB363DB5 F69AEA15 28588B34 3B1B5DCF D330022C 63FDD7F5 2535D2F4 [40]\n";
	os << "FBD318B4 C80A34D1 289D43E4 2B400C18 8BC0FE27 F292BC76 6702F299 A7D043E8 [48]\n";
	os << "3407105C 0B72A53B F02BCE70 E9603A20 41541D57 81AEFD0D 3355EFF2 35F375C9 [56]\n";
	os << "9F86D081 884C7D65 9A2FEAA0 C55AD015 A3BF4F1B 2B0B822C D15D6C15 B0F00A08 [64]\n" << std::endl;
	
	WriteH(os, h);
}

// ================================================================================

CCryptosystem::CCryptosystem(uint32_t wordSizeBitsT /*= 32*/) :
	CCryptosystemBase(wordSizeBitsT)
{
	// Let's create our "unity" constant operand.
	this->unity = std::make_shared<COperand>(*this, E_OPERAND_CONSTANT, this->constantOperands.size());
	this->constantOperands.push_back(this->unity);

	this->zero = std::make_shared<COperator>(*this);
	
	this->one = std::make_shared<COperator>(*this);
	this->one->AddOperand(this->unity, 1);		// do any Add() calls only after setting this->zero in this constructor
	
	this->flattenedZero = std::make_shared<CFlattenedOperator>(*this);
	this->flattenedOne = std::make_shared<CFlattenedOperator>(*this);
	this->flattenedOne->AddOperand(this->unity, 1);
}

CCryptosystem::~CCryptosystem()
{
}

void CCryptosystem::UnvisitAll()
{
	for(uint64_t n = 0; n < this->userOutputOperands.size(); ++n)
	{
		this->DoUnvisit(this->userOutputOperands[n]->sourceOp);
		this->DoUnvisit(this->userOutputOperands[n]->targetOp);
	}
	for(uint64_t n = 0; n < this->autoTempOperands.size(); ++n)
	{
		this->DoUnvisit(this->autoTempOperands[n]->sourceOp);
		this->DoUnvisit(this->autoTempOperands[n]->targetOp);
	}
}

void CCryptosystem::DoUnvisit(ROperator node)
{
	if(node == nullptr || node->flags.visited == false)
	{
		return;
	}
	
	node->ClearFlags();

	if(node->flattenedVersion != nullptr)
	{
		node->flattenedVersion->ClearFlags();
	}
	
	for(std::map<CUniversalId, std::pair<ROperator, mpq_class> >::iterator i = node->childOperators.begin();
		i != node->childOperators.end();
		++i
	)
	{
		this->DoUnvisit(i->second.first);
	}
	
	for(std::map<CUniversalId, std::pair<ROperand, mpq_class> >::iterator i = node->childOperands.begin();
		i != node->childOperands.end();
		++i
	)
	{
		this->DoUnvisit(i->second.first->sourceOp);

		this->DoUnvisit(i->second.first->targetOp);
	}
}

// Returns true if successful, false otherwise.
bool CCryptosystem::Compute(std::vector<bool> &inputValues, std::vector<bool> &constantValues, std::vector<bool> &outputValues)
{
	try
	{
		for(uint64_t n = 0; n < this->userOutputOperands.size(); ++n)
		{
			if(n >= outputValues.size())
			{
				break;
			}
		
			ROperator src = this->userOutputOperands[n]->sourceOp;
		
			if(src == nullptr)
			{
				throw std::runtime_error("CCryptosystem::Compute(): unspecified source operator.");
			}
		
			mpq_class temp = this->DoCompute(src, inputValues, constantValues, outputValues);
			
			if(temp.get_den() != 1)
			{
				throw std::runtime_error("CCryptosystem::Compute(): Unable to evaluate output operand.");
			}
			
			outputValues[n] = (temp.get_num() % 2) != 0;
		}
	}
	catch(std::runtime_error &e)
	{
		this->UnvisitAll();

		//@std::cout << "CCryptosystem::Compute(): " << e.what() << std::endl;	// uncomment to assist with debugging

		return false;
	}

	this->UnvisitAll();

	return true;
}

mpq_class CCryptosystem::DoCompute(ROperator node, std::vector<bool> &inputValues, std::vector<bool> &constantValues, std::vector<bool> &outputValues)
{
	if(node->flags.visited == false)
	{
		node->flags.visited = true;
		mpq_class value = 0;
		
		for(std::map<CUniversalId, std::pair<ROperator, mpq_class> >::iterator i = node->childOperators.begin();
			i != node->childOperators.end();
			++i
		)
		{
			value += i->second.second * this->DoCompute(i->second.first, inputValues, constantValues, outputValues);
		}
		
		for(std::map<CUniversalId, std::pair<ROperand, mpq_class> >::iterator i = node->childOperands.begin();
			i != node->childOperands.end();
			++i
		)
		{
			ROperand oper = i->second.first;
			
			if(oper->sourceOp != nullptr)
			{
				mpq_class temp = this->DoCompute(oper->sourceOp, inputValues, constantValues, outputValues);
				
				if(temp.get_den() != 1)
				{
					//@std::cout << "\n" << temp << std::endl;//@
				
					throw std::runtime_error("Evaluate error A");
				}

				value += i->second.second * (temp.get_num() % 2);
			}
			else if(oper->operandType == E_OPERAND_INPUT)
			{
				if(oper->bitIndexLabel == -1)
				{
					throw std::runtime_error("Evaluate error C");
				}
				
				value += i->second.second * (int)inputValues[oper->bitIndexLabel];
			}
			else if(oper->operandType == E_OPERAND_CONSTANT)
			{
				if(oper->bitIndexLabel == -1)
				{
					throw std::runtime_error("Evaluate error D");
				}
				
				value += i->second.second * (int)constantValues[oper->bitIndexLabel];
			}
			else
			{
				throw std::runtime_error("Evaluate error B");
			}
		}
		
		node->flags.evaluateValue = value;
	}
	
	return node->flags.evaluateValue;
}

// ================================================================================

void CCryptosystem::DoAddFlattened(RFlattenedOperator dest, RFlattenedOperator src, mpq_class scalar)
{
	if(scalar == 0)
	{
		return;
	}

	for(std::map<CUniversalId, std::pair<ROperand, mpq_class> >::iterator i = src->childOperands.begin();
		i != src->childOperands.end();
		++i
	)
	{
		if(i->second.second != 0)
		{
			dest->AddOperand(i->second.first, i->second.second * scalar, true);
		}
	}
}

void CCryptosystem::DoFlatten(ROperand rootOperand, ROperator node /*= nullptr*/)
{
	if(node == nullptr)
	{
		node = rootOperand->sourceOp;
		
		if(node == nullptr)
		{
			throw std::runtime_error("nullptr exception A");
		}
	}
	
	if(node->flags.visited == true)
	{
		return;
	}
	
	node->flags.visited = true;
	
	RFlattenedOperator flattenedOp = std::make_shared<CFlattenedOperator>(*this);
	
	// Recurse child operators.
	for(std::map<CUniversalId, std::pair<ROperator, mpq_class> >::iterator i = node->childOperators.begin();
		i != node->childOperators.end();
		++i
	)
	{
		this->DoFlatten(rootOperand, i->second.first);
		
		this->DoAddFlattened(flattenedOp, i->second.first->flattenedVersion, i->second.second);
	}

	// Recurse child operands.
	for(std::map<CUniversalId, std::pair<ROperand, mpq_class> >::iterator i = node->childOperands.begin();
		i != node->childOperands.end();
		++i
	)
	{
		ROperand oper = i->second.first;
		
		if(oper->sourceOp != nullptr)
		{
			if(oper->targetOp == nullptr)
			{
				// This is NOT a 'root' node. Recurse!
				this->DoFlatten(rootOperand, oper->sourceOp);
				
				if(oper->physicalPositionIndex == -1LL)
				{
					oper->physicalPositionIndex = this->autoTempOperands.size();
					this->autoTempOperands.push_back(oper);
				}
				
				// Add operand itself to our flattened expression.
				flattenedOp->AddOperand(oper, i->second.second, true);
			}
			else
			{
				// This is a 'root' output node, i.e. a node with a known target value.
				this->DoFlatten(rootOperand, oper->targetOp);
				
				this->DoAddFlattened(flattenedOp, oper->targetOp->flattenedVersion, i->second.second);
			}
		}
		else
		{
			// This is an input or constant (not temp/output) operand.
			flattenedOp->AddOperand(oper, i->second.second, true);
		}
	}
	
	node->flattenedVersion = flattenedOp;
}

// Returns true if successful, false otherwise.
bool CCryptosystem::Flatten(std::ostream &os)
{
	autoTempOperandOutputPositions.clear();
	autoTempOperandOutputPositions.resize(userOutputOperands.size(), -1LL);
	autoTempOperands.clear();

	try
	{
		for(uint64_t n = 0; n < this->userOutputOperands.size(); ++n)
		{
			ROperator src = this->userOutputOperands[n]->sourceOp;
		
			if(src == nullptr)
			{
				throw std::runtime_error("CCryptosystem::Flatten(): Error: unspecified source operator.");
				return false;
			}
			
			// TODO check that src->targetOp is not null here?
			
			this->DoFlatten(this->userOutputOperands[n]);

			autoTempOperandOutputPositions[n] = autoTempOperands.size();
			
			this->userOutputOperands[n]->physicalPositionIndex = this->autoTempOperands.size();
			
			autoTempOperands.push_back(this->userOutputOperands[n]);
		}
	}
	catch(std::runtime_error &e)
	{
		this->UnvisitAll();
		
		os << "\nCCryptosystem::Flatten(): Error: " << e.what() << std::endl;

		return false;
	}

	this->UnvisitAll();
	
	return true;
}

// Returns true if successful, false in case of failure.
bool CCryptosystem::CheckEquations(std::ostream &os, std::vector<bool> &savedInputValues, std::vector<bool> &savedConstantValues)
{
	std::vector<bool> tempValues(autoTempOperands.size(), 1);	// initialize all values to 1 just because we're trying to make 0s
	std::vector<bool> knownValue(autoTempOperands.size(), false);
	uint64_t targetCount = 0;

	for(uint64_t n = 0; n < this->autoTempOperands.size(); ++n)
	{
		if(this->autoTempOperands[n] == nullptr || this->autoTempOperands[n]->sourceOp == nullptr || this->autoTempOperands[n]->sourceOp->flattenedVersion == nullptr)
		{
			os << "\nCCryptosystem::CheckEquations(): nullptr encountered" << std::endl;
			
			return false;
		}
		
		mpz_class divisor = (mpz_class(1) << this->autoTempOperands[n]->sourceOp->flattenedVersion->divisorShift);
		
		if(divisor != 1)
		{
			os << "\nCCryptosystem::CheckEquations(): divisor of " << divisor << " found (not supported)" << std::endl;
			
			return false;
		}
		
		uint64_t defPos = this->autoTempOperands[n]->physicalPositionIndex;
		
		if(defPos != n)
		{
			os << "\nCCryptosystem::CheckEquations(): defined position mismatch!" << std::endl;
			
			return false;
		}
		
		if(defPos >= tempValues.size())
		{
			os << "\nCCryptosystem::CheckEquations(): variable position out of bounds (!) " << defPos << " >= " << tempValues.size() << std::endl;
			
			return false;
		}
		
		mpq_class value = 0;
		
		for(auto iter = this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.begin();
			iter != this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.end();
			++iter
		)
		{
			if(iter->second.first->uid == this->unity->uid)
				value += iter->second.second;
			else
			if(iter->second.first->operandType == E_OPERAND_INPUT)
			{
				if(savedInputValues[iter->second.first->bitIndexLabel] != 0)
					value += iter->second.second;
			}
			else if(iter->second.first->operandType == E_OPERAND_CONSTANT)
			{
				if(savedConstantValues[iter->second.first->bitIndexLabel] != 0)
					value += iter->second.second;
			}
			else
			{
				if(iter->second.first->physicalPositionIndex == -1LL)
				{
					os << "\nCCryptosystem::CheckEquations(): reference to variable with unknown physical position." << std::endl;
					
					return false;
				}
				
				if(iter->second.first->physicalPositionIndex >= defPos)
				{
					os << "\nCCryptosystem::CheckEquations(): reference to variable with disallowed physical position." << std::endl;
					
					return false;
				}
				
				if(knownValue[iter->second.first->physicalPositionIndex] == false)
				{
					os << "\nCCryptosystem::CheckEquations(): attempt to access unknown variable at position " << iter->second.first->physicalPositionIndex << std::endl;
					
					return false;
				}
				
				if(tempValues[iter->second.first->physicalPositionIndex] != 0)
					value += iter->second.second;
			}
		}
		
		if(value.get_den() != 1)
		{
			os << "\nCCryptosystem::CheckEquations(): obtained a fractional value of " << value << std::endl;
			
			return false;
		}
		
		// theory: I don't think 'value' can be negative here. TODO: Check?
		/*
		if(value.get_num() < 0)
		{
			os << "\n?? Negative value detected." << std::endl;

			return false;
		}
		*/

		tempValues[defPos] = ((value.get_num() % 2) != 0);	// +/- 1 after modulo 2 (nonzero) means 1 (!)
		knownValue[defPos] = true;

		bool checked = false;
		bool ok = false;

		if(this->autoTempOperands[n]->targetOp != nullptr)
		{
			if(this->autoTempOperands[n]->targetOp->uid == this->zero->uid)
			{
				checked = true;
				ok = (tempValues[defPos] == 0);
			}
			else if(this->autoTempOperands[n]->targetOp->uid == this->one->uid)
			{
				checked = true;
				ok = (tempValues[defPos] != 0);
			}
			else
			{
				os << "\nCCryptosystem::CheckEquations(): unable to check equations, complex target (not precisely the 0 or 1 operator)" << std::endl;

				return false;
			}
		}
		
		/*
		if(checked)
		{
			++targetCount;
			if(ok)  os << "+"; else os << "_";
			if(!ok)
			{
				os << " " << value << " vs. " << (!(value.get_num().get_ui() % 2)) << std::endl;
			}
		}
		*/
		
		if(checked)
		{
			++targetCount;
		}
		
		if(checked == true && ok == false)
		{
			os << "\nCCryptosystem::CheckEquations(): test fail." << std::endl;
			return false;
		}
	}
	
	//os << "\n" << targetCount << std::endl;
	
	os << "CCryptosystem::CheckEquations(): computed " << targetCount << " correct output bit(s). All OK!" << std::endl;

	return true;	// indicate success
}

// Returns true if successful, false in case of failure.
static bool DoWriteEquationsCollect(std::vector<int64_t> &newPos, std::vector<int64_t> &oldPos, int64_t pos, CCryptosystem *pCs)
{
	if(pos < 0)
	{
		return false;
	}
	
	if(newPos[pos] != -1LL)
	{
		return true;		// already visited this node
	}
	
	for(auto iter = pCs->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.begin();
		iter != pCs->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.end();
		++iter
	)
	{
		if(iter->second.first->uid == pCs->GetUnity()->uid)  continue;
		
		if(iter->second.first->operandType == E_OPERAND_INPUT)  continue;
		
		if(iter->second.first->operandType == E_OPERAND_CONSTANT)  continue;
		
		if(iter->second.first->physicalPositionIndex == -1LL)
		{
			return false;
		}
		
		if(iter->second.first->physicalPositionIndex >= pos)
		{
			return false;
		}
		
		if(DoWriteEquationsCollect(newPos, oldPos, iter->second.first->physicalPositionIndex, pCs) == false)
		{
			return false;
		}
	}
	
	newPos[pos] = oldPos.size();
	oldPos.push_back(pos);
	
	return true;
}

// Returns true if successful, false in case of failure.
bool CCryptosystem::WriteEquationsBinary(std::FILE *fo)
{
	std::vector<int64_t> newPos(this->autoTempOperands.size(), -1LL);
	std::vector<int64_t> oldPos;
	
	for(uint64_t i = 0; i < this->autoTempOperandOutputPositions.size(); ++i)
	{
		if(DoWriteEquationsCollect(newPos, oldPos, this->autoTempOperandOutputPositions[i], this) == false)
		{
			return false;
		}
	}
	
	using namespace std;
	
	// Write 'targets ' vector, which contains the temporary node numbers for each of our 'user outputs', in order.
	// These are the output H bits, with 0s substituted for the ones we don't care about.
	uint64_t x = 0;
	x = 8 + 8 + this->autoTempOperandOutputPositions.size() * 8;
	fwrite(&x, sizeof(uint64_t), 1, fo);
	memcpy(&x, "targets ", 8);
	fwrite(&x, sizeof(uint64_t), 1, fo);
	for(uint64_t i = 0; i < this->autoTempOperandOutputPositions.size(); ++i)
	{
		x = newPos[this->autoTempOperandOutputPositions[i]];
		fwrite(&x, sizeof(uint64_t), 1, fo);
	}
	
	// Write the number of equations. This is also the number of temporaries. Each of these is numbered, starting with 0.
	// If a position matches
	x = oldPos.size();
	fwrite(&x, sizeof(uint64_t), 1, fo);
	
	for(uint64_t i = 0; i < oldPos.size(); ++i)
	{
		uint64_t pos = oldPos[i];
		x = i;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write equation position number, to help sure we stay on track...
		
		x = this->autoTempOperands[pos]->sourceOp->flattenedVersion->divisorShift;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write out our divisor shift (will always be 0 in files we generate)
							// the modulo is 2 << (this value) and the temporary value is to be 0
							// or 1 << (this value) depending on its inputs [i.e. for equations
							// we generate, 0 or 1 precisely and we're modulo 2].
		
		x = this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.size();
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write number of child operands (!)
		
		for(auto iter = this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.begin();
			iter != this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.end();
			++iter
		)
		{
			std::string coeff = iter->second.second.get_str();
			fwrite(coeff.c_str(), coeff.size(), 1, fo);
			char c = '\0';
			fwrite(&c, 1, 1, fo);
			
			if(iter->second.first->uid == this->GetUnity()->uid)
			{
				c = '1';
				fwrite(&c, 1, 1, fo);
			}
			else if(iter->second.first->operandType == E_OPERAND_INPUT)
			{
				c = 'x';	// 'unknown input' variable
				fwrite(&c, 1, 1, fo);
				x = iter->second.first->bitIndexLabel;
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else if(iter->second.first->operandType == E_OPERAND_CONSTANT)
			{
				c = 'c';	// 'constant' variable
				fwrite(&c, 1, 1, fo);
				x = iter->second.first->bitIndexLabel;
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else if(iter->second.first->physicalPositionIndex != -1LL)
			{
				c = 't';	// 'temporary' variable
				fwrite(&c, 1, 1, fo);
				x = newPos[iter->second.first->physicalPositionIndex];
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else
			{
				return false;
			}
		}
	}
	
	// Write end marker, for synchronization purposes (so we can make sure we read everything properly).
	memcpy(&x, "endend  ", 8);
	fwrite(&x, sizeof(uint64_t), 1, fo);

	return true;
}

// Returns true if successful, false in case of failure.
bool CCryptosystem::FinalizeEquationsBinary(FILE *fo, std::ostream &os)
{
	os << "Finalizing equations..." << std::endl;

	// Write 'targets ' vector, which contains the temporary node numbers for each of our 'user outputs', in order.
	// These are the output H bits, with 0s substituted for the ones we don't care about.
	uint64_t x = 0;
	x = 8 + 8 + this->autoTempOperandOutputPositions.size() * 8;
	fwrite(&x, sizeof(uint64_t), 1, fo);
	memcpy(&x, "targets ", 8);
	fwrite(&x, sizeof(uint64_t), 1, fo);
	for(uint64_t i = 0; i < this->autoTempOperandOutputPositions.size(); ++i)
	{
		x = this->autoTempOperandOutputPositions[i];
		fwrite(&x, sizeof(uint64_t), 1, fo);
	}
	
	// Write 0 here. This would normally be the number of equations, but 0 indicates the following field is that number and
	// our equations are to be in reverse!
	x = 0;
	fwrite(&x, sizeof(uint64_t), 1, fo);
	
	// Write the number of equations. This is also the number of temporaries. Each of these is numbered, starting with 0.
	// If a position matches
	x = this->autoTempOperands.size();
	fwrite(&x, sizeof(uint64_t), 1, fo);
	
	for(int64_t n = this->autoTempOperands.size() - 1; n >= 0; --n)
	{
		os << "\r" << (this->autoTempOperands.size() - 1 - n) << "/" << (this->autoTempOperands.size() - 1) << std::flush;
	
		if(this->autoTempOperands[n] == nullptr)
		{
			os << "\nFailure with finalize: nullptr detected!" << std::endl;

			return false;
		}
		
		mpz_class divisor = (mpz_class(1) << this->autoTempOperands[n]->sourceOp->flattenedVersion->divisorShift);
		
		if(divisor != 1)
		{
			os << "\nFailure with finalize: non-unity divisor detected!" << std::endl;
			
			return false;
		}
		
		std::map<uint64_t, std::pair<ROperand, mpz_class> > removedTerms;

		for(auto iter = this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.begin();
			iter != this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.end();
		)
		{
			auto next = iter;
			++next;
			
			iter->second.second.canonicalize();
			
			if(iter->second.second == 0)
			{
				this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.erase(iter);
				iter = next;
				continue;
			}
			
			if(iter->second.first->uid == this->unity->uid)
				;	// unity
			else if(iter->second.first->operandType == E_OPERAND_INPUT)
				;	// unknown (to the code-breaker) input variable
			else if(iter->second.first->operandType == E_OPERAND_CONSTANT)
				;	// known (to at "code-breaking time") constant variable
			else if(iter->second.second.get_den() == 1)
			{
				// this coefficient applies to a temporary and has a unity denominator.
				
				if(iter->second.first->physicalPositionIndex == -1LL)
				{
					os << "\nFailure with finalize: unknown physical position index for an operand!" << std::endl;
					
					return false;
				}
				
				if(removedTerms.find(iter->second.first->physicalPositionIndex) != removedTerms.end())
				{
					os << "\nFailure with finalize: duplicate operand (with the same physical position index)!" << std::endl;
					
					return false;
				}
				
				removedTerms[iter->second.first->physicalPositionIndex] = std::pair<ROperand, mpz_class>(iter->second.first, iter->second.second.get_num());
				
				this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.erase(iter);
				iter = next;
				continue;
			}
			
			iter = next;
		}
		
		// If we removed at least one unity-coefficient term, let's substitute it/them back with their definition.
		while(removedTerms.empty() == false)
		{
			auto riter = --removedTerms.end();
		
			mpz_class scalar = riter->second.second;
			
			uint64_t m = riter->first;
			
			removedTerms.erase(riter);
			
			if(scalar == 0)  continue;
			
			for(auto iter = this->autoTempOperands[m]->sourceOp->flattenedVersion->childOperands.begin();
				iter != this->autoTempOperands[m]->sourceOp->flattenedVersion->childOperands.end();
				++iter
			)
			{
				if(iter->second.first->uid == this->unity->uid || iter->second.first->operandType == E_OPERAND_INPUT || iter->second.first->operandType == E_OPERAND_CONSTANT ||
					iter->second.second.get_den() != 1
				)
				{
					// This is a coefficient we're free to add in: it's not a temp with a unity denominator
					this->autoTempOperands[n]->sourceOp->flattenedVersion->AddOperand(iter->second.first, iter->second.second * scalar, true);
				}
				else
				{
					if(removedTerms.find(iter->second.first->physicalPositionIndex) == removedTerms.end())
					{
						removedTerms[iter->second.first->physicalPositionIndex] = std::pair<ROperand, mpz_class>(iter->second.first, iter->second.second.get_num() * scalar);
					}
					else
					{
						mpz_class temp = (removedTerms[iter->second.first->physicalPositionIndex].second + iter->second.second.get_num() * scalar) % 2;
						
						removedTerms[iter->second.first->physicalPositionIndex].second = temp;
					}
				}
			}
		}
		
		uint64_t pos = n;
		x = n;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write equation position number, to help sure we stay on track...
		
		x = this->autoTempOperands[pos]->sourceOp->flattenedVersion->divisorShift;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write out our divisor shift (will always be 0 in files we generate)
							// the modulo is 2 << (this value) and the temporary value is to be 0
							// or 1 << (this value) depending on its inputs [i.e. for equations
							// we generate, 0 or 1 precisely and we're modulo 2].
		
		x = this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.size();
		fwrite(&x, sizeof(uint64_t), 1, fo);	// write number of child operands (!)
		
		for(auto iter = this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.begin();
			iter != this->autoTempOperands[pos]->sourceOp->flattenedVersion->childOperands.end();
			++iter
		)
		{
			std::string coeff = iter->second.second.get_str();
			fwrite(coeff.c_str(), coeff.size(), 1, fo);
			char c = '\0';
			fwrite(&c, 1, 1, fo);
			
			if(iter->second.first->uid == this->GetUnity()->uid)
			{
				c = '1';
				fwrite(&c, 1, 1, fo);
			}
			else if(iter->second.first->operandType == E_OPERAND_INPUT)
			{
				c = 'x';	// 'unknown input' variable
				fwrite(&c, 1, 1, fo);
				x = iter->second.first->bitIndexLabel;
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else if(iter->second.first->operandType == E_OPERAND_CONSTANT)
			{
				c = 'c';	// 'constant' variable
				fwrite(&c, 1, 1, fo);
				x = iter->second.first->bitIndexLabel;
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else if(iter->second.first->physicalPositionIndex != -1LL)
			{
				c = 't';	// 'temporary' variable
				fwrite(&c, 1, 1, fo);
				x = iter->second.first->physicalPositionIndex;
				fwrite(&x, sizeof(uint64_t), 1, fo);
			}
			else
			{
				return false;
			}
		}

		// reclaim memory (we won't be needing this equation anymore).
		this->autoTempOperands[n]->sourceOp->flattenedVersion = nullptr;
	}

	// Write end marker, for synchronization purposes (so we can make sure we read everything properly).
	memcpy(&x, "endend  ", 8);
	fwrite(&x, sizeof(uint64_t), 1, fo);
	
	os << "\nDone finalizing.\n" << std::endl;
	return true;
}

// Returns true if successful, false in case of failure.
bool CCryptosystem::WriteEquationsText(std::ostream &os, bool showUids /*= false*/)
{
	// Write out the equations describing our flattened system. This represents a directed 'acyclic' graph.
	os << "CCryptosystem::Flatten(): We have " << autoTempOperands.size() << " total operand(s)." << std::endl;
	for(uint64_t n = 0; n < this->autoTempOperands.size(); ++n)
	{
		mpz_class modulo = 2;
		mpz_class divisor = 1;
		
		if(this->autoTempOperands[n] != nullptr)
		{
			divisor = (mpz_class(1) << this->autoTempOperands[n]->sourceOp->flattenedVersion->divisorShift);
		}
		
		if(divisor != 1)
		{
			os << "(" << divisor << ") ";
		}
		
		os << "t[" << this->autoTempOperands[n]->physicalPositionIndex;
		if(showUids == true)
		{
			char s[256];
			s[255] = 0;
			std::sprintf(s, "%016llx%016llx", (unsigned long long)(this->autoTempOperands[n]->uid.Get(1)), (unsigned long long)(this->autoTempOperands[n]->uid.Get(0)));
			os << "@" << s;
		}
		os << "] = (";
		
		if(this->autoTempOperands[n] == nullptr)
		{
			os << "<nullptr>";
		}
		else
		{
			modulo = (mpz_class(2) << this->autoTempOperands[n]->sourceOp->flattenedVersion->divisorShift);
			
			bool needPlus = false;
			
			for(auto iter = this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.begin();
				iter != this->autoTempOperands[n]->sourceOp->flattenedVersion->childOperands.end();
				++iter
			)
			{
				if(needPlus)  os << " + ";
				
				os << "(" << iter->second.second << ")";
				
				// write operand
				if(iter->second.first->uid == this->unity->uid)
					;
				else
				if(iter->second.first->operandType == E_OPERAND_INPUT)
				{
					os << " x[" << iter->second.first->bitIndexLabel << "]";
				}
				else if(iter->second.first->operandType == E_OPERAND_CONSTANT)
				{
					os << " c[" << iter->second.first->bitIndexLabel << "]";
				}
				else
				{
					os << " t[";
					if(iter->second.first->physicalPositionIndex == -1LL)
					{
						os << "<unknown>";
						
						char s[256];
						s[255] = 0;
						std::sprintf(s, "%016llx%016llx", (unsigned long long)(iter->second.first->uid.Get(1)), (unsigned long long)(iter->second.first->uid.Get(0)));
						
						os << "@" << s;
					}
					else
					{
						os << iter->second.first->physicalPositionIndex;
						
						if(iter->second.first->physicalPositionIndex >= this->autoTempOperands[n]->physicalPositionIndex)
						{
							os << std::endl;
							
							std::cerr << "\nFatal: variable used before being defined." << std::endl;
							
							return false;
						}
					}
					os << "]";
				}

				needPlus = true;
			}

			if(needPlus == false)  os << "0";
		}
		
		os << ") mod " << modulo;
		
		if(this->autoTempOperands[n]->targetOp != nullptr)
		{
			if(this->autoTempOperands[n]->targetOp->uid == this->zero->uid)
			{
				os << " = 0";
			}
			else if(this->autoTempOperands[n]->targetOp->uid == this->one->uid)
			{
				os << " = " << divisor;		// would be = 1, but we shifted everything left
			}
			else
			{
				os << " = (known)";
			}
		}
		
		os << std::endl;
	}

	return true;
}

// ================================================================================

}	// namespace formal_crypto


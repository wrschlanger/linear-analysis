// formproblem.cpp - Released to the Public Domain in August of 2017.
// ===========================================================================

#include "formproblem.h"

namespace formal_crypto
{

// ========================================================================

// returns true on success, false in case of failure.
bool CProblemReader::ReadProblem(const char *fn, CProblemAcceptor &acceptor)
{
	using namespace std;
	
	FILE *fi = fopen(fn, "rb");
	if(fi == nullptr)
	{
		std::cerr << "\nFatal: unable to open file for reading: " << fn << std::endl;
		
		return false;
	}
	
	uint64_t fsize = 0;
	if(fread(&fsize, sizeof(uint64_t), 1, fi) != 1 || fsize < 8)
	{
		fclose(fi);
		std::cerr << "\nFatal: invalid file format: " << fn << std::endl;

		return false;
	}
	
	std::cout << "Reading " << (fsize + 1024 * 1024 - 1) / (1024 * 1024) << " MB from " << fn << "... " << std::flush;
	
	uint64_t *data = new uint64_t [(fsize + 7) / 8];
	
	rewind(fi);
	if(fread(data, fsize, 1, fi) != 1)
	{
		fclose(fi);
	
		delete [] data;
		
		std::cout << "fail!" << std::endl;

		return false;
	}
	
	std::cout << "done" << std::endl;
	
	fclose(fi);

	const uint8_t *rawdata = (const uint8_t *)(data);

	char magic[17] = {0};
	memcpy(magic, rawdata + 8, 16);
	
	if(memcmp(magic, "sha256x2", 8) != 0)
	{
		std::cout << "Warning: magic signature not recognized: " << magic << std::endl;
	}
	else
	{
		std::cout << "Magic signature: " << magic << std::endl;
	}
	
	rawdata += 8 + 16;
	
	uint64_t numUnknownBits = *(const uint64_t *)(rawdata);
	rawdata += 8;
	
	std::cout << "Number of unknown bits: " << numUnknownBits << std::endl;
	
	uint64_t constantVectorSizeBytes = *(const uint64_t *)(rawdata);

	// note: constant number 0 is always 1 (it's where our 'unity' operand value lives).
	uint64_t numConstantItems = (constantVectorSizeBytes - 8 - 8) / 8;
	
	std::vector<bool> constantValues(numConstantItems, 0);
	
	for(uint64_t i = 0; i < numConstantItems; ++i)
	{
		uint64_t value = *(const uint64_t *)(rawdata + 8 + 8 + 8 * i);
		
		constantValues[i] = (value != 0);
	}
	
	std::cout << "Number of constant bits: " << constantValues.size() << std::endl;

	rawdata += constantVectorSizeBytes;
	
	rawdata += 8;	// skip equations atom size
	
	uint64_t equatns8cc = *(const uint64_t *)(rawdata);
	
	if(memcmp(&equatns8cc, "equatns ", 8) != 0)
	{
		delete [] data;
		
		std::cerr << "\nFile format error (missing or misplaced 'equatns ' atom): " << fn << std::endl;
		
		return false;
	}
	
	rawdata += 8;
	
	// Our next step is to read in the equations, themselves!
	
	uint64_t targetsSizeBytes = *(const uint64_t *)(rawdata);
	
	uint64_t targets8cc = *(const uint64_t *)(rawdata + 8);
	if(memcmp(&targets8cc, "targets ", 8) != 0)
	{
		delete [] data;
		
		std::cerr << "\nFile format error (missing or misplaced 'targets ' atom): " << fn << std::endl;
		
		return false;
	}
	
	uint64_t numOutputTarget = (targetsSizeBytes - 8 - 8) / 8;
	
	std::vector<uint64_t> targetOutputTemps(numOutputTarget, 0);
	
	for(uint64_t i = 0; i < numOutputTarget; ++i)
	{
		uint64_t tempPos = *(const uint64_t *)(rawdata + 8 + 8 + 8 * i);
		
		targetOutputTemps[i] = tempPos;
	}
	
	rawdata += targetsSizeBytes;
	
	bool backwards = false;
	
	uint64_t numEquations = *(const uint64_t *)(rawdata);
	
	rawdata += 8;
	
	if(numEquations == 0)
	{
		backwards = true;
		
		numEquations = *(const uint64_t *)(rawdata);
		
		rawdata += 8;
	}
	
	std::cout << "Preparing " << numEquations << " equations... " << std::flush;
	
	if(acceptor.Initialize(constantValues, targetOutputTemps, numUnknownBits, numEquations, std::string(magic)) == false)
	{
		delete [] data;
		
		std::cerr << "\nInitialize() failed. Giving up reading file: " << fn << std::endl;
		
		return false;
	}
	
	for(int64_t i = (backwards == true) ? (numEquations) : -1; ;)
	{
		if(backwards)
		{
			--i;
			if(i < 0)
			{
				break;
			}
		}
		else
		{
			++i;
			if(i >= numEquations)
			{
				break;
			}
		}
	
		const uint64_t synchValue = *(const uint64_t *)(rawdata);
		
		if(synchValue != i)
		{
			delete [] data;
			
			std::cerr << "\nFile format error: " << fn << std::endl;
			
			return false;
		}
		
		rawdata += 8;
		
		uint64_t divisorShift = *(const uint64_t *)(rawdata);
		
		rawdata += 8;
		
		uint64_t operandCount = *(const uint64_t *)(rawdata);
		
		rawdata += 8;
		
		if(divisorShift != 0)
		{
			delete [] data;
			
			// we expect our input file equations to be all 'mod 2'.
			std::cerr << "\nIncorrect divisorShift in input file (expected 0): " << fn << std::endl;
			
			return false;
		}
		
		CGenerationEquation equation;
		equation.divisorShift = 1;	// we're changing everything to mod 4 (so divisorShift is to become 1)
		
		// iterate through operands. if there are none, that means we have a value of 0.
		for(uint64_t j = 0; j < operandCount; ++j)
		{
			const char *coeffT = (const char *)(rawdata);
			
			mpq_class coeff;
			coeff.set_str(coeffT, 10);
			
			rawdata += std::strlen(coeffT) + 1;
			
			CGenerationOperand operand;
			operand.type = *(const char *)(rawdata);
			++rawdata;
			
			operand.pos = 0;
			
			if(operand.type == '1')
				;	// unity
			else if(operand.type == 'x' || operand.type == 'c')	// variable or constant
			{
				operand.pos = *(const uint64_t *)(rawdata);
				
				rawdata += 8;
			}
			else if(operand.type == 't')
			{
				operand.pos = *(const uint64_t *)(rawdata);
				
				rawdata += 8;
				
				if(operand.pos >= i)
				{
					delete [] data;
					
					std::cerr << "\nFile format error (possibly cyclic): " << fn << std::endl;
					
					return false;
				}
			}
			
			if(coeff != 0)
			{
				coeff *= 2;	// we're mod 4 now
				
				equation.operands.push_back(std::pair<CGenerationOperand, mpq_class>(operand, coeff));
			}
		}
		
		equation.zeroTarget = false;
		
		if(acceptor.AcceptNextEquation(equation, i) == false)
		{
			delete [] data;
			
			std::cerr << "\nError from AcceptNextEquation() while reading file: " << fn << std::endl;
			
			return false;
		}
	}
	
	if(memcmp(rawdata, "endend  ", 8) != 0)
	{
		delete [] data;
		
		std::cerr << "\nFile format error (missing end marker): " << fn << std::endl;
		
		return false;
	}
	
	std::cout << "done" << std::endl;

	std::cout << "Finishing up... " << std::flush;

	delete [] data;

	if(acceptor.Finish() == false)
	{
		std::cerr << "\nError from Finish() while reading file: " << fn << std::endl;
		
		return false;
	}
	
	std::cout << "done\n" << std::endl;

	return true;
}

// ========================================================================

}	// namespace formal_crypto


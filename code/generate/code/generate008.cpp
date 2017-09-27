// ---------------------------------------------------------------------------------
// generate008.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// see build.txt
// ---------------------------------------------------------------------------------
// Required:
//
// GMP
// 1. This is a multiprecision arithmetic library
// 2. I.e. on Debian:
//    sudo apt-get install libgmp-dev libgmpxx4ldbl
//
// To build:
// g++ -I./h -std=c++11 -o generate008.out generate008.cpp formcrypto.cpp formsha256.cpp -lgmp -lgmpxx -O2
// ---------------------------------------------------------------------------------
// Formal representation for SHA-256 (applied twice, presently with 68 target bits).
// =================================================================================

#include "formcrypto.h"
#include "formsha256.h"

#include <iostream>
#include <fstream>
#include <cstdio>

int main()
{
	bool fullProblem = false;
	using namespace formal_crypto;

	/* This works.
	CUtilSha256::SelfTest(std::cout);
	*/
	
	CCryptosystem cSystem;
	enum { UNKNOWN_W_BIT_COUNT = 0 };
	enum { TARGET_H_BIT_COUNT = 256 };
	CFormalSha256 cSha256(cSystem, UNKNOWN_W_BIT_COUNT, TARGET_H_BIT_COUNT, 1, 64 /*examples: 8, 16, or 24*/);

	std::vector<bool> savedInputValues;
	std::vector<bool> savedConstantValues;
	
	if(true)
	{
		// Let's see what the final 8 w's look like, to check our system.
		std::vector<bool> inputValues(cSystem.inputOperands.size(), 0);
		std::vector<bool> constantValues(cSystem.constantOperands.size(), 0);
		std::vector<bool> outputValues(cSystem.userOutputOperands.size(), 0);
		constantValues[cSystem.GetUnity()->bitIndexLabel] = 1;			// this should be at 'constant' position 0
		
		uint32_t wSecret[16] = {0};
		
		if(true)
		{
			wSecret[0] = ('t' << 0) + ('s' << 8) + ('e' << 16) + ('t' << 24);	// 'test' message
			wSecret[1] = 0x80000000u;						// marker bit
			wSecret[14] = 0;							// message length in bits (high part)
			wSecret[15] = (4 * 8);							// message length in bits (low part)
		}
		else
		{
			wSecret[0] = ('t' << 0) + ('s' << 8) + ('e' << 16) + ('t' << 24);	// 'test' message
			wSecret[1] = 0x0019DDC2u;						// 'counter' value we brute forced previously (see above)
			wSecret[2] = 0x80000000u;						// marker bit
			wSecret[14] = 0;							// message length in bits (high part)
			wSecret[15] = 64;							// message length in bits (low part)
		}

		for(uint32_t n = 0; n < 512; ++n)
		{
			bool value = ((wSecret[n / 32] >> (n & 31)) & 1u);
		
			if(n < UNKNOWN_W_BIT_COUNT)
			{
				inputValues[n] = value;
			}
			else
			{
				constantValues[n + 1] = value;				// constant bit 0 is reserved for unity
			}
		}
		
		// For now, let's use the default initial value for h[].
		for(uint32_t n = 0; n < 256; ++n)
		{
			bool value = ((CUtilSha256::GetInitialH(n / 32) >> (n & 31)) & 1u);
			
			constantValues[513 + n] = value;
		}
		
		// Let's set our expected output values.
		uint32_t expectedOutputHSimple[8] = {0};
		uint32_t expectedOutputHFull[8] = {0};
		uint32_t *expectedOutputH = (fullProblem == true) ? expectedOutputHFull : expectedOutputHSimple;
		
		for(uint32_t i = TARGET_H_BIT_COUNT; i < 256; ++i)
		{
			expectedOutputH[i / 32] &= ~(1u << (i & 31));
		}
		for(uint32_t i = 0; i < 256; ++i)
		{
			bool value = ((expectedOutputH[i / 32] >> (i & 31)) & 1u);
		
			constantValues[513 + 256 + i] = value;				
		}
		
		savedInputValues = inputValues;
		savedConstantValues = constantValues;

		if(cSystem.Compute(inputValues, constantValues, outputValues) == false)
		{
			std::cout << "Compute failure" << std::endl;
			return 1;
		}
		
		uint32_t result[8] = {0};
		
		for(uint32_t i = 0; i < outputValues.size(); ++i)
		{
			if(i >= 32 * 8)  break;
			
			if(outputValues[i] == 0)  continue;
			
			result[i / 32] |= (1u << (i & 31));
		}
		
		// output.
		for(uint32_t i = 0; i < 8; ++i)
		{
			char s[256];
			s[255] = '\0';
			
			std::sprintf(s, "%08X", (unsigned int)result[i]);
			std::cout << s << " ";
		}
		std::cout << std::endl;
	}
	
	std::cout << "\nFlattening..." << std::endl;
	if(cSystem.Flatten(std::cout) == false)
	{
		return 1;
	}
	std::cout << "Done flattening.\n" << std::endl;

	if(true)
	{	
		using namespace std;
		
		uint64_t x = 0;
		
		const char *fn = "problem256x2-68.bin";
		FILE *fo = fopen(fn, "wb");
		if(fo == nullptr)
		{
			std::cout << "Unable to open output file for writing: " << fn << std::endl;
			
			return 1;
		}
		std::cout << "Writing file: " << fn << std::endl;
		
		// reserve space for total file size
		x = 0;
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		// write first magic signature, "sha256x2". this represents SHA-256 applied twice.
		memcpy(&x, "sha256x2", 8);		// this is for human consumption only and can be changed without notice
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		// number of actual unknown input bits (64) and the number of known target equations (68).
		memcpy(&x, "-64equ68", 8);		// this is the human-readable description and might be wrong (i.e. we could be mislabeled)
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		// let's write a second, definitive machine-readable version of the number of unknown bits.
		x = savedInputValues.size();
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		// let's write out the constant vector next.
		x = 8 + 8 + savedConstantValues.size() * 8;
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		memcpy(&x, "constant", 8);
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		for(uint64_t i = 0; i < savedConstantValues.size(); ++i)
		{
			x = savedConstantValues[i];
			fwrite(&x, sizeof(uint64_t), 1, fo);
		}
		
		uint64_t equatnsPos = ftell(fo);
		x = 0;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// placeholder for 'equatns ' size
		memcpy(&x, "equatns ", 8);
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		if(cSystem.FinalizeEquationsBinary(fo, std::cout) == false)
		{
			std::cout << "\nGiving up." << std::endl;
		
			return 1;
		}
		
		uint64_t y = ftell(fo);
		x = ftell(fo) - equatnsPos;
		fseek(fo, equatnsPos, SEEK_SET);
		fwrite(&x, sizeof(uint64_t), 1, fo);	// overwrite 'equatns ' size

		// overwrite total file size
		rewind(fo);
		x = y;
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		std::cout << "done" << std::endl;		
		fclose(fo);
	}

	if(false && fullProblem == true && savedInputValues.empty() == false)
	{
		std::cout << "Checking equations..." << std::endl;
	
		if(cSystem.CheckEquations(std::cout, savedInputValues, savedConstantValues) == false)
		{
			std::cout << "Equation check failed!" << std::endl;
		
			return 1;
		}
		
		std::cout << "Done checking equations (test pass!)\n" << std::endl;
	}
	
	if(false)
	{
		// Let's look at these equations ! TODO regenerate once test passes..
		std::cout << "Writing equations to out_eqns.txt... " << std::flush;
		std::ofstream fo("out_eqns.txt");
		if(cSystem.WriteEquationsText(fo, false) == false)
		{
			std::cout << "\n\nError writing equations to a text file. Giving up!" << std::endl;
			
			return 1;
		}
		std::cout << "done\n" << std::endl;
	}
	
	if(true)
	{
		using namespace std;

		const char *fn = "solution256x2-68.bin";
		FILE *fo = fopen(fn, "wb");
		if(fo == nullptr)
		{
			std::cout << "Unable to open output file for writing: " << fn << std::endl;
			
			return 1;
		}
		std::cout << "Writing " << fn << "... " << std::flush;
		uint64_t x = savedInputValues.size();
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		for(uint64_t i = 0; i < savedInputValues.size(); ++i)
		{
			x = savedInputValues[i];
			fwrite(&x, sizeof(uint64_t), 1, fo);
		}
		
		fclose(fo);
		std::cout << "done" << std::endl;
	}

	return 0;
}


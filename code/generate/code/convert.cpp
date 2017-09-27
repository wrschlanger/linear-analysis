// convert.cpp - Released to the Public Domain in August of 2017.
// see build.txt
// ---------------------------------------------------------
// This program converts e.g. "problem256x2-68.bin" to the
// "problem.dat" data file. This conversion is being done
// to allow us to read our data in chunks (without having
// to have the entire data file in memory prior to
// processing). The intent is that we can easily generate
// a matrix from this data, without having to have two full
// copies of the data in memory at once.
// ---------------------------------------------------------
// g++ -I./h -std=c++11 -o convert.out convert.cpp formproblem.cpp -lgmp -lgmpxx -O2
// =========================================================

#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <map>

#include <cstdio>

#include "formproblem.h"

namespace formal_crypto
{

class CProblemConverter :
	public CProblemAcceptor
{
	std::FILE *fo;
	
	uint64_t unityPosition;
	
	std::map<uint64_t, uint64_t> operandToColumn;
	
	uint64_t *row;
	
	bool firstEqn;
	
	uint64_t numUnknownInputs;

public:
	CProblemConverter(std::string outputFileName) :
		fo(nullptr),
		unityPosition(0),
		row(nullptr),
		firstEqn(true)
	{
		fo = fopen(outputFileName.c_str(), "wb");
	}

	virtual ~CProblemConverter()
	{
		delete [] row;
	
		if(fo != nullptr)
		{
			std::fclose(fo);
		}
	}
	
	virtual bool Initialize(std::vector<bool> &constantValues, std::vector<uint64_t> &targetOutputTemps, uint64_t numUnknownInputs, uint64_t numEquations, std::string magicSignature)
	{
		this->numUnknownInputs = numUnknownInputs;
	
		if(fo == nullptr)
		{
			std::cout << "\nUnable to open output file for writing." << std::endl;
			
			return false;
		}
		
		std::vector<uint64_t> header;
		uint64_t x;
		memcpy(&x, "problemd", 8);
		
		header.push_back(0);	// reserved for size (in bytes)
		header.push_back(x);	// magic signature ("problemd")
		
		header.push_back(numEquations);
		header.push_back(numUnknownInputs);
		
		// Columns in our matrix consist of:
		// 1. (unknown) input variables  [count = 'numUnknownInputs']
		// 2. temporary variables        [count = 'numEquations']
		//                               note: some of these (exactly 'targetOutputTemps.size()']
		//                               are 'output' temporaries. we want those variables to be 0.
		//                               all other variables may be 0 or 1. the solution set is preserved
		//                               by replacing any reference to an output temporary variable with 0
		//                               (since output temporary variables have a target value of 0).
		// 3. constants (excluding unity)  [count = 'constantValues.size()'].
		//                                 note: the values of the constants in 'constantValues' can be changed.
		// 4. unity                      [count = 1]
		
		// For the purpose of column layout when generating our output file, the above layout is used.
		// This means there are temporary variables even for 'output temporaries'. Those variables must be 0, so
		// the data file user may want to add some rows [equations] prior to reduction, to mandate the same.
		
		unityPosition = 0;
		
		operandToColumn.clear();
		
		for(uint64_t i = 0; i < numUnknownInputs; ++i)
		{
			CGenerationOperand oper;
			oper.type = 'x';
			oper.pos = i;
			operandToColumn[oper.GetFullValue()] = unityPosition++;
		}
		
		for(uint64_t i = 0; i < numEquations; ++i)
		{
			CGenerationOperand oper;
			oper.type = 't';
			oper.pos = i;
			operandToColumn[oper.GetFullValue()] = unityPosition++;
		}
		
		for(uint64_t i = 0; i < constantValues.size(); ++i)
		{
			if(i == 0)  continue;		// skip unity
		
			CGenerationOperand oper;
			oper.type = 'c';
			oper.pos = i;
			operandToColumn[oper.GetFullValue()] = unityPosition++;
		}
		
		CGenerationOperand unityOper;
		unityOper.type = '1';
		unityOper.pos = 0;
		operandToColumn[unityOper.GetFullValue()] = unityPosition;
		
		header.push_back(0);	// reserved for future expansion
		header.push_back(0);
		header.push_back(0);
		header.push_back(0);

		header.push_back(unityPosition + 1);	// this is the number of columns a matrix representation would need
		
		header.push_back(targetOutputTemps.size());
		for(uint64_t i = 0; i < targetOutputTemps.size(); ++i)
		{
			header.push_back(targetOutputTemps[i]);
		}

		header.push_back(constantValues.size());
		for(uint64_t i = 0; i < constantValues.size(); ++i)
		{
			header.push_back(constantValues[i]);
		}
		
		header[0] = sizeof(uint64_t) * header.size();	// update size (in bytes)
		
		for(uint64_t i = 0; i < header.size(); ++i)
		{
			x = header[i];
			
			std::fwrite(&x, sizeof(uint64_t), 1, fo);
		}
		
		row = new uint64_t [2 + unityPosition + 1];	// we're preceded by the size in bytes of this row, then the equation number; finally comes the column data
		memset(row, 0, sizeof(uint64_t) * (2 + unityPosition + 1));
		
		return true;
	}
	
	virtual bool AcceptNextEquation(const CGenerationEquation &equation, int64_t position)
	{
		memset(row, 0, sizeof(uint64_t) * (2 + unityPosition + 1));
		
		row[0] = (2 + unityPosition + 1) * sizeof(uint64_t);
		
		row[1] = position;
		
		row[2 + numUnknownInputs + position] = (1uLL << 32);	// this is the operand being defined
		
		if(equation.divisorShift != 1)
		{
			std::cout << "\nExpected input to be modulo 4 with fractional coefficients." << std::endl;
			
			return false;
		}
		
		for(std::list<std::pair<CGenerationOperand, mpq_class> >::const_iterator i = equation.operands.begin();
			i != equation.operands.end();
			++i
		)
		{
			mpq_class coeff = i->second;
			
			const CGenerationOperand &oper = i->first;
			
			uint64_t positionT = oper.GetFullValue();
			
			if(operandToColumn.find(positionT) == operandToColumn.end())
			{
				std::cout << "\nUnable to find an operand (?)" << std::endl;
				
				return false;
			}
			
			uint64_t position = operandToColumn[positionT];
			
			coeff *= mpz_class(2 * 1024) * mpz_class(1024 * 1024);
			
			if(coeff.get_den() != 1)
			{
				std::cout << "\nExpected input coefficients to have a 33-bit base." << std::endl;
				
				return false;
			}
			
			mpz_class temp = coeff.get_num();
			
			temp = temp % (mpz_class(1) << 33);
			if(temp < 0)
				temp += (mpz_class(1) << 33);
			
			// first, let's get bit 0
			uint64_t value = temp.get_ui() & 1;
			
			temp = (temp - value) / 2;
			
			// then lets get bits 1..32 inclusive
			value += 2uLL * temp.get_ui();
			
			row[2 + position] = value;
		}
		
		if(std::fwrite(row, row[0], 1, fo) != 1)
		{
			std::cout << "\nError writing to output file." << std::endl;
		
			return false;
		}
		
		if(firstEqn == true)
		{
			std::cout << std::endl;
			
			firstEqn = false;
		}
		
		std::cout << "\r" << position << "             " << std::flush;
	
		return true;
	}
	
	virtual bool Finish()
	{
		if(fo != nullptr)
		{
			std::fclose(fo);
			
			fo = nullptr;
		}
		std::cout << "\nDone writing file." << std::endl;

		return true;
	}
};

}	// namespace formal_crypto

int main()
{
	using namespace formal_crypto;
	
	if(true)
	{
		std::string location = "./";
		std::cout << "This program looks for its input data files here: " << location << std::endl;

		std::string fn_problem = "problem256x2-68.bin";
		//std::string fn_solution = "solution256x2-68.bin";
		
		std::cout << "\nWe will convert " << fn_problem << " at the above location to 'problem.dat'\n";
		std::cout << "in the current directory.\n" << std::endl;
		
		CProblemConverter converter("problem.dat");
		CProblemReader reader;
		if(reader.ReadProblem(std::string(location + fn_problem).c_str(), converter) == false)
		{
			std::cout << "\nGiving up." << std::endl;
			
			return 1;
		}
		
		std::cout << "Conversion complete." << std::endl;

		return 0;
	}

#if 0
	if(false)
	{
		// This code demonstrates and tests our generic 33-bit word-size matrix storage class.
		std::shared_ptr<CSquareMatrix> matrix = std::make_shared<CSquareMatrix>(64);

		std::ofstream fo("m.txt");

		for(uint64_t y = 0; y < 64; ++y)
		{
			matrix->RawSet(y, y, 0x111111111uLL);
		}

		for(uint64_t y = 0; y < 64; ++y)
		{
			using namespace std;
			char s[128];

			for(uint64_t x = 0; x < 64; ++x)
			{
				sprintf(s, "%09llX", (unsigned long long)(matrix->RawGet(y, x).x));
				fo << s << " ";
			}
			
			fo << std::endl;
		}
	}
	
	if(false)
	{
		// This program does a simple HNF reduction to demonstrate CHermiteMatrix.
		std::shared_ptr<CHermiteMatrix> matrix = std::make_shared<CHermiteMatrix>(64);
		
		// add row: [1, 0, 0, ...]
		matrix->ZeroRow(matrix->GetSize());
		matrix->RawSet(matrix->GetSize(), 0, 1);
		matrix->AddRow();
		
		// add row: [2, 3, 0, ...]
		matrix->ZeroRow(matrix->GetSize());
		matrix->RawSet(matrix->GetSize(), 0, 2);
		matrix->RawSet(matrix->GetSize(), 1, 3);
		matrix->AddRow();

		// add row: [0, 2, 6, ...]
		matrix->ZeroRow(matrix->GetSize());
		matrix->RawSet(matrix->GetSize(), 1, 2);
		matrix->RawSet(matrix->GetSize(), 2, 6);
		matrix->AddRow();

		matrix->Publish();
		std::ofstream fo("m.txt");
		for(uint64_t y = 0; y < matrix->LogicalHeight(); ++y)
		{
			using namespace std;
			char s[128];

			for(uint64_t x = 0; x < 64; ++x)
			{
				sprintf(s, "%09llX", (unsigned long long)(matrix->LogicalGet(y, x).x));
				fo << s << " ";
			}
			
			fo << std::endl;
		}
	}
#endif

	return 0;
}

// check.cpp - Released to the Public Domain in August of 2017.
// see build.txt
// ---------------------------------------------------------
// This program is a follow-on to 'convert.cpp'.
// It reads problem.dat.
// ---------------------------------------------------------
// The purpose of this program is to read in the problem.dat
// file, generate a matrix, and check it using solution.bin.
// ---------------------------------------------------------
// It also produces the 'sha2_256_out.txt' file, which in
// theory is human-readable (see compute1.cpp for a sample
// program that uses that text file!)
// ---------------------------------------------------------
// g++ -I./h -std=c++11 -o check2.out check2.cpp -lgmp -lgmpxx -O2
// =========================================================

#include "../include/matrix.h"

#include <map>
#include <set>
#include <list>
#include <string>
#include <vector>
#include <iostream>

namespace formal_crypto
{

class CAcceptRow
{
public:
	virtual void Begin(std::vector<uint64_t> &header) = 0;
	virtual void AcceptRow(RMatrix dest, uint64_t position) = 0;
	virtual void End(RMatrix matrix) = 0;
};

class CRawAcceptRow :
	public CAcceptRow
{
public:
	std::vector<uint64_t> header;
	
	CRawAcceptRow()
	{
	}
	
	bool CheckRawMatrix(std::string solutionFileName, RMatrix matrix, std::vector<bool> &secretValues)
	{
		secretValues.clear();
		secretValues.resize(matrix->GetLogicalWidth(), 0);
		std::vector<bool> valueIsKnown(matrix->GetLogicalWidth(), false);
		
		uint64_t numTemps = header[2];	// this is also the number of equations

		uint64_t numInputs = header[3];

		// Read solution file. This contains the secret key.
		// We're reading this so we can check our matrix for correctness.
		if(true)
		{
			std::FILE *fi = fopen(solutionFileName.c_str(), "rb");
			
			if(fi == nullptr)
			{
				std::cout << "Unable to open file for reading: " << solutionFileName << std::endl;
				
				return false;
			}
			
			uint64_t numInputsInSolution = 0;
			if(std::fread(&numInputsInSolution, sizeof(uint64_t), 1, fi) != 1)
				numInputsInSolution = 0;
			else
			{
				for(uint64_t i = 0; i < numInputsInSolution; ++i)
				{
					uint64_t x = 0;
					if(std::fread(&x, sizeof(uint64_t), 1, fi) != 1)
					{
						std::cout << "Unable to read binary solution file." << std::endl;
						
						std::fclose(fi);
						
						return false;
					}
					
					valueIsKnown[i] = true;
					secretValues[i] = (x != 0);
				}
			}
			
			std::fclose(fi);
			
			if(numInputsInSolution != numInputs)
			{
				std::cout << "Invalid solution binary file." << std::endl;
				
				return false;
			}

			//secretValues[0] = !secretValues[0];	// purposely use an invalid key to make sure it's rejected
		}

		std::ofstream fo2("sha2_256_out.txt");

		for(uint64_t i = 0; i < header[9]/*number of output temps*/; ++i)
		{
			uint64_t pos = numInputs + header[9 + 1 + i];

			fo2 << "Y " << i << " " << pos << std::endl;
		}

		fo2 << "Y -1 -1" << std::endl;

		uint64_t numOutputTemps = header[9];
		uint64_t posConstants = 9 + 1 + numOutputTemps;
		uint64_t numConstants = header[posConstants];

		fo2 << "T " << numTemps << std::endl;

		fo2 << "X " << 0 << std::endl;

		fo2 << "C " << numConstants << std::endl;

		char s2[33];

		s2[0] = s2[32] = 0;

		// Load constants.
		// [inputs, temporaries, constants, unity]
		if(true)
		{
			uint64_t nextPosition = numInputs + numTemps;
			
			for(uint64_t i = 0; i < numConstants; ++i)
			{
				if(i == 0)  continue;	// skip unity
				
				valueIsKnown[nextPosition] = true;
				secretValues[nextPosition] = ((header[posConstants + 1 + i]) != 0);
				
				++nextPosition;
			}
			
			// Next, let's do 'unity'.
			valueIsKnown[nextPosition] = true;
			secretValues[nextPosition] = 1;
		}
		
		
		// Now let's go through and compute our temporaries.
		
		std::cout << "Checking matrix..." << std::endl;
		
		for(uint64_t yy = 0; yy < numTemps; ++yy)
		{
			std::cout << "\r" << /*y*/yy << "/" << (numTemps - 1) << std::flush;

			const uint64_t y = yy;
		
			if(matrix->Get(y, numInputs + y).x == 0)
			{
				std::cout << "\nInvalid row: " << y << std::endl;
				
				return false;
			}
			
			uword_t value = 0;

			fo2 << "begin";
			
			for(uint64_t x = 0; x < matrix->GetLogicalWidth(); ++x)
			{
				uword_t coeff = matrix->Get(y, x);
				
				s2[0] = s2[32] = 0;
				int s2len = sprintf(s2, "%09llx", (unsigned long long)coeff.x);

				if(s2len != 9)
				{
					std::cout << s2len << " is not 9" << std::endl;

					return 1;
				}

				fo2 << " ";

				fo2 << s2;

				if(x == numInputs + y)  continue;
				
				if(coeff.x == 0)  continue;
				
				if(valueIsKnown[x] == false)
				{
					std::cout << "\nUnknown value required, column " << x << std::endl;
					
					return false;
				}
				
				if(secretValues[x] != 0)
				{
					value.x += coeff.x;
				}
			}

			fo2 << std::endl;
			
			if(value.x == 0)
			{
				valueIsKnown[numInputs + y] = true;
				secretValues[numInputs + y] = 0;
			}
			else
			{
				uword_t check = matrix->Get(y, numInputs + y);
				
				check.x += value.x;
				
				if(check.x == 0)
				{
					valueIsKnown[numInputs + y] = true;
					secretValues[numInputs + y] = 1;
				}
				else
				{
					std::cout << "\nInvalid value computed, row " << y << std::endl;
				}
			}
		}
		
		std::cout << "\n\nResult:" << std::endl;

		uint32_t u[8] = {0};

		for(uint64_t i = 0; i < header[9]/*number of output temps*/; ++i)
		{
			uint64_t pos = numInputs + header[9 + 1 + i];
			
			if(valueIsKnown[pos] == false)
			{
				std::cout << "_";
			}
			else if(secretValues[pos] == 0)
			{
				std::cout << "0";
			}
			else
			{
				std::cout << "1";

				u[i / 32] |= (1u << (i & 31));
			}
		}
		
		std::cout << std::endl;

		for(uint32_t i = 0; i < 8; ++i)
		{
			char s[33];

			s[0] = s[32] = 0;

			using namespace std;

			sprintf(s, "%08x", u[i]);

			std::cout << s;
		}

		std::cout << std::endl;

		return true;
	}

	virtual void Begin(std::vector<uint64_t> &headerT)
	{
		this->header = headerT;
	}

	virtual void AcceptRow(RMatrix dest, uint64_t position)
	{
		for(uint64_t i = 0; i < dest->GetLogicalWidth(); ++i)
		{
			// accept row from invisible bottom row of matrix, to 'position'.
			dest->Set(position, i, dest->Get(dest->GetLogicalHeight() - 1, i));
			
			// zero out bottom row.
			dest->Set(dest->GetLogicalHeight() - 1, i, 0);
		}
	}
	
	virtual void End(RMatrix matrix)
	{
		std::cout << "\nStatistics:" << std::endl;
		std::cout << "Raw matrix size is " << matrix->GetLogicalHeight() << "x" <<
			matrix->GetLogicalWidth() << std::endl
		;
		
		std::cout << "Active height is " << matrix->GetActiveHeight() << std::endl;
		
		std::cout << "There are " << header[3] << " (unknown) input variable(s)." << std::endl;
		std::cout << "There are " << header[2] << " temporary variable(s)." << std::endl;
		std::cout << "This includes " << header[9] << " output temporary variable(s)." << std::endl;
		std::cout << "The number of significant operands is thus " << (header[3] + header[2] - header[9]) << "." << std::endl;
	}
};

static RMatrix GenerateMatrix(std::string inFileName, CAcceptRow &acceptor)
{
	RMatrix matrix = nullptr;
	
	std::cout << "Reading " << inFileName << "..." << std::endl;
	
	std::FILE *fi = std::fopen(inFileName.c_str(), "rb");
	
	if(fi == nullptr)
	{
		std::cout << "[1] Error reading file: " << inFileName << std::endl;
		
		return nullptr;
	}
	
	uint64_t x = 0;
	if(std::fread(&x, sizeof(uint64_t), 1, fi) != 1)
	{
		std::fclose(fi);
		std::cout << "[2] Error reading file: " << inFileName << std::endl;
		return nullptr;
	}
	
	uint64_t *header = new uint64_t [x / sizeof(uint64_t)];
	
	rewind(fi);
	
	if(std::fread(header, x, 1, fi) != 1)
	{
		delete [] header;
		std::fclose(fi);
		std::cout << "[3] Error reading file: " << inFileName << std::endl;
		return nullptr;
	}
	
	std::vector<uint64_t> headerVector(header, header + x / sizeof(uint64_t));
	
	delete [] header;
	header = nullptr;
	
	uint64_t numColumnsRequired = headerVector[8]/* number of columns, incuding unity*/;

	// compute number of rows we need for our unreduced matrix. we're adding the number of output equations because
	// we plan to demand those equations have a value of 0, a requirement that involves us adding a new row.
	uint64_t numRowsRequired = headerVector[2]/*numEquations*/ + headerVector[9]/*number of output equations*/;
	
	uint64_t size = (numColumnsRequired > numRowsRequired) ? numColumnsRequired : numRowsRequired;
	
	matrix = std::make_shared<CMatrix>(numRowsRequired, numColumnsRequired);
	
	// Now let's read some data!
	uint64_t rowSize = numColumnsRequired + 2;	// the first entry is a length in bytes; then comes the equation number.
	
	uint64_t readBufferSizeBytes = rowSize * sizeof(uint64_t);
	
	if(readBufferSizeBytes < 8 * 1024 * 1024)
	{
		uint64_t scalar = 8 * 1024 * 1024;
		scalar /= readBufferSizeBytes;
		
		readBufferSizeBytes *= scalar;
	}
	
	uint64_t *buffer = new uint64_t [(readBufferSizeBytes + sizeof(uint64_t) - 1) / sizeof(uint64_t)];
	memset(buffer, 0, readBufferSizeBytes);
	
	acceptor.Begin(headerVector);
	
	// Let's start by requiring all 'output' temporaries be 0. This will be done by adding some rows demanding as much.
	for(int64_t i = headerVector[9] - 1; i >= 0; --i)
	{
		uint64_t position = headerVector[10 + i];
		
		matrix->ZeroRow(matrix->GetLogicalHeight() - 1);
		
		// Let's demand this variable be 0. Just place a 1 in its position of the matrix, and leave all other values in
		// the row 0 (including the 'unity' column). This means 1 * X = 0, so X must be 0.
		matrix->Set(matrix->GetLogicalHeight() - 1, headerVector[3]/*numInputs*/ + position, 1);
		
		// These rows come after (in the unreduced matrix) the normal 'temporary equation' rows.
		acceptor.AcceptRow(matrix, headerVector[2]/*# of regular equations*/ + i);
	}
	
	do
	{
		uint64_t numBytesRead = std::fread(buffer, 1, readBufferSizeBytes, fi);
		
		if(numBytesRead == 0)
		{
			break;
		}
		
		if((numBytesRead % (rowSize * sizeof(uint64_t))) != 0)
		{
			delete [] buffer;
			std::fclose(fi);
			
			std::cout << "[4] Read an incorrect number of bytes. Is the file valid? Does it end early?" << std::endl;
			
			return nullptr;
		}
		
		uint64_t numEqnsRead = numBytesRead / (rowSize * sizeof(uint64_t));
		
		// Let's go through our row now(s).
		
		uint64_t *data = buffer;
		
		for(uint64_t i = 0; i < numEqnsRead; ++i)
		{
			uint64_t sizeBytes = data[0];
			uint64_t eqnNumber = data[1];

			// Display status.
			std::cout << "\r" << eqnNumber << "                " << std::flush;
			
			// Check for validity!
			if(sizeBytes != rowSize * sizeof(uint64_t))
			{
				delete [] buffer;
				std::fclose(fi);
				
				std::cout << "\n[5] Invalid or corrupt data file detected." << std::endl;
				
				return nullptr;
			}
			
			// Zero out destination row.
			matrix->ZeroRow(matrix->GetLogicalHeight() - 1);
			
			// Set column data.
			for(uint64_t j = 0; j < numColumnsRequired; ++j)
			{
				matrix->Set(matrix->GetLogicalHeight() - 1, j, data[2 + j]);
			}
			
			// Accept the row !
			acceptor.AcceptRow(matrix, eqnNumber);
		
			data += rowSize;
		}
		
	}	while(!std::feof(fi));
	
	delete [] buffer;
	
	std::fclose(fi);
	
	acceptor.End(matrix);
	
	std::cout << "\rDone reading matrix.                " << std::endl;
	
	return matrix;
}

// Returns true if the test passed, false otherwise.
static bool DoCheckMatrix(RMatrix matrix, std::vector<bool> &secretValues)
{
	if(secretValues.size() < matrix->GetLogicalWidth())
	{
		std::cout << "\nDoCheckMatrix(): not enough known secret values to do check!" << std::endl;
		
		return false;
	}
	
	for(uint64_t y = 0; y < matrix->GetLogicalHeight(); ++y)
	{
		if(matrix->RowIsAllZeros(y) == true)  continue;
		
		uword_t value = 0;
		
		for(uint64_t x = 0; x < matrix->GetLogicalWidth(); ++x)
		{
			if(matrix->Get(y, x).x == 0)  continue;
			
			if(secretValues[x] == 0)  continue;
			
			value.x += matrix->Get(y, x).x;
		}
		
		if(value.x != 0)
		{
			std::cout << "\nMatrix evaluation failure, row " << y << std::endl;
			
			std::cout << "Computed value: 0x" << std::hex << value.x << std::dec << std::endl;
			
			return false;
		}
	}
	
	return true;
}

}	// namespace formal_crypto

int main()
{
	using namespace formal_crypto;

	std::cout << "check2" << std::endl;
	
	RMatrix matrix;
	
	// This contains values (0 or 1) for each column in the matrix, based on the secret key solution
	// and the unreduced matrix.
	std::vector<bool> secretValues;
	
	std::vector<uint64_t> header;

	// Our first step is to accept (and check) the unreduced matrix. This loads 'matrix' and 'secretValues'.
	if(true)
	{
		CRawAcceptRow rawAcceptor;
		
		matrix = GenerateMatrix("problem.dat", rawAcceptor);
		
		if(matrix == nullptr)
		{
			std::cout << "\nGiving up." << std::endl;
			
			return 1;
		}
		
		header = rawAcceptor.header;
		
		// Let's check our unreduced matrix and also fill 'secretValues' so we can do checks later on.
		if(rawAcceptor.CheckRawMatrix("solution256x2-68.bin", matrix, secretValues) == false)
		{
			std::cout << "\nGiving up." << std::endl;
			
			return 1;
		}
	}
	
	if(false)
	{
		using namespace std;
		
		std::cout << "\nWriting m0.dat... " << std::flush;
		FILE *fo = fopen("m0.dat", "wb");
		matrix->Write(fo);
		fclose(fo);
		fo = nullptr;
		std::cout << "done" << std::endl;
	
		std::cout << "\nBegin row reduce." << std::endl;
	
		if(matrix->RowReduce(std::cout) == false)
		{
			std::cout << "\nRow reduce failed." << std::endl;
			
			return 1;
		}
		
		std::cout << "\nRow reduce complete." << std::endl;
		
		std::cout << "\nWriting m1.dat... " << std::flush;
		fo = fopen("m1.dat", "wb");
		matrix->Write(fo);
		fclose(fo);
		fo = nullptr;
		std::cout << "done" << std::endl;

		std::cout << "\nChecking matrix..." << std::endl;
	
		if(DoCheckMatrix(matrix, secretValues) == false)
		{
			std::cout << "\nMatrix check failed." << std::endl;
			
			return 1;
		}
		
		std::cout << "\nMatrix check passed, active height = " <<
			matrix->GetActiveHeight() << std::endl
		;
	}
	
	return 0;
}


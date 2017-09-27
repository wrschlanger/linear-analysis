// matrix.h - by Willow Schlanger. Released to the Public Domain in August of 2017.

#ifndef l_matrix_h__formal_included
#define l_matrix_h__formal_included

#include <stdexcept>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <map>
#include <set>

#include <stdint.h>

#include <cstdio>

#include "common.h"

struct uword_t
{
	uint64_t x : WORD_SIZE_BITS + 1;

	uword_t()
	{
	}
	
	uword_t(const uword_t &src)
	{
		this->x = src.x;
	}
	
	uword_t(uint64_t srcT)
	{
		this->x = srcT;
	}
	
	uword_t &operator=(const uword_t src)
	{
		this->x = src.x;
		
		return *this;
	}
	
	uword_t &operator=(uint64_t src)
	{
		this->x = src;
		
		return *this;
	}
	
	bool operator<(const uword_t &src) const
	{
		return this->x < src.x;
	}
	
	// If n is not 0, n * GetScalarPowerOfTwo(n) will be a power of 2.	
	uword_t GetScalarForPowerOfTwo() const
	{
		uword_t src;
		src.x = this->x;
	
		if(src.x == 0)
		{
			return 0;	// if src == 0, return 0 (this avoids an infinite loop)
		}

		uword_t scalar = 1;
		uword_t original = src;
		
		while((src.x & 1u) == 0)
		{
			scalar.x <<= 1;
			src.x >>= 1;
		}
	
		if(src.x == 0)
		{
			return 1u;	// we're already a power of 2 !
		}
	
		/*
		uword_t result = 1u;
	
		for(uint64_t i = 1; i < WORD_SIZE_BITS + 1; ++i)
		{
			result.x *= src.x;
		
			src.x *= src.x;
		}
		*/
		uword_t result = ComputeModuloInverse(src.x, 1uLL << (WORD_SIZE_BITS + 1));
		
		uword_t check = result.x * original.x;
	
		if(check.x != scalar.x)
		{
			std::cerr << "\nFatal error: " << original.x << " couldn't be inverted modulo 2^33; " << src.x << std::endl;
		
			throw std::runtime_error("Internal error: unable to find a coefficient that turns a 33-bit value into a power of two");
		}
	
		return result;
	}

	// pre: value and modulo should be relatively prime, e.g.
	// GCD(value, modulo) should be 1.
	static uint64_t ComputeModuloInverse(uint64_t value, uint64_t modulo)
	{
		uint64_t check = value * value;
	
		if(check == 1)
		{
			return value;
		}

		std::map<uint64_t, std::pair<uint64_t, uint64_t> > m;
	
		uint64_t a = modulo;
	
		uint64_t b = value;
	
		for(;;)
		{
			uint64_t r = a % b;
			uint64_t q = a / b;
		
			if(r == 0)
			{
				break;
			}
		
			if(a == modulo)
			{
				if(r == 1)
				{
					return -q;
				}

				m[r] = std::pair<uint64_t, uint64_t>(-q, 1);
			}
			else if(a == value)
			{
				std::pair<uint64_t, uint64_t> p;
				p.first = 1;
				p.second = 0;
			
				// Add to 'p' the following value:
				// -q * m[b]
				p.first += -q * m[b].first;
				p.second += -q * m[b].second;
			
				if(r == 1)
				{
					return p.first;
				}

				m[r] = p;
			}
			else
			{
				std::pair<uint64_t, uint64_t> p = m[a];
			
				p.first += -q * m[b].first;
				p.second += -q * m[b].second;

				if(r == 1)
				{
					return p.first;
				}
			
				m[r] = p;
			}
		
			a = b;
			b = r;
		}
	
		return 0;	// failure!
	}
};

class CIntegralMatrix
{
	uint64_t height;
	uint64_t width;
	uword_t *buffer;

public:
	uint64_t GetBufferEntryCount() const
	{
		return this->height * this->width;
	}
	
	uword_t *GetBuffer()
	{
		return this->buffer;
	}

	CIntegralMatrix() :
		height(0),
		width(0),
		buffer(nullptr)
	{
	}
	
	uint64_t GetWidth() const
	{
		return this->width;
	}
	
	uint64_t GetHeight() const
	{
		return this->height;
	}
	
	CIntegralMatrix(const CIntegralMatrix &src) :
		height(src.height),
		width(src.width),
		buffer(nullptr)
	{
		this->buffer = new uword_t [width * (height + 1)];
		
		for(uint64_t n = 0; n < width * (height + 1); ++n)
		{
			this->buffer[n] = src.buffer[n];
		}
	}
	
	CIntegralMatrix &operator=(const CIntegralMatrix &src)
	{
		this->height = src.height;
		this->width = src.width;
		this->buffer = nullptr;
	
		this->buffer = new uword_t [width * (height + 1)];
		
		for(uint64_t n = 0; n < width * (height + 1); ++n)
		{
			this->buffer[n] = src.buffer[n];
		}
		
		return *this;
	}

	CIntegralMatrix(uint64_t heightT, uint64_t widthT) :
		height(heightT),
		width(widthT),
		buffer(nullptr)
	{
		this->buffer = new uword_t [width * (height + 1)];
		
		this->ZeroMatrix();
		
		this->ZeroRow(height);				// zero out invisible bottom row
	}
	
	void ZeroMatrix()
	{
		for(uint64_t n = 0; n < width * height; ++n)	// don't zero out invisible bottom row
		{
			this->buffer[n].x = 0;
		}
	}
	
	void ZeroRow(uint64_t row)
	{
		for(uint64_t n = 0; n < width; ++n)
		{
			this->buffer[width * row + n].x = 0;
		}
	}
	
	virtual ~CIntegralMatrix()
	{
		delete [] buffer;
	}
	
	bool RowIsAllZeros(uint64_t row)
	{
		for(uint64_t n = 0; n < width; ++n)
		{
			if(this->buffer[width * row + n].x != 0)
			{
				return false;
			}
		}
	
		return true;
	}
	
	void Set(uint64_t y, uint64_t x, uword_t src)
	{
		this->buffer[this->width * y + x] = src;
	}
	
	uword_t Get(uint64_t y, uint64_t x) const
	{
		return this->buffer[this->width * y + x];
	}
};

// This is a matrix reference.
class CMatrix
{
	std::shared_ptr<CIntegralMatrix> target;
	CIntegralMatrix unityColumnAdder;
	std::vector<uint64_t> actualColumns;		// -1uLL means: the column is 0
	uint64_t logicalHeight;
	uint64_t logicalWidth;
	
	void WriteMatrix(std::FILE *fo, CIntegralMatrix &m, const char eightcc[8])
	{
		uint64_t x = m.GetBufferEntryCount() * sizeof(uint64_t) + sizeof(uint64_t) * 4;
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		memcpy(&x, eightcc, 8);
		fwrite(&x, sizeof(uint64_t), 1, fo);

		x = m.GetHeight();
		fwrite(&x, sizeof(uint64_t), 1, fo);

		x = m.GetWidth();
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		fwrite(m.GetBuffer(), m.GetBufferEntryCount() * sizeof(uword_t), 1, fo);
	}
	
	// Returns true on success, false otherwise.
	bool ReadMatrix(std::FILE *fi, CIntegralMatrix &m, const char eightcc[8])
	{
		uint64_t x = 0;
		(void) fread(&x, sizeof(uint64_t), 1, fi);

		if(x != m.GetBufferEntryCount() * sizeof(uint64_t) + sizeof(uint64_t) * 4)
		{
			return false;
		}
		
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(memcmp(&x, eightcc, 8) != 0)
		{
			return false;
		}
		
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(x != m.GetHeight())
		{
			return false;
		}
		
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(x != m.GetWidth())
		{
			return false;
		}
		
		if(fread(m.GetBuffer(), m.GetBufferEntryCount() * sizeof(uword_t), 1, fi) != 1)
		{
			return false;
		}
	
		return true;
	}
	
public:
	// returns true on success, false in case of failure.
	bool AcceptColumnMapping(const CMatrix &src)
	{
		if(this->actualColumns.size() != src.actualColumns.size())
		{
			return false;
		}
		
		this->actualColumns = src.actualColumns;
		
		return true;
	}

	void Asgn(const CMatrix &src)
	{
		this->target = std::make_shared<CIntegralMatrix>(*src.target);
		
		this->unityColumnAdder = src.unityColumnAdder;
		
		this->actualColumns = src.actualColumns;
		
		this->logicalHeight = src.logicalHeight;
		
		this->logicalWidth = src.logicalWidth;
	}

	uint64_t GetPhysicalColumnIndex(uint64_t logicalX) const
	{
		return this->actualColumns[logicalX];
	}

	uint64_t GetLogicalHeight() const
	{
		return this->logicalHeight;
	}

	uint64_t GetLogicalWidth() const
	{
		return this->logicalWidth;
	}

	// Returns true on success, false otherwise.
	bool Read(std::FILE *fi)
	{
		uint64_t totalSize = 0;
		(void) fread(&totalSize, sizeof(uint64_t), 1, fi);
		
		uint64_t x = 0;
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(memcmp(&x, "integral", 8) != 0)
		{
			return false;
		}
		
		(void) fread(&this->logicalHeight, sizeof(uint64_t), 1, fi);
		(void) fread(&this->logicalWidth, sizeof(uint64_t), 1, fi);
		
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(x < sizeof(uint64_t) * 2)
		{
			return false;
		}
		x -= sizeof(uint64_t) * 2;
		x /= sizeof(uint64_t);
		
		if(x != actualColumns.size())
		{
			return false;
		}
		
		(void) fread(&x, sizeof(uint64_t), 1, fi);
		if(memcmp(&x, "actualco", 8) != 0)
		{
			return false;
		}
		
		for(uint64_t i = 0; i < actualColumns.size(); ++i)
		{
			(void) fread(&x, sizeof(uint64_t), 1, fi);
			this->actualColumns[i] = x;
		}
		
		if(ReadMatrix(fi, this->unityColumnAdder, "unitycol") == false)
		{
			return false;
		}

		if(ReadMatrix(fi, *this->target, "maindata") == false)
		{
			return false;
		}
		
		return true;
	}

	void Write(std::FILE *fo)
	{
		using namespace std;
	
		uint64_t x = 0;
		
		uint64_t fp = ftell(fo);
		
		x = 0;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// placeholder for file size (0 = invalid)

		memcpy(&x, "integral", 8);		// 8cc used to identify our matrix
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		fwrite(&this->logicalHeight, sizeof(uint64_t), 1, fo);
		fwrite(&this->logicalWidth, sizeof(uint64_t), 1, fo);

		x = actualColumns.size() * sizeof(uint64_t) + sizeof(uint64_t) * 2;
		fwrite(&x, sizeof(uint64_t), 1, fo);	// size of 'actualco' section

		memcpy(&x, "actualco", 8);		// 8cc used to identify 'actualColumns'
		fwrite(&x, sizeof(uint64_t), 1, fo);
		
		for(uint64_t i = 0; i < actualColumns.size(); ++i)
		{
			x = this->actualColumns[i];
			fwrite(&x, sizeof(uint64_t), 1, fo);
		}
		
		WriteMatrix(fo, this->unityColumnAdder, "unitycol");
		
		WriteMatrix(fo, *this->target, "maindata");
		
		x = ftell(fo);

		if(fp == 0)
			rewind(fo);
		else
			fseek(fo, fp, SEEK_SET);

		// update file size
		fwrite(&x, sizeof(uint64_t), 1, fo);
	}

	// Create a 'null' matrix.
	CMatrix()
	{
	}
	
	CMatrix(const CMatrix &src) :
		target(src.target),
		unityColumnAdder(src.unityColumnAdder),
		actualColumns(src.actualColumns),
		logicalHeight(src.logicalHeight),
		logicalWidth(src.logicalWidth)
	{
	}
	
	CMatrix &operator=(const CMatrix &src)
	{
		this->target = src.target;
		this->unityColumnAdder = src.unityColumnAdder;
		this->actualColumns = src.actualColumns;
		this->logicalHeight = src.logicalHeight;
		this->logicalWidth = src.logicalWidth;
		return *this;
	}

	CMatrix(uint64_t heightT, uint64_t widthT) :
		unityColumnAdder(heightT, 1)
	{
		// create target matrix
		this->target = std::make_shared<CIntegralMatrix>(heightT, widthT);
		
		// create identity mapping
		this->actualColumns.resize(widthT, -1uLL);
		for(uint64_t x = 0; x < widthT; ++x)
		{
			this->actualColumns[x] = x;
		}
		
		this->logicalHeight = heightT + 1;
		this->logicalWidth = widthT;
	}
	
	// Create a zero'd out and ready-to-use matrix of the indicated size.
	static std::shared_ptr<CMatrix> Create(uint64_t heightT, uint64_t widthT)
	{
		return std::make_shared<CMatrix>(heightT, widthT);
	}
	
	uword_t Get(uint64_t y, uint64_t x) const
	{
		if(y >= this->logicalHeight || x >= this->logicalWidth)
		{
			return 0;
		}
	
		uint64_t physicalX = this->actualColumns[x];
		
		if(physicalX == -1uLL)
		{
			return 0;	// this column is all 0s
		}
		
		uword_t adder = 0;
		
		if(x == this->logicalWidth - 1)
		{
			// the rightmost logical column is always a special 'unity' column.
			adder = this->unityColumnAdder.Get(y, 0);
		}
		
		return this->target->Get(y, physicalX).x + adder.x;
	}
	
	// Returns true on success, false in case of failure.
	bool AddToRow(uint64_t y, uword_t adder)
	{
		if(y >= this->logicalHeight)
		{
			return false;
		}
		
		this->unityColumnAdder.Set(y, 0, this->unityColumnAdder.Get(y, 0).x + adder.x);
		
		return true;
	}
	
	// Returns true on success, false otherwise.
	bool Set(uint64_t y, uint64_t x, uword_t src)
	{
		if(y >= this->logicalHeight || x >= this->logicalWidth)
		{
			return false;
		}

		uint64_t physicalX = this->actualColumns[x];
		
		if(physicalX == -1uLL)
		{
			return false;	// tried to set an always-0 column (not allowed!)
		}
		
		this->target->Set(y, physicalX, src);
		
		if(x == this->logicalWidth - 1)
		{
			// zero out adder since we're overwriting the unity column
			this->unityColumnAdder.Set(y, 0, 0);
		}
		
		return true;		// success!
	}
	
	bool ZeroRow(uint64_t y)
	{
		if(y >= this->logicalHeight)
		{
			return false;
		}
		
		this->target->ZeroRow(y);
		
		return true;		// success
	}
	
	bool RowIsAllZeros(uint64_t y) const
	{
		for(uint64_t x = 0; x < this->logicalWidth; ++x)
		{
			if(this->Get(y, x).x != 0)
			{
				return false;
			}
		}
	
		return true;
	}
	
	uint64_t GetActiveHeight() const
	{
		uint64_t rows = 0;
		
		for(uint64_t y = 0; y < this->logicalHeight; ++y)
		{
			if(this->RowIsAllZeros(y) == true)
			{
				continue;
			}
			
			rows = y + 1;
		}
		
		return rows;
	}

	// Warning! Do not ever delete the 'unity' (rightmost) column.
	// Code should be modified to check for that case and return false.
	bool EraseColumn(uint64_t logicalX)
	{
		if(logicalX >= this->logicalWidth)
		{
			return false;
		}
		
		for(uint64_t x = logicalX; x < this->logicalWidth - 1; ++x)
		{
			this->actualColumns[x] = this->actualColumns[x + 1];
		}
		
		this->actualColumns[this->logicalWidth - 1] = -1uLL;
		
		--this->logicalWidth;
		
		return true;
	}
	
	// Returns true on success, false in case of failure.
	bool PromoteConstantColumn(uint64_t logicalX)
	{
		if(logicalX + 1 >= this->logicalWidth)
		{
			return false;	// note: we can't promote the 'unity' column
		}
		
		uint64_t former = this->actualColumns[logicalX];
		
		for(uint64_t x = logicalX; x < this->logicalWidth - 1; ++x)
		{
			this->actualColumns[x] = this->actualColumns[x + 1];
		}
		
		this->actualColumns[this->logicalWidth - 1] = former;
		
		// return the 'unity' column to its former location
		std::swap(this->actualColumns[this->logicalWidth - 1],
			this->actualColumns[this->logicalWidth - 2]
		);
	
		return true;
	}
	
	bool SetLogicalHeight(uint64_t logicalHeightT)
	{
		if(logicalHeightT > this->target->GetHeight())
		{
			return false;
		}
		
		this->logicalHeight = logicalHeightT;
		
		return true;	// success
	}
	
	void Write(std::ostream &os, int row = -1)
	{
		uint64_t height = this->GetActiveHeight();
		
		if(height == 0)
		{
			height = 1;	// just so we get some kind of output when empty
		}
		
		char s[33];
		s[32] = '\0';
		
		for(uint64_t y = (row == -1) ? 0 : row; y < height; ++y)
		{
			for(uint64_t x = 0; x < this->logicalWidth; ++x)
			{
				using namespace std;
				sprintf(s, "%9llX", (unsigned long long int)(this->Get(y, x).x));
				if(x != 0)
					os << " ";
				os << s;
			}
			
			os << "\n";
			
			if(row != -1)
			{
				break;
			}
		}
		os << std::flush;
	}
	
	void AddLinear(uint64_t row, uint64_t varCol, uword_t varCoeff, uword_t adder)
	{
		this->Add(row, varCol, varCoeff);
		this->Add(row, this->logicalWidth - 1, adder);		// unity column
	}
	
	void Add(uint64_t row, uint64_t col, uword_t value)
	{
		this->Set(row, col, this->Get(row, col).x + value.x);
	}
	
	// do not call this to change the value of 'unity' (!) returns true on success, false otherwise.
	bool SetColumnValue(uint64_t logicalX, uword_t value)
	{
		if(logicalX == this->logicalWidth - 1)	// user tried to change the unity column
		{
			return false;
		}
	
		for(uint64_t y = 0; y < this->logicalHeight; ++y)
		{
			uword_t coeff = this->Get(y, logicalX);
		
			if(coeff.x == 0)
			{
				continue;
			}
			
			this->AddToRow(y, coeff.x * value.x);
		}
		
		this->EraseColumn(logicalX);
		
		return true;
	}
	
	void AddRows(uint64_t destY, uint64_t srcY, uword_t scalar)
	{
		if(scalar.x != 0)
		{
			for(uint64_t x = 0; x < this->logicalWidth; ++x)
			{
				this->Add(destY, x, this->Get(srcY, x).x * scalar.x);
			}
		}
	}
	
	// Returns true on success, false otherwise.
	// Note: I experimented with using row reduction to break two rounds of SHA2-256.
	// I left this old, dead code in (note that there is a much better way to break SHA-256
	// once it's been reduced to only two rounds, and the full algorithm has 64 rounds).
	bool RowReduce(std::ostream &os)
	{
		uint64_t m = this->GetActiveHeight();

		os << m << " row(s)" << std::endl;
		os << "Reducing matrix... " << std::flush;
		uint64_t n = this->logicalWidth;
		
		if(m == 0 || n == 0)
		{
			os << "done, is all zeros" << std::endl;
			return true;
		}

		uint64_t skip = 0;
		
		uint64_t lastPercent = -1;
		
		uint64_t progress = 0;
		
		while(skip < m)
		{
			//os << "\rSkip = " << skip << std::endl;
		
			if((progress*100/m) != lastPercent)
			{
				os << "\rReducing matrix... " << (skip*100/m) << "%" << std::flush;
				
				lastPercent = (skip*100/m);
			}
			++progress;
			
			bool done = true;
			
			for(uint64_t y = skip; y < m; ++y)
			{
				if(RowIsAllZeros(y) == false)
				{
					done = false;
					
					break;
				}
			}
			
			if(done)
			{
				break;
			}
			
			uint64_t pivotX = this->DetermineLeftmostNonzeroColumn(skip, m, n);
			
			if(pivotX >= n - 1)
			{
				if(pivotX == n)
				{
					continue;
				}
				
				os << "\rReducing matrix... failure! contradiction detected." << std::endl;
				os << "Col " << pivotX << " value " << std::hex << this->Get(skip, pivotX).x << std::dec << std::endl;
				
				for(uint64_t y = skip; y < m; ++y)
				{
					if(this->Get(y, pivotX).x == 0)  continue;
					bool ok = false;
					for(uint64_t xx = 0; xx < pivotX; ++xx)
					{
						if(this->Get(y, xx).x != 0)
						{
							ok = true;
							break;
						}
					}
					if(ok)  continue;
					
					os << "Row " << y << " value " << std::hex << this->Get(y, pivotX).x << std::dec << std::endl;
					break;
				}
				
				return false;
			}
			
			uint64_t powers[WORD_SIZE_BITS + 1];
			
			for(uint64_t i = 0; i < WORD_SIZE_BITS + 1; ++i)
			{
				powers[i] = n;
			}
			
			uint64_t lowestPower = WORD_SIZE_BITS + 1;
			
			// Built histogram-like thing.
			for(uint64_t y = skip; y < m; ++y)
			{
				uint64_t x = GetLeadingNonzeroColumn(y, n);
				
				if(x >= n - 1)
				{
					continue;
				}
				
				uword_t value = this->Get(y, x);
				
				uword_t scalar = value.GetScalarForPowerOfTwo();
				
				if(scalar.x != 1u)
				{
					this->MultiplyRow(y, scalar);
				}
				
				value = this->Get(y, pivotX);
				
				if(value.x == 0)
				{
					continue;
				}
				
				uint32_t shift = 0;
				
				while(value.x != 1u)
				{
					++shift;
					
					value.x >>= 1;
				}
				
				if(powers[shift] != n)
				{
					continue;
				}
				
				powers[shift] = y;
				
				if(shift < lowestPower)
				{
					lowestPower = shift;
				}
			}
			
			if(lowestPower == WORD_SIZE_BITS + 1)
			{
				os << "\rReducing matrix... failure! internal error." << std::endl;
				
				return false;
			}
			
			uint64_t pivotY = skip;
			
			
			// Let's put our "lowest power" row in row 'pivotY'.
			uint64_t srcY = powers[lowestPower];
			
			if(srcY != pivotY)
			{
				for(uint64_t x = 0; x < n; ++x)
				{
					uword_t temp = this->Get(srcY, x);
					
					this->Set(srcY, x, this->Get(pivotY, x));
					
					this->Set(pivotY, x, temp);
				}
			}
			
			
			// Put zero's beneath row 'pivotY'.
			uword_t src = this->Get(pivotY, pivotX);
			
			for(uint64_t y = pivotY + 1; y < m; ++y)
			{
				uword_t dest = this->Get(y, pivotX);
				
				if(dest.x == 0)
				{
					continue;
				}
				
				uword_t scalar = dest.x / src.x;

				//os << std::hex << dest.x << " / " << src.x << " = " << scalar.x << std::dec << std::endl;
				
				for(uint64_t x = 0; x < n; ++x)
				{
					this->Set(y, x, this->Get(y, x).x - this->Get(pivotY, x).x * scalar.x);
				}
				
				if(this->Get(y, pivotX).x != 0)
				{
					os << "\rReducing matrix... failure! internal error 2." << std::endl;
					
					return false;
				}
			}
			
			// Check for any non-unity column values with the sign bit set. Subtract and add in to unity column if found.
			bool mustRepeat = false;
			
			/* this doesn't apply anymore now that our operands are 0 or 1 again
			for(uint64_t x = 0; x < n - 1; ++x)
			{
				uword_t value = this->Get(skip, x);
				
				if(value.x >= (1uLL << WORD_SIZE_BITS))
				{
					mustRepeat = true;

					// coefficients are always precisely +1 or -1, and thus are never 0.
					// (2^32 + 2^30) * X = (2^32 * X) + (2^30 * X) = 2^32 + (2^30 * X).
					this->Set(skip, x, value.x - (1uLL << WORD_SIZE_BITS));
					
					this->Set(skip, n - 1, this->Get(skip, n - 1).x + (1uLL << WORD_SIZE_BITS));
				}
			}
			*/
			
			// Finish up.
			if(mustRepeat == false && this->RowIsAllZeros(skip) == false)
			{
				++skip;
			}
		}
		
		os << "\rReducing matrix... done          " << std::endl;
	
		return true;
	}
	
	void MultiplyRow(uint64_t y, uword_t scalar)
	{
		for(uint64_t x = 0; x < this->logicalWidth; ++x)
		{
			this->Set(y, x, this->Get(y, x).x * scalar.x);
		}
	}
	
	uint64_t GetLeadingNonzeroColumn(uint64_t y, uint64_t n)
	{
		uint64_t x = n;
		
		for(uint64_t xx = 0; xx < n; ++xx)
		{
			if(this->Get(y, xx).x != 0)
			{
				x = xx;
				
				break;
			}
		}
		
		return x;
	}

	uint64_t DetermineLeftmostNonzeroColumn(uint64_t skip, uint64_t m/*height*/, uint64_t n/*width*/)
	{
		uint64_t pivotX = n;	// this will be the return value if there is no leftmost nonzero column
	
		for(uint64_t x = 0; x < n; ++x)
		{
			bool columnIsAllZeros = true;
			
			for(uint64_t y = skip; y < m; ++y)
			{
				uword_t first = this->Get(y, x);

				if(first.x == 0)
				{
					continue;
				}

				columnIsAllZeros = false;
				
				break;
			}
			
			if(columnIsAllZeros == false)
			{
				pivotX = x;
				
				break;
			}
		}
		
		return pivotX;
	}
};

typedef std::shared_ptr<CMatrix> RMatrix;

#endif	// l_matrix_h__formal_included


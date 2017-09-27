// compute1.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// see build.txt
//
// g++ -I./h -std=c++11 -o compute1.out compute1.cpp
//
// ./compute1.out
//
// This program uses the 'sha2_256_out.txt' file as input.
//
// The SHA2-256 value of the following sentence, with an appended new-line (only one 0x0a, and no x0d characters), is
// 253736f3ba044d4373df1aa89022762663a47cae6577aefd35f3926973572302:
// You're with another special project now, Grandma! Special education students in New York will remember Captain Muriel Bliss and the Some Have crew.

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

// This program uses the associated text files to perform
// a sample SHA2-256 computation. The computation
// is done in a fully linear (but iterative, i.e. row-at-a-time instead of all-at-once) way, and
// the text files represent a matrix of non-negative integer
// coefficients. The matrix has about 20,000 columns and rows.
//
// Each row is used to determine variable values at run time,
// and each column represents either a temporary, unknown,
// or constant. The rightmost constant is also the rightmost
// column and represents unity. The order of the columns,
// from left to right, in this matrix is: unknowns, then
// temporaries, then constants. In this matrix, however, there are
// no 'unknowns'.

#include <stddef.h>

#include <stdio.h>

#include <string.h>

#include <stdint.h>

#include <iostream>

#include <fstream>

#include <vector>

#include <stdlib.h>

uint32_t sha256_initial_h[8] =
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

// Returns true to indicate success, false to indicate failure.

bool get_input(int argc, char *argv[], uint32_t input_w[16])
{
	// This can be changed, if so desired.
	std::cout << "hellosir" << std::endl;
	//input_w[0] = ('g' << 0) + ('N' << 8) + ('O' << 16) + ('L' << 24);   // another
	//input_w[0] = ('t' << 0) + ('s' << 8) + ('e' << 16) + ('t' << 24);   // sample
	input_w[0] = ('l' << 0) + ('l' << 8) + ('e' << 16) + ('h' << 24);   // message to digest ("test")
	input_w[1] = ('r' << 0) + ('i' << 8) + ('s' << 16) + ('o' << 24);   // message to digest ("test")
	input_w[2] = 0x80000000u;                                           // marker bit
	input_w[14] = 0;                                                    // message length, high 32 bits
	input_w[15] = (8 * 8);                                              // message length, low 32 bits
	// End section that can be changed.

	return true;  // indicate success
}

uint64_t get_sign_mask()
{
  uint64_t value = 2;

  value <<= 16;

  value <<= 16;

  return value - 1;  // return 2**33-1
}

uint64_t get_sign_constant()
{
  return 0x100000000uLL;
}

class CLinearSha2_256_Implementation
{
public:
  CLinearSha2_256_Implementation(std::vector<int> &yaTemps) :
    values(NULL),
    known(NULL),
    yTemps(yaTemps)
  {
  }

  virtual ~CLinearSha2_256_Implementation()
  {
    delete [] values;

    delete [] known;
  }

  void init(int numTa, int numXa, int numCa, int numYa)
  {
    numT = numTa;

    numX = numXa;

    numC = numCa;

    numY = numYa;

    delete [] values;

    delete [] known;

    values = new uint64_t [numT + numX + numC];
    
    known = new bool [numT + numX + numC];

    memset(values, 0, sizeof(uint64_t) * (numT + numX + numC));

    memset(known, 0, sizeof(bool) * (numT + numX + numC));

    // there are (numT + numX + numC) columns, in total, making up a row.

    // the column order is X's first, then T's, then C's.
    // (for this implementation, there are no X's).

    // the final C is unity, which means its value is always 1.

    // T means temporary variable (some might be output variables);
    // X means unknown variable and doesn't apply for this implementation;
    // and C means constant.

    values[numT + numX + numC - 1] = 1;

    for(size_t i = 0; i < numC; ++i)
    {
      known[numT + numX + i] = true;
    }
  }

  // c[1..512] represent the input W values.

  void InitializeW(uint32_t inputW[16])
  {
    for(uint32_t i = 0; i < 512; ++i)
    {
      if(((inputW[i / 32] >> (i & 31)) & 1u) != 0)
      {
        // note: c[0] became unity, so the first constant variable is
        // really c[1].

        values[(i + 1) - 1 + numX + numT] = 1;

        known[(i + 1) - 1 + numX + numT] = true;
      }
      else
      {
        values[(i + 1) - 1 + numX + numT] = 0;
        
        known[(i + 1) - 1 + numX + numT] = true;
      }
    }
  }

  // c[513..513+256-1] represents the input H values.

  void InitializeH(uint32_t inputH[8])
  {
    for(uint32_t i = 0; i < 256; ++i)
    {
      if(((inputH[i / 32] >> (i & 31)) & 1u) != 0)
      {
        // reminder: the first constant is really c[1],
        // and the 'last' constant is unity, i.e. c[0].

        values[(513 + i) - 1 + numX + numT] = 1;

        known[(513 + i) - 1 + numX + numT] = true;
      }
      else
      {
        values[(513 + i) - 1 + numX + numT] = 0;

        known[(513 + i) - 1 + numX + numT] = true;
      }
    }
  }

  // returns true if successful, false if otherwise.

  bool acceptRow(int rowNumber, uint64_t row[])
  {
    // there are (numT + numX + numC) columns, in total, making up a row.

    // the column order is X's first, then T's, then C's.

    // we assume there are no X's.

    if(numX != 0 || rowNumber >= numT)
    {
	std::cout << "\nFail case A" << std::endl;

      return false;
    }

    int i = 0;

//for(i = 0; i < numT; ++i)
//{
//  if(row[i] != 0)  break;
//}
//std::cout << " rowN " << rowNumber << " " << row[i] << " " << i << std::endl;
//i = 0;

    int ii = 0;

    for(i = rowNumber + 1; i < numT; ++i)
    {
      if(row[i] != 0)
      {
	std::cout << "\nFail case BB" << std::endl;

	std::cout << "Fail, row " << (int) rowNumber << std::endl;

	return false;
      }
    }

    // This is called the 'definer coefficient' in the row in question.
    // Its column determines the variable whose value is being defined
    // by matrix row in question.
    if(row[rowNumber] != get_sign_constant())
    {
	std::cout << "\nFail case B" << std::endl;

        std::cout << "Fail, row " << (int) rowNumber << " " << row[rowNumber] << std::endl;

        return false;
    }

if(false)
    for(int ik = 0; ik < numT - 1 - i; ++ik)
    {
	if(row[ik] != 0)
	{
		std::cout << "\nTest fail " << ik << " " << numT - 1 - i << std::endl;

		return false;
	}
    }

    // column 'i' is the 'definer coefficient'. The corresponding row
    // of the output state column vector, is the value whose value we're
    // determining for this step, i.e. for the computation involving the
    // present matrix row of coefficients. we can assume, at this time,
    // that the corresponding input state vector row's element value is
    // 0 at present, and if the corresponding output state vector row's
    // element value is not congruent to 0 subject to a modulo of two
    // to the power of 33, then it will instead be congruent to two to
    // the power of 32 exactly subject to the same modulo, and we are
    // to 'flip' the input state vector row's element value from 0 to
    // 1 for the purpose of subsequent matrix row computations. certain
    // output state (column) vector element values are temporaries which
    // are also outputs.

    	///std::cout << "    " << numT - 1 - i << " " << rowNumber << " " << numT << std::endl;
	///return true;

    if(rowNumber >= numT)
    {
	std::cout << "\nFail case C" << std::endl;

      return false;
    }

    ii = i;

    struct {
      uint64_t x : 33;
    } value;

    value.x = 0;

    // This is our linear computation step. It effectively
    // multiplies one row of coefficients, by some input column state
    // vector, to produce some corresponding state vector's element
    // value; the value at a particular row, namely row 'rowNumber'.
    // 0 is the value assumed for anything not already known, and this
    // is an 'iterative', instead of all-at-once, matrix multiplication
    // computation. By the process called Convergent Linear Analysis,
    // then cryptosystems like SHA2-256 can be effectively linearized
    // into a matrix of (in this case, 33-bit unsigned integer)
    // coefficients, which can then be used instead of the original
    // algorithm description to achieve the same effects, i.e. to perform
    // the SHA2-256 algorithm's computation, itself. See also the
    // sha2_256_out.txt data file, as well as build.txt and the rest of
    // the source code, for details.

    for(i = 0; i < numT + numX + numC; ++i)
    {
      value.x += row[i] * values[i];
      /*
      if(i < numT && i >= rowNumber)  continue;

      if(row[i] == 0)  continue;

      if(!known[i])
      {
        std::cout << "\nFail !!!" << std::endl;

        return false;
      }

      if(values[i] != 0)  value.x += row[i];
      */
    }

    //value &= get_sign_mask();

    if(row[rowNumber] != get_sign_constant())
    {
	std::cout << "\nFail case C" << std::endl;

      std::cout << "Fail 2\n" << std::endl;

      return false;
    }

    //bool newValue = 0;

    if(value.x != 0)
    {
      if(value.x != get_sign_constant())
      {
	std::cout << "\nFail case DD" << std::endl;

        std::cout << "Fail 1" << std::endl;

        return false;
      }

      //newValue = 1;
      //values[rowNumber] = 1;
    }
    else
    {
      //values[rowNumber] = 0;
    }
    
    // note: because of our use of a power-of-two modulo, the following division operation is technically not 'linear', at least not
    // in the sense one intends when one uses matrix multiplication to perform a whole computation at once. in an 'iterative' process,
    // one computes the value of the column vectors that result from performing the matrix multiplication, one row at a time -- and one
    // is allowed to do something after each computation, as one is now more or less interactive, with each row being used for a dot
    // product, and that, at least is fully linear. the result is then taken subject to the correct power-of-two modulo, i.e. 2^33 in
    // our case, and the value will then be equal to 2^32 times the value we just determined for the temporary variable in question.
    // (recall that certain temporary variables, are also output variables and represent an output bit; others, were only 'internal'
    // operands in the directed acyclic graph that we converted the original cryptosystem algorithm into).
    values[rowNumber] = value.x / ((1uLL << 16) << 16);

    known[rowNumber] = true;

    return true;
  }

  void fetchResultH(uint32_t valueH[8])
  {
    memset(valueH, 0, sizeof(uint32_t) * 8);

    for(uint32_t i = 0; i < 256; ++i)
    {
      if(values[yTemps[i]] != 0)
      {
        valueH[i / 32] |= (1u << (i & 31));
      }
    }
  }

public: //private:
  // only the low 33 bits of the elements of this array are signficant.
  uint64_t *values;

  bool *known;

  std::vector<int> &yTemps;

  int numT;

  int numX;

  int numC;

  int numY;
};

int main(int argc, char *argv[])
{
  // You're with another special project now, Grandma!
  // 253736f3ba044d4373df1aa89022762663a47cae6577aefd35f3926973572302

  std::ifstream fis("sha2_256_out.txt");

  if(!fis)
  {
    std::cout << "sha2_256_out.txt must exist." << std::endl;

    return 1;
  }

  uint32_t input_w[16];

  memset(input_w, 0, sizeof(input_w));
  
  if(!get_input(argc, argv, input_w))
  {
    return 1;
  }

  std::cout << "\nOpened file: sha2_256_out.txt\n" << std::endl;

  std::vector<int> yTemps;

  int numT = 0, numX = 0, numC = 0;  // this should be 1025 !

  char *line = new char[(numT + numX + numC) * 9 + 18];

  memset(line, 0, (numT + numX + numC) * 9 + 18);

  if(fis)
  {
    int count = 0;

    for(;;)
    {
      int yT = 0, tempT = 0;

      char yc = 0;

      fis >> yc;

      if(yc != 'Y')
      {
        std::cout << "\nError [1] with sha2_256_out.txt" << std::endl;

        return 0;
      }

      fis >> yT;

      fis >> tempT;

      if(yT == -1)  break;

      if(yT != count)
      {
        std::cout << "\nError with sha2_256_out.txt" << std::endl;

        return 0;
      }

      yTemps.push_back(tempT);

      ++count;
    }

    //std::cout << yTemps.size() << std::endl;

    char cInt = 0;

    int xInt = 0;

    fis >> cInt;

    fis >> xInt;

    if(cInt == 'T')  numT = xInt;
    if(cInt == 'C')  numC = xInt;

    //std::cout << cInt << " " << xInt << std::endl;

    fis >> cInt;

    fis >> xInt;

    if(cInt == 'T')  numT = xInt;
    if(cInt == 'C')  numC = xInt;

    fis >> cInt;

    fis >> xInt;

    if(cInt == 'T')  numT = xInt;
    if(cInt == 'C')  numC = xInt;

    std::cout << numT << " 0 " << numC << "\n" << std::endl;
  }

  uint64_t *row = new uint64_t [numT + numX + numC];

  memset(row, 0, sizeof(uint64_t) * (numT + numX + numC));

  CLinearSha2_256_Implementation sha2Impl(yTemps);

  sha2Impl.init(numT, numX, numC, 256);

  // This is specific to the computation we want to run.

  // Use default (i.e. from spec) SHA2-256 values.
  // This can be changed, if so desired.
  sha2Impl.InitializeH(sha256_initial_h);
  // End section that can be changed.

  sha2Impl.InitializeW(input_w);

  int remain = numT;

  uint64_t a = 0;

  char t[1024];

  t[0] = t[1023] = 0;

  int cc = 0;

  int rowNum = 0;

  int colNum = 0;

  int count_t = 0;

  int tempsRemaining = numT;

  int prob = 1;

  for(;;)
  {
    std::cout << "\r" << (numT - tempsRemaining) << "/" << numT << std::flush;

    if(tempsRemaining-- == 0)
    {
      std::cout << "\r" << (numT - tempsRemaining + 1) << "/" << numT << std::flush;

      break;
    }

    bool cont = false;

    size_t columnNum = 0;

    uint64_t value = 0;

    memset(row, 0, sizeof(uint64_t) * (numT + numX + numC));

    bool valid = false;

    int valid_count = 0;

    for(size_t i = 0;;)
    {
      fis >> line;

      if(strcmp(line, "begin") == 0)
      {
        if(valid)
        {
          std::cout << "Fail Case A" << std::endl;

          return 1;
        }

        valid = true;

	valid_count = 0;

	fis >> line;
      }

      ++valid_count;

      if(strlen(line) != 9)
      {
          std::cout << "\nInvalid file 1: " << " " << i << " [" << (line) << "]" << std::endl;

          delete [] row;

	  delete [] line;

          return 1;
      }

      value = strtoll(line, NULL, 16);

      row[columnNum++] = value;

      if(valid_count == numT + numX + numC)
      {
        //std::cout << "Fail Excess" << std::endl;

        break;
      }
    }

    if(columnNum != (numT + numX + numC))
    {
      std::cout << "\nInvalid file 4: " << std::endl;

      delete [] row;

      delete [] line;

      return 1;
    }

    if(!sha2Impl.acceptRow(rowNum, row))
    {
      std::cout << "\nFail, row " << (int)rowNum << std::endl;

      delete [] row;

      delete [] line;

      return 1;
    }

    //line = "";

    ++rowNum;

    colNum = 0;

    continue;
  }

  uint32_t outputH[8];

  memset(outputH, 0, sizeof(uint32_t) * 8);

  sha2Impl.fetchResultH(outputH);

  std::cout << "\n\nResult:\n" << std::endl;

  for(size_t i = 0; i < 8; ++i)
  {
    char s[33];

    s[0] = s[32] = 0;
    
    sprintf(s, "%08llx", (unsigned long long)outputH[i]);

    std::cout << s;
  }
  
  std::cout << "\n" << std::endl;

  if(false)
  {
    std::cout << std::endl;

    std::cout << "\nAbove value was computed. Below are pre-programmed SHA2-256" << std::endl;
    std::cout << "values, for comparison purposes:\n" << std::endl;

    std::cout << "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 [test]" << std::endl;
    std::cout << "f37a425b44e74b702828d910449f5bb11f0564d65757c2b0a8679e949427878b [hellosir]" << std::endl;
  }

  if(false)
  {
    // also write the result to a file?
    std::ofstream fo("result.txt");

    fo << "\nCompuation result:" << std::endl;

    for(size_t i = 0; i < 8; ++i)
    {
      char s[33];

      s[0] = s[32] = 0;
    
      sprintf(s, "%08x", outputH[i]);

      fo << s;
    }

    fo << std::endl;
  }

  delete [] row;

  delete [] line;

  return 0;
}


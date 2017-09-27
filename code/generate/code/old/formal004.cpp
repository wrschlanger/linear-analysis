// formal004.cpp - by Willow Schlanger. Released to the Public Domain in August of 2017.
// To build:
//   g++ -std=c++11 -o formal004.out formal004.cpp formcrypto.cpp -lgmp -lgmpxx -O9
// --------------------------------------------------------------------------------
// This program represents the following two equations:
// t[0] = ((1) x[0] + (1) x[1]) mod 2
// t[1] = ((1/2) x[0] + (1/2) x[1] + (-1/2) t[0]) mod 2 = 1
// (i.e. x0 AND x1 = 1).
// ================================================================================

#include "formcrypto.h"

#include <iostream>
#include <cstdio>

int main()
{
	using namespace formal_crypto;

	/* This works.
	CUtilSha256::SelfTest(std::cout);
	*/
	
	CCryptosystem cSystem;
	
	// y0 = (x0 + x1) mod 2 = x0 ^ x1
	cSystem.inputOperands.push_back(cSystem.CreateOperand(E_OPERAND_INPUT, 0));		// create 'x0'
	cSystem.inputOperands.push_back(cSystem.CreateOperand(E_OPERAND_INPUT, 1));		// create 'x1'
#if 0
	cSystem.userOutputOperands.push_back(cSystem.CreateOperand(E_OPERAND_TEMP, 0));		// create 'y0'
#endif
	cSystem.userOutputOperands.push_back(cSystem.CreateOperand(E_OPERAND_TEMP, 1));		// create 'y1'
	
	ROperator temp1 = cSystem.CreateOperator();			// create operator for y0
	temp1->AddOperand(cSystem.inputOperands[0]);
	temp1->AddOperand(cSystem.inputOperands[1]);			// let the operator equal the sum of x0 and x1
#if 0
	cSystem.userOutputOperands[0]->sourceOp = temp1;
#else
	ROperand temp1op = cSystem.CreateOperand(E_OPERAND_TEMP);
	temp1op->sourceOp = temp1;
#endif
	
	// y1 = .5 x0 + .5 x1 - .5 y0 = x0 AND x1
	ROperator temp2 = cSystem.CreateOperator();
	temp2->AddOperand(cSystem.inputOperands[0], mpq_class(1, 2));
	temp2->AddOperand(cSystem.inputOperands[1], mpq_class(1, 2));
#if 0
	temp2->AddOperand(cSystem.userOutputOperands[0], mpq_class(-1, 2));
	cSystem.userOutputOperands[1]->sourceOp = temp2;
#else
	temp2->AddOperand(temp1op, mpq_class(-1, 2));
	cSystem.userOutputOperands[0]->sourceOp = temp2;	// y1 is now at position 0
#endif
	
	// Let's evaluate our system to ensure we get the right truth table.
	std::vector<bool> inputValues(cSystem.inputOperands.size(), 0);
	std::vector<bool> constantValues(cSystem.constantOperands.size(), 0);
	std::vector<bool> outputValues(cSystem.userOutputOperands.size(), 0);
	constantValues[cSystem.GetUnity()->bitIndexLabel] = 1;

	std::cout << "Truth table:" << std::endl;
	for(int x0 = 0; x0 < 2; ++x0)
	{
		for(int x1 = 0; x1 < 2; ++x1)
		{
			inputValues[0] = x0;
			inputValues[1] = x1;
			
			outputValues[0] = 0;
			outputValues[1] = 0;
			
			if(cSystem.Compute(inputValues, constantValues, outputValues) == false)
			{
				std::cout << "Compute failure" << std::endl;
				continue;
			}
			
#if 0
			std::cout << x0 << " " << x1 << " -> " << outputValues[0] << " " << outputValues[1] << std::endl;
#else
			std::cout << x0 << " " << x1 << " -> " << outputValues[0] << std::endl;
#endif
		}
	}

	// Set success criteria. These MUST be set prior to calling "flatten". In theory they need not be set to 0 or 1 though,
	// and could be set e.g. to a 'constant operand' (I think?)
	// The first criteria says we need (x0 ^ x1) to be 0, e.g. we need x0 = x1.
#if 0
	cSystem.userOutputOperands[0]->targetOp = cSystem.GetZero();	// demand y0 = 0
	
	// The second criteria says we need (x0 AND x1) to be 0, e.g. we can't have x0 = x1 = 1.
	cSystem.userOutputOperands[1]->targetOp = cSystem.GetZero();	// demand y1 = 0
#else
	cSystem.userOutputOperands[0]->targetOp = cSystem.GetOne();	// demand y1 = 1 (now at position 0)
#endif

	// Our next step is to "flatten" the cryptosystem and possibly write out the equations to a text file for inspection.
	// This will add temporaries as needed.
	if(cSystem.Flatten(std::cout) == false)
	{
		return false;
	}
	
	std::cout << "\nEquations:" << std::endl;
	cSystem.WriteEquationsText(std::cout);

	return 0;
}


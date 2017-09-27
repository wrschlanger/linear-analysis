// common.h - by Willow Schlanger. Released to the Public Domain in August of 2017.

#ifndef l_common_h__included_nextbreak
#define l_common_h__included_nextbreak

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum
{
	WORD_SIZE_BITS = 32
};

class CWord
{
public:
	typedef uint64_t ValueType;

protected:
	ValueType x : WORD_SIZE_BITS + 1;

public:
	CWord() :
		x(0)
	{
	}
	
	CWord(ValueType src) :
		x(src)
	{
	}
	
	CWord(const CWord &src) :
		x(src.x)
	{
	}
	
	CWord &operator=(ValueType src)
	{
		this->x = src;
		
		return *this;
	}
	
	CWord &operator=(const CWord &src)
	{
		this->x = src.x;
		
		return *this;
	}
	
	ValueType operator()() const
	{
		return this->x;
	}
};

#endif	// l_common_h__included_nextbreak


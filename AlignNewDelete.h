
// ****************************************************************************
// File: AlignNewDelete.h
// Desc: Class/struct memory alloc align 16 new/delete override
// Auth: Sirmabus 2012
//
// ****************************************************************************
#pragma once
#include <new>

/*
	Override a classes default new/delete operators with a align 16 (partial cache line)
	allocations for performance and SIMD/SSE instruction data requirements.

	Example usage:
	// Your class
	class MyClass : public AlignNewDelete
	{
	};

	Now all of this class instances created with new (not compiler ones, they will use the stack!)
	and it's internal new/delete operator calls will be aligned allocations.
	You can and should verify the behavior in a debugger at least once by putting a break point
	on the base new() and delete() and steping through class instance invocations, etc.
*/

// References and further reading:
// http://www.gamasutra.com/view/feature/3942/data_alignment_part_1.php
// http://www.gamasutra.com/view/feature/3975/data_alignment_part_2_objects_on_.php
// http://stdcxx.apache.org/doc/stdlibref/operatornew.html
// http://stdcxx.apache.org/doc/stdlibref/operatordelete.html
// http://www.informit.com/guides/content.aspx?g=cplusplus&seqNum=40


class __declspec(align(16)) AlignNewDelete
{
public:
	// -------------- New operators --------------
	inline void* __cdecl operator new(size_t _Size)
	{
		if(_Size <= 0) _Size = 1;
		if(void *p = _aligned_malloc(_Size, 16))
			return(p);
		else
			throw std::bad_alloc();
	}

	inline void* __cdecl operator new(size_t, void *_Where)
	{
		return(_Where);
	}

	void* __cdecl operator new[](size_t _Size)
	{
		return(operator new(_Size));
	}

	inline void* __cdecl operator new[](size_t, void *_Where)
	{
		return(_Where);
	}

	inline void * __cdecl operator new(size_t _Size, const std::nothrow_t&)
	{
		if(_Size <= 0) _Size = 1;
		return(_aligned_malloc(_Size, 16));
	}

	inline void * __cdecl operator new[](size_t _Size, const std::nothrow_t &_NoThrow)
	{
		return(operator new(_Size, _NoThrow));
	}

	// -------------- Delete operators --------------
	inline void __cdecl operator delete(void *p)
	{
		_aligned_free(p);
	}

	inline void __cdecl operator delete(void *, void *)
	{
	}

	inline void __cdecl operator delete[](void *p)
	{
		operator delete(p);
	}

	inline void operator delete[](void*, void*)
	{
	}

	inline void __cdecl operator delete(void *p, const std::nothrow_t&)
	{
		operator delete(p);
	}

	inline void __cdecl operator delete[](void *p, const std::nothrow_t&)
	{
		operator delete(p);
	}
};

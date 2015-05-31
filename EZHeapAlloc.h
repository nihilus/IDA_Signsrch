
// std lib alloc replacement to use our own global heap
// Based Pete Isensee's articles
//

#pragma once
#include <memory>

template <typename _Ty> class EZHeapAlloc
{
public:
	typedef size_t      size_type;
	typedef ptrdiff_t   difference_type;
	typedef _Ty*        pointer;
	typedef const _Ty*  const_pointer;
	typedef _Ty&        reference;
	typedef const _Ty&  const_reference;
	typedef _Ty         value_type;

	// convert an allocator<_Ty> to an allocator <_Other>
	template <typename _Other> struct rebind
	{
		typedef EZHeapAlloc<_Other> other;
	};

	// return address of mutable _Val
	pointer address(reference _Val) const
	{
		return(&_Val);
	}

	// return address of non-mutable _Val
	const_pointer address(const_reference _Val) const
	{
		return(&_Val);
	}

	// Constructors
	EZHeapAlloc() throw() {}
	EZHeapAlloc(const EZHeapAlloc&) throw() {}
	template <typename _Other> EZHeapAlloc(const EZHeapAlloc<_Other> &) throw() {}

	EZHeapAlloc &operator=(const EZHeapAlloc &ha)
	{
		return(*this);
	}

	// Destructor
	~EZHeapAlloc() throw() {	}

	pointer allocate(size_type _Count)
	{
		return(pointer(Heap().Alloc(_Count * sizeof(_Ty))));
	}

	void deallocate(pointer _Ptr, size_type)
	{
		Heap().Free(_Ptr);
	}


	// construct object at _Ptr with value _Val
	void construct(pointer _Ptr, const _Ty& _Val)
	{
		std::_Construct(_Ptr, _Val);
	}

	// destroy object at _Ptr
	void destroy(pointer _Ptr)
	{
		std::_Destroy(_Ptr);
	}

	size_t max_size() const
	{
		size_t _Count = ((size_t)(-1) / sizeof (_Ty));
		return(((0 < _Count) ? _Count : 1));
	}
};

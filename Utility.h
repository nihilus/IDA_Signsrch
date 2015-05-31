
// ****************************************************************************
// File: Utility.h
// Desc: Utility stuff
//
// ****************************************************************************
#pragma once

// Size of string with out terminator
#define SIZESTR(x) (sizeof(x) - 1)

#define ALIGN(_x_) __declspec(align(_x_))

// Stack alignment trick, based on Douglas Walker's post
// http://www.gamasutra.com/view/feature/3975/data_alignment_part_2_objects_on_.php
#define STACKALIGN(name, type) \
	BYTE space_##name[sizeof(type) + (16-1)]; \
	type &name = *reinterpret_cast<type *>((UINT_PTR) (space_##name + (16-1)) & ~(16-1))

// Time
typedef double TIMESTAMP;  // Time in floating seconds
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)
#define DAY    (HOUR * 24)

TIMESTAMP getTimeStamp();
void trace(LPCSTR format, ...);
long fsize(FILE *fp);
char *replaceNameInPath(char *pszPath, char *pszNewName);
LPCSTR timeString(TIMESTAMP time);
LPCTSTR byteSizeString(UINT64 uSize);
LPSTR  prettyNumberString(UINT64 n, __bcount(32) LPSTR buffer);

#define CATCH() catch (...) { msg("** Exception in %s()! ***\n", __FUNCTION__); }

// Tick IDA's Qt message pump so it will show msg() output
#define refreshUI() WaitBox::processIdaEvents()

#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC__ __FILE__ "("__STR1__(__LINE__)") : Warning MSG: "
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "
// Now you can use the #pragma message to add the location of the message:
//
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")

// ea_t zero padded hex number format
#ifndef __EA64__
#define EAFORMAT "%08X"
#else
#define EAFORMAT "%016I64X"
#endif

// Sequential 32 bit flag serializer
struct SBITFLAG
{
	inline SBITFLAG() : Index(0) {}
	inline UINT First(){ Index = 0; return(1 << Index++); }
	inline UINT Next(){ return(1 << Index++); }
	UINT Index;
};


// Private heap for easy management with align 16 and better cache cohesion, etc.
class EZHeap : public AlignNewDelete
{
public:
	EZHeap() : m_hHeap(NULL)
	{
		if(m_hHeap = ::HeapCreate(HEAP_CREATE_ALIGN_16, 0, 0))
		{
			// HeapAlloc() actually faster then the default CRT malloc() (At least on Windows XP SP3 32bit)
			// Only works if HeapCreate(x, 0, 0), and not while debugging.
			// Low fragmentation heap
			ULONG uLFHFlag = 2;
			::HeapSetInformation(m_hHeap, HeapCompatibilityInformation, &uLFHFlag, sizeof(ULONG));
		}
		assert(m_hHeap);
	}

	~EZHeap()
	{
		if(m_hHeap)
		{
			//Trace("HeapCompact: %d\n", HeapCompact(m_hHeap, 0));
			BOOL bSuccess = ::HeapDestroy(m_hHeap);
			m_hHeap = NULL;
			assert(bSuccess);
		}
	}

	inline PVOID Alloc(size_t Size)
	{
		assert(m_hHeap != NULL);
		return(::HeapAlloc(m_hHeap, 0, Size));
		//if(p == NULL) throw std::bad_alloc();
	}

	PVOID Realloc(PVOID lpMem, size_t Size)
	{
		assert(m_hHeap != NULL);
		if(!lpMem)
			return(Alloc(Size));
		else
			return(::HeapReAlloc(m_hHeap, 0, lpMem, Size));
	}

	inline void Free(PVOID lpMem)
	{
		if(lpMem)
		{
			BOOL bSuccess = ::HeapFree(m_hHeap, 0, lpMem);
			assert(bSuccess);
		}
	}

	// Call Free() to free up string when done
	LPSTR strdup(LPSTR pszIn)
	{
		if(int iLen = strlen(pszIn))
		{
			if(LPSTR pszOut = reinterpret_cast<LPSTR>(Alloc(++iLen)))
			{
				memcpy(pszOut, pszIn, iLen);
				return(pszOut);
			}
		}
		return(NULL);
	}

private:
	HANDLE m_hHeap;
};

// Instance a EZHeap singleton style
#define INSTANCE_EZHeap(name)					\
inline EZHeap &name()							\
{												\
	static EZHeap *pNewHeap = new EZHeap();		\
	return(*pNewHeap);							\
}

// My plug-in heap
extern EZHeap &Heap();

// Type alloc cleaness for my Heap() allocations
template <typename _Ty> _Ty *TAlloc(size_t Elements){  return((_Ty *) Heap().Alloc(Elements * sizeof(_Ty))); }
template <typename _Ty> _Ty *TRealloc(_Ty *lpMem, size_t Elements){  return((_Ty *) Heap().Realloc(lpMem, Elements * sizeof(_Ty))); }
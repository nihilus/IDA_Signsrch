
// code provided by Andrew based on the work of David Musser and Nishanov
// http://www.team5150.com/~andrew/
// http://www.cs.rpi.edu/~musser/gp/gensearch/index.html
#include "stdafx.h"

#define HASH_RANGE_MAX	512
#define SUFFIX_SIZE		2

static inline int Hash(PBYTE  pData)
{
	return((((int) pData[-1]) + ((int) pData[0])) & (HASH_RANGE_MAX - 1));
}

static int SearchSmallpat(PBYTE pSrc, int iSrcLen, PBYTE  pPattern, int iPatternLen)
{
	if(!iSrcLen || !iPatternLen || (iPatternLen > iSrcLen))
		return(-1);

	PBYTE pLimit = (pSrc + iSrcLen - iPatternLen);
	for(PBYTE p = pSrc; p <= pLimit; p++)
	{
		if(!memcmp(p, pPattern, iPatternLen))
			return(p - pSrc);
	}

	return(-1);
}

static void ComputeBacktrackTable(PBYTE pPattern, int iPatternLen, int *piPatternBacktrack)
{
	int j = 0, t = -1;
	piPatternBacktrack[j] = -1;

	while(j < (iPatternLen - 1))
	{
		while((t >= 0) && (pPattern[j] != pPattern[t]))
			t = piPatternBacktrack[t];

		++j, ++t;
		piPatternBacktrack[j] = ((pPattern[j] == pPattern[t]) ? piPatternBacktrack[t] : t);
	};
}

static int SearchHashed2(PBYTE pSrc, int iSrcLen, PBYTE pPattern, int iPatternLen, int *piPatternBacktrack)
{
	if((iSrcLen <= 0) || (iPatternLen <= 0) || (iPatternLen > iSrcLen))
		return(-1);

	if(iPatternLen < SUFFIX_SIZE)
		return(SearchSmallpat(pSrc, iSrcLen, pPattern, iPatternLen));

	ComputeBacktrackTable(pPattern, iPatternLen, piPatternBacktrack);

	int	aSkip[HASH_RANGE_MAX];
	for(int i = 0; i < HASH_RANGE_MAX; i++)
		aSkip[i] = (iPatternLen - SUFFIX_SIZE + 1);

	for(int i = 0; i < iPatternLen - 1; i++)
		aSkip[Hash(pPattern + i)] = (iPatternLen - 1 - i);

	int	iLarge         = (iSrcLen + 1);
	int iMismatchShift = aSkip[Hash(pPattern + iPatternLen - 1)];
	aSkip[Hash(pPattern + iPatternLen - 1)] = iLarge;

	PBYTE pSrcEnd = (pSrc + iSrcLen);
	int	k = -iSrcLen;
	int	iAdjustment = (iLarge + iPatternLen - 1);

	while(TRUE)
	{
		k += (iPatternLen - 1);
		if(k >= 0)
			return(-1);

		do { k += aSkip[Hash(pSrcEnd + k)];	} while(k < 0);
		if(k < iPatternLen)
			return(-1);
		k -= iAdjustment;

		if(pSrcEnd[k] != pPattern[0])
		{
			k += iMismatchShift;
			continue;
		}

		int i = 1;
		while(TRUE)
		{
			if(pSrcEnd[++k] != pPattern[i])
				break;

			if(++i == iPatternLen)
				return((iSrcLen + k) - iPatternLen + 1);
		};

		if(iMismatchShift > i)
		{
			k += (iMismatchShift - i);
			continue;
		}

		while(TRUE)
		{
			i = piPatternBacktrack[i];
			if(i <= 0)
			{
				if(i < 0) k++;
				break;
			}

			while(pSrcEnd[k] == pPattern[i])
			{
				k++;
				if(++i == iPatternLen)
					return((iSrcLen + k) - iPatternLen);

				if(k == 0)
					return(-1);
			}
		};
	};
}


static PINT piPatternBacktrack = NULL;
static int  iPatternBacktrackSize = 0;

// Clean up pattern search data
void clearPatternSearchData()
{
	if(piPatternBacktrack) Heap().Free(piPatternBacktrack);
	piPatternBacktrack    = NULL;
	iPatternBacktrackSize = 0;
}

// Search for pattern
UINT patternSearch(PBYTE pSrc, int iSrcLen, PBYTE pPattern, int iPatternLen, int iAnd)
{
	// Init backtrack buffer the first time
	if(!piPatternBacktrack)
	{
		// Largest seen 7/9/2012 131072 bytes
		iPatternBacktrackSize = max((iPatternLen * sizeof(int)), 131072);
		piPatternBacktrack    = TAlloc<int>(iPatternBacktrackSize);
		if(!piPatternBacktrack)
		{
			msg("** Failed to allocate pattern backtrace bufferr! **\n");
			iPatternBacktrackSize = 0;
			return(-1);
		}
	}

	// Expand buffer as needed
	int iNeeded = (iPatternLen * sizeof(int));
	if(iNeeded > iPatternBacktrackSize)
	{
		//msg("Expanding backtrace buffer from %d to %d bytes\n", iPatternBacktrackSize, iNeeded);
		if(piPatternBacktrack = TRealloc<int>(piPatternBacktrack, iNeeded))
			iPatternBacktrackSize = iNeeded;
		else
		{
			msg("** Failed to expand pattern backtrace bufferr from %d to %d bytes! **\n", iPatternBacktrackSize, iNeeded);
			iPatternBacktrackSize = 0;
			return(-1);
		}
	}

	int	iGranularity = (iAnd >> 3);
	int	iSlicesize   = ((iGranularity) ? iGranularity : iPatternLen);
	int	iRemaining   = iSrcLen;
	int	iOfs         = -1;
	int	iMaxAndDistance = (iPatternLen * 16);
	PBYTE pPatLimit  = (pPattern + iPatternLen);
	PBYTE pPatStart  = NULL;

	for(PBYTE pStart = pSrc, p = pPattern; p < pPatLimit;)
	{
		iOfs = SearchHashed2(pStart, iRemaining, p, iSlicesize, piPatternBacktrack);
		if(iOfs != -1)
		{
			iRemaining -= (iOfs + iSlicesize);
			if(!pPatStart)
			{
				pPatStart = (pStart + iOfs);
				if(iRemaining > iMaxAndDistance)
					iRemaining = iMaxAndDistance;
			}

			pStart += (iOfs + iSlicesize);
			p      += iSlicesize;
		}
		else
		{
			if(!pPatStart)
				break;

			pStart = (pPatStart + iSlicesize);
			iRemaining = (iSrcLen - (pStart - pSrc));
			p = pPattern;
			pPatStart = NULL;
		}
	}

	return((iOfs != -1) ? (pPatStart - pSrc) : (UINT) -1);
}

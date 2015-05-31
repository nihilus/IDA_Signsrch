
// ****************************************************************************
// File: Utility.cpp
// Desc: Utility stuff
//
// ****************************************************************************
#include "stdafx.h"

#define I2TIME(_int) ((double) (_int) * (double) ((double) 1.0 / (double) 1000.0))

// Single heap instance
INSTANCE_EZHeap(Heap);

// ****************************************************************************
// Func: GetTimeSamp()
// Desc: Get elapsed factional seconds
//
// ****************************************************************************
TIMESTAMP getTimeStamp()
{
	LARGE_INTEGER tLarge;
	QueryPerformanceCounter(&tLarge);

	static ALIGN(16) TIMESTAMP s_ClockFreq;
	if(s_ClockFreq == 0.0)
	{
		LARGE_INTEGER tLarge;
		QueryPerformanceFrequency(&tLarge);
		s_ClockFreq = (TIMESTAMP) tLarge.QuadPart;
	}

	return((TIMESTAMP) tLarge.QuadPart / s_ClockFreq);
}


void trace(LPCSTR format, ...)
{
	if(format)
	{
		va_list vl;
		char str[4096];

		va_start(vl, format);
		_vsnprintf(str, (sizeof(str) - 1), format, vl);
		str[(sizeof(str) - 1)] = 0;
		va_end(vl);
		OutputDebugString(str);
	}
}


long fsize(FILE *fp)
{
	long psave, endpos;
	long result = -1;

	if((psave = ftell(fp)) != -1L)
	{
		if(fseek(fp, 0, SEEK_END) == 0)
		{
			if((endpos = ftell(fp)) != -1L)
			{
				fseek(fp, psave, SEEK_SET);
				result = endpos;
			}
		}
	}

	return(result);
}

char *replaceNameInPath(char *pszPath, char *pszNewName)
{
	char szDrive[_MAX_DRIVE];
	char szDir[_MAX_DIR];
	_splitpath(pszPath, szDrive, szDir, NULL, NULL);
	_makepath(pszPath, szDrive, szDir, pszNewName, NULL);
	return(pszPath);
}

// Get a pretty delta time string for output
LPCSTR timeString(TIMESTAMP time)
{
	static char szBuff[64];

	if(time >= HOUR)
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.01)
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f milliseconds", (time * (TIMESTAMP) 1000.0));
	else
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f seconds", time);

	return(szBuff);
}

// Returns a pretty factional byte size string for given input size
LPCSTR byteSizeString(UINT64 bytes)
{
    static const UINT64 KILLOBYTE = 1024;
    static const UINT64 MEGABYTE = (KILLOBYTE * 1024); // 1048576
    static const UINT64 GIGABYTE = (MEGABYTE * 1024); // 1073741824
    static const UINT64 TERABYTE = (GIGABYTE * 1024); // 1099511627776

    #define BYTESTR(_Size, _Suffix) \
        { \
	    double fSize = ((double) bytes / (double) _Size); \
	    double fIntegral; double fFractional = modf(fSize, &fIntegral); \
	    if(fFractional > 0.05) \
		    _snprintf(buffer, SIZESTR(buffer), ("%.1f " ## _Suffix), fSize); \
                                else \
		    _snprintf(buffer, SIZESTR(buffer), ("%.0f " ## _Suffix), fIntegral); \
        }

    static char buffer[32];
    ZeroMemory(buffer, sizeof(buffer));
    if (bytes >= TERABYTE)
        BYTESTR(TERABYTE, "TB")
    else
    if (bytes >= GIGABYTE)
        BYTESTR(GIGABYTE, "GB")
    else
    if (bytes >= MEGABYTE)
        BYTESTR(MEGABYTE, "MB")
    else
    if (bytes >= KILLOBYTE)
        BYTESTR(KILLOBYTE, "KB")
    else
    _snprintf(buffer, SIZESTR(buffer), "%u byte%c", bytes, (bytes == 1) ? 0 : 's');

    return(buffer);
}


// Return a comma formatted string for a given number
LPSTR prettyNumberString(UINT64 n, __bcount(32) LPSTR buffer)
{
    std::string s;
    int c = 0;
    do
    {
        s.insert(0, 1, char('0' + (n % 10)));
        n /= 10;
        if ((c += (3 && n)) >= 3)
        {
            s.insert(0, 1, ',');
            c = 0;
        }
    } while (n);
    strncpy(buffer, s.c_str(), 31);
    return(buffer);
}
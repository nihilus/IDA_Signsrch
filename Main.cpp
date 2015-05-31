
// ****************************************************************************
// File: Main.cpp
// Desc: Plugin main
// Auth: Sirmabus 2012
//
// ****************************************************************************
#include "stdafx.h"
#include <WaitBoxEx.h>

// Signature container
#pragma pack(push, 1)
typedef struct _SIG
{
	LPSTR title;
	PBYTE data;
	UINT  size;
	WORD  bits;
	WORD  flags;
} SIG, *LPSIG;
#pragma pack(pop)
typedef std::vector<SIG, EZHeapAlloc<SIG>> SIGLIST;

// Match container
typedef struct _MATCH
{
	ea_t address;
	UINT index;
	bool operator()(_MATCH const &a, _MATCH const &b){ return(a.address < b.address); }
} MATCH, *LPMATCH;
typedef std::vector<MATCH, EZHeapAlloc<MATCH>> MATCHLIST;

// wFlag defs
const WORD BIGENDIAN = (1 << 0); // 0 = little endian, 1 = big endian ** Don't change, this must be '1' **
const WORD REVERSE   = (1 << 1); // Reverse/reflect
const WORD AND       = (1 << 2); // And bits

#define SIGFILE "signsrch.xml"

// === Function Prototypes ===
static int idaapi pluginInit();
static void idaapi pluginTerm();
static void idaapi pluginRun(int arg);
static void freeSignatureData();
static void clearProcessSegmentBuffer();
extern void clearPatternSearchData();
static void clearMatchData();

// === Data ===
static const char PLUGIN_NAME[] = "Signsrch";

ALIGN(16) static SIGLIST   sigList;
ALIGN(16) static MATCHLIST matchList;

static HMODULE myModule = NULL;
static int  iconID = -1;
static UINT sigDataBytes = 0;
static UINT totalMatches = 0;
static BOOL listWindowUp = FALSE;

// UI options bit flags
// *** Must be same sequence as check box options
static SBITFLAG BitF;
const static WORD OPT_ALTENDIAN  = BitF.Next();
const static WORD OPT_DEBUGOUT   = BitF.Next();
const static WORD OPT_CODESEGS   = BitF.Next();
const static WORD OPT_COMMENTS   = BitF.Next();
static BOOL altEndianSearch     = FALSE;
static BOOL debugOutput	        = FALSE;
static BOOL includeCodeSegments = TRUE;
static BOOL placeComments       = TRUE;

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	pluginInit,
	pluginTerm,
	pluginRun,
    PLUGIN_NAME,
	" ",
	PLUGIN_NAME,
	NULL
};

ALIGN(16) static const char mainForm[] =
{
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'

	// Title
	"IDA Signsrch\n"

	// Message text
	"IDA Signsrch\n"
	"Version: %A, build: %A, by Sirmabus\n\n"

	// checkbox -> bAltEndianSearch
	"<#Do alternate endian search in addition to the IDB's native endian.\nSearching will take about twice as long but can find additional matches in some cases. #Alternate endian search.:C>\n"

	// checkbox -> bDebugOutput
	"<#Output matches to the debugging channel so they can be viewed \nand logged by Sysinternals \"DebugView\", etc.#Output to debug channel.:C>\n"

	// checkbox -> bIncludeCodeSegments
	"<#Search code segments in addition to data segments. #Include code segments.:C>\n"

	// checkbox -> bPlaceComments
	"<#Automatically place label comments for located signatures.#Place signature comments. :C>>\n"

	// * Maintain button names hard coded in "HelpURL.h"
	"<#Click to open plugin support page.#Macromonkey forum:k:2:16::>   "
	"<#Click to open Luigi Auriemma's Signsrch page.#Luigi Signsrch page:k:2:16::>\n \n "
};

// Custom chooser icon
static const BYTE iconData[] =
{
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00,
    0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61,
    0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0E,
    0xC4, 0x00, 0x00, 0x0E, 0xC4, 0x01, 0x95, 0x2B, 0x0E, 0x1B, 0x00,
    0x00, 0x00, 0x2F, 0x49, 0x44, 0x41, 0x54, 0x38, 0xCB, 0x63, 0x60,
    0x18, 0xF2, 0x80, 0x91, 0x61, 0x93, 0xE4, 0x7F, 0x74, 0xC1, 0xFF,
    0xBE, 0xCF, 0x30, 0x14, 0x3E, 0x63, 0x64, 0xC4, 0x10, 0x93, 0x66,
    0x60, 0x60, 0x64, 0xA1, 0xD4, 0x05, 0xA3, 0x06, 0x8C, 0x1A, 0x40,
    0x15, 0x03, 0x06, 0x1E, 0x00, 0x00, 0x73, 0xC1, 0x05, 0x2A, 0x17,
    0xC4, 0xDC, 0xF5, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82,
};


// ======================================================================================
static int idaapi pluginInit()
{
	// SIG struct should be align 16
	C_ASSERT((sizeof(SIG) & (16-1)) == 0);

	listWindowUp = FALSE;
	return(PLUGIN_OK);
}

// ======================================================================================
static void idaapi pluginTerm()
{
    if (iconID != -1)
    {
        free_custom_icon(iconID);
        iconID = -1;
    }

	// Just in case..
	clearMatchData();
	clearPatternSearchData();
	freeSignatureData();
}

// ======================================================================================

// Load signature XML file
static LPSTR xmlValueStr = NULL;
static int   xmlValueBufferSize = 0;
static void XMLCALL characterHandler(PVOID parm, LPCSTR dataStr, int len)
{
	try
	{
		if(xmlValueBufferSize)
		{
			// Increase buffer size as needed
			int adjLen = (len + 1);
			if(xmlValueBufferSize < adjLen)
			{
				if(xmlValueStr = TRealloc<char>(xmlValueStr, adjLen))
					xmlValueBufferSize = adjLen;
				else
				{
					msg("** Failed to realloc() XML data bufferr! Size wanted: %d **\n", adjLen);
					xmlValueBufferSize = 0;
				}
			}

			// Save contents
			if(xmlValueBufferSize)
			{
				memcpy(xmlValueStr, dataStr, len);
				xmlValueStr[len] = 0;
			}
		}
	}
	CATCH();
}
//
ALIGN(16) static char titleStr[1024] = {0};
static void XMLCALL startElement(PVOID parm, LPCTSTR nameStr, LPCTSTR *attribStr)
{
	try
	{
		if(xmlValueBufferSize)
		{
			if(*((PWORD) nameStr) == MAKEWORD('p',0))
			{
				if(LPCSTR tagPtr = attribStr[0])
				{
					if(*((PWORD) tagPtr) == MAKEWORD('t',0))
					{
						if(LPCSTR titlePtr = attribStr[1])
							strncpy(titleStr, titlePtr, SIZESTR(titleStr));
					}
				}
			}
		}

		xmlValueStr[0] = 0;
	}
	CATCH();
}
//
static void XMLCALL endElement(PVOID parm, LPCSTR name)
{
	try
	{
		if(xmlValueBufferSize)
		{
			if(*((PWORD) name) == MAKEWORD('p',0))
			{
				STACKALIGN(sig, SIG);
				sig.title = Heap().strdup(titleStr);
				sig.data    = NULL;

				if(sig.title)
				{
					//== Parse data out of the title
					// Find the last start brace
					LPSTR stringPtr = titleStr;
					LPSTR lastBrace = NULL;
					while(LPSTR pszBrace = strchr(stringPtr, '['))
					{
						lastBrace = pszBrace;
						stringPtr = (pszBrace + 1);
					};

					if(lastBrace)
					{
						// Largest section seen is 16 chars
						int len = strlen(++lastBrace);
						lastBrace[len - 1] = 0;

						// And flag?
						WORD andFlag = 0;
						if(lastBrace[len - 2] == '&')
						{
							//msg("And: \"%s\"\n", Sig.pszTitle);
							lastBrace[len - 2] = 0;
							andFlag = AND;
						}

						// First is the optional bits
						int steps = 0;
						BOOL endianBail = FALSE;
						LPSTR bitsStr = lastBrace;
						if(LPSTR endStr = strchr(lastBrace, '.'))
						{
							*endStr = 0; ++steps;

							// AND type must have bits
							sig.bits = 0;
							if(andFlag)
							{
								if(bitsStr[0])
								{
									if(strcmp(bitsStr, "float") == 0)
										sig.bits = 32;
									else
									if(strcmp(bitsStr, "double") == 0)
										sig.bits = 64;
									else
										sig.bits = atoi(bitsStr);
								}

								if(sig.bits == 0)
									msg("** AND type missing bits! \"%s\" **\n", sig.title);
							}

							// Next endian and reverse flag
							// Can be none for default of IDB endian
							LPSTR endianStr = ++endStr;
							if(endStr = strchr(endStr, '.'))
							{
								*endStr = 0; ++steps;

								sig.flags = 0;
								if(endianStr[0])
								{
									if(*((PWORD) endianStr) == MAKEWORD('b','e'))
										sig.flags = BIGENDIAN;

									// Bail out if altEndianSearch off and opposite our endian
                                    if (!altEndianSearch && ((BYTE) inf.mf != (BYTE)sig.flags))
									{
										//msg("B: \"%s\"\n", sig.title);
										endianBail = TRUE;
									}
									else
									if(*((PWORD) (endianStr + 2)) == MAKEWORD(' ','r'))
										sig.flags |= REVERSE;
								}

								if(!endianBail)
								{
									sig.flags |= andFlag;

									// Last, size
									LPSTR sizeStr = (endStr + 1);
									sig.size = atoi(sizeStr);
									// Valid size required
									if((sig.size > 0) && (sig.size == (strlen(xmlValueStr) / 2)))
									{
										++steps;

										// Signature string to bytes
										sig.data = (PBYTE) Heap().Alloc(sig.size);
										if(sig.data)
										{
											// Hex string to byte data
											UINT  size   = sig.size;
											PBYTE srcPtr = (PBYTE) xmlValueStr;
											PBYTE dstPtr = sig.data;

											do
											{
												BYTE hi = (srcPtr[0] - '0');
												if(hi > 9) hi -= (('A' - '0') - 10);

												BYTE lo = (srcPtr[1] - '0');
												if(lo > 9) lo -= (('A' - '0') - 10);

												*dstPtr = (lo | (hi << 4));
												srcPtr += 2, dstPtr += 1;
											}while(--size);

											// Save signature
											//if(uSize == 0)
											{
												++steps;
												sigDataBytes += strlen(sig.title);
												sigDataBytes += sig.size;
												sigList.push_back(sig);
											}
											//else
											//	Heap().Free(Sig.pData);
										}
									}
									else
										msg("** Signature data parse size mismatch! Title: \"%s\" **\n", sig.title);
								}
							}
						}

						if(steps != 4)
						{
							if(!endianBail)
								msg("** Failed to parse signature! Title: \"%s\" **\n", sig.title);

							if(sig.title)
								Heap().Free(sig.title);
						}
					}
					else
						msg("** Failed locate info section in title decode! \"%s\" **\n", sig.title);
				}
				else
				{
					msg("** Failed to allocate XML title string copy! **\n");
					xmlValueBufferSize = 0;
				}
			}
		}

		xmlValueStr[0] = titleStr[0] = 0;
	}
	CATCH();
}
//
static BOOL loadSignatures()
{
	BOOL result = FALSE;
	sigDataBytes = 0;

	try
	{
		// Get my module full path replaced with XML file name
		char pathStr[MAX_PATH]; pathStr[0] = pathStr[SIZESTR(pathStr)] = 0;
		GetModuleFileNameEx(GetCurrentProcess(), myModule, pathStr, SIZESTR(pathStr));
		replaceNameInPath(pathStr, SIGFILE);

		if(FILE *fp = fopen(pathStr, "rb"))
		{
			long lSize = fsize(fp);
			if(lSize > 0)
			{
				if(LPSTR textStr = TAlloc<char>(lSize+1))
				{
					// Data value buffer
					// Largest seen data size 0xFFFF
					xmlValueBufferSize = 69632;
					if(xmlValueStr = TAlloc<char>(xmlValueBufferSize))
					{
						textStr[0] = textStr[lSize] = 0;
						if(fread(textStr, lSize, 1, fp) == 1)
						{
							if(XML_Parser p = XML_ParserCreate(NULL))
							{
								//  7/09/2012 element count: One endian 1,411, both 2278
								sigList.reserve(2600);

								XML_SetUserData(p, p);
								XML_SetElementHandler(p, startElement, endElement);
								XML_SetCharacterDataHandler(p, characterHandler);

								if(XML_Parse(p, textStr, lSize, 1) != XML_STATUS_ERROR)
								{
									result = (xmlValueBufferSize > 0);
									sigDataBytes += (sigList.size() * sizeof(SIG));
								}
								else
									msg("** Signature XML parse error: \"%s\" at line #%u! **\n", XML_ErrorString(XML_GetErrorCode(p)), XML_GetCurrentLineNumber(p));

								XML_ParserFree(p);
							}
						}

						Heap().Free(xmlValueStr);
					}

					xmlValueBufferSize = 0;
					Heap().Free(textStr);
				}

			}

			fclose(fp);
		}
		else
			msg("** Signature file \"%s\" not found! **\n", SIGFILE);
	}
	CATCH();

	return(result);
}

// Free up signature container
static void freeSignatureData()
{
	if(!sigList.empty())
	{
		UINT count = sigList.size();
		LPSIG e = &sigList[0];
		do
		{
			if(e->title) Heap().Free(e->title);
			if(e->data)  Heap().Free(e->data);
			e++, --count;
		}while(count);

		sigList.clear();
	}
}

static void idaapi forumBtnHandler(TView *fields[], int code){ open_url("http://www.macromonkey.com/bb/index.php/topic,22.0.html"); }
static void idaapi luigiBtnHandler(TView *fields[], int code){ open_url("http://aluigi.org/mytoolz.htm#signsrch"); }

// Process a segment for signatures
extern UINT patternSearch(PBYTE, int, PBYTE, int, int);
static PBYTE pageBuffer     = NULL;
static UINT  pageBufferSize = 0;

static void clearProcessSegmentBuffer()
{
	if(pageBuffer) Heap().Free(pageBuffer);
	pageBuffer     = NULL;
	pageBufferSize = 0;
}

static void clearMatchData()
{
	matchList.clear();
}

static UINT processSegment(segment_t *segPtr)
{
	UINT matches = 0;

	if(UINT size = (UINT) segPtr->size())
	{
		if(!pageBuffer)
		{
			// Usually less then 10mb
			pageBufferSize = max(size, (10 * (1024 * 1024)));
			pageBuffer     = TAlloc<BYTE>(pageBufferSize);
			if(!pageBuffer)
			{
				msg("** Failed to allocate segment bufferr! **\n");
				pageBufferSize = 0;
				return(0);
			}
		}

		//== Copy IDB bytes to buffer
		// Expand buffer as needed
		if(size > pageBufferSize)
		{
			if(pageBuffer = TRealloc<BYTE>(pageBuffer, size))
				pageBufferSize = size;
			else
			{
				msg("** Failed to expand segment buffer! **\n");
				return(0);
			}
		}

		// Copy speed appears to be constant regardless of what accessor
		// 7-10-2012 About .3 seconds for every 7mb
		// Note: Padded bytes (that don't exist in the source?) will be all 0xFF
		{
			ea_t  currentEa = segPtr->startEA;
			ea_t  endEa     = segPtr->endEA;
			PBYTE buffer    = pageBuffer;
			UINT  count     = size;

			do
			{
				*buffer = get_db_byte(currentEa);
				++currentEa, ++buffer, --count;

			}while(count);

			//DumpData(pPageBuffer, 256);
			//DumpData(pPageBuffer + (uSize - 256), 256);
		}

		// Scan signatures
		{
			// 7-10-2012 about 2 seconds per 6.5mb
			UINT  count  = sigList.size();
			LPSIG e      = &sigList[0];
            char name[64]; name[0] = name[SIZESTR(name)] = 0;
			get_true_segm_name(segPtr, name, SIZESTR(name));

			for(UINT i = 0; i < count; i++, e++)
			{
				UINT offset = patternSearch(pageBuffer, size, e->data, e->size, e->bits);
				if(offset != -1)
				{
					// Get item address points too for code addresses
					// TOOD: Is there ever data cases too?
					ea_t address = get_item_head(segPtr->startEA + offset);
					//msg("Match %08X \"%s\"\n", eaAddress, e->pszTitle);

					// Optional output to debug channel
					if(debugOutput)
                        trace(EAFORMAT" \"%s\"\n", address, e->title);

					// Optional place comment
					if(placeComments)
					{
						const char prefix[] = {"<$ignsrch> "};
						char comment[MAXSTR]; comment[0] = comment[SIZESTR(comment)] = 0;

						// Already has one?
						int size = get_cmt(address, TRUE, comment, SIZESTR(comment));
						if(size > 0)
						{
							// Skip if already Signsrch comment
							if((size > sizeof(prefix)) && (strstr(comment, prefix) != NULL))
								size = -1;

							if(size != -1)
							{
								// Skip if not enough space
								if((size + strlen(e->title) + sizeof("\n")) >= SIZESTR(comment))
									size = -1;

								if(size != -1)
								{
									// If big add a line break, else just a space
									if(size >= 54)
									{
										strcpy(comment + size, "\n");
										size += SIZESTR("\n");
									}
									else
									{
										comment[size] = ' ';
										size += SIZESTR(" ");
									}
								}
							}
						}
						else
							size = 0;

						if(size >= 0)
						{
							sprintf(comment + size, "%s\"%s\" ", prefix, e->title);
							set_cmt(address, comment, TRUE);
						}
					}

					MATCH match = {address, i};
					matchList.push_back(match);
					matches++;
				}

                if (WaitBox::isUpdateTime())
                    if (WaitBox::updateAndCancelCheck())
                        return(-1);
			}
		}
	}

	return(matches);
}


// ============================================================================
// Matches list window stuff
static const LPCSTR columnHeader[] =
{
	"Address",
	"Size",
	"Label",
};
const int LBCOLUMNCOUNT = (sizeof(columnHeader) / sizeof(LPCSTR));
static int aListBColumnWidth[LBCOLUMNCOUNT] = {15, 4, 52}; // (9 | CHCOL_HEX)

UINT CALLBACK LB_onGetLineCount(PVOID parm)
{
	return(matchList.size());
}

void CALLBACK LB_onMakeLine(PVOID parm, UINT n, char * const *cellPtr)
{
	try
	{
		// Set column header labels
		if(n == 0)
		{
			for(UINT i = 0; i < LBCOLUMNCOUNT; i++)
				strcpy(cellPtr[i], columnHeader[i]);
		}
		else
		// Set line strings
		{
			ea_t address = matchList[n - 1].address;
			if(segment_t *seg = getseg(address))
			{
				char name[64]; name[SIZESTR(name)] = 0;
				get_true_segm_name(seg, name, SIZESTR(name));
                sprintf(cellPtr[0], "%s:"EAFORMAT, name, address);
			}
			else
                sprintf(cellPtr[0], "unknown:"EAFORMAT, address);
			//sprintf(ppCell[0], EAFORMAT, MatchList[n - 1].eaAddress);

			sprintf(cellPtr[1], "%04X", sigList[matchList[n - 1].index].size);
			strcpy(cellPtr[2], sigList[matchList[n - 1].index].title);
		}
	}
	CATCH()
}

// No icon
int CALLBACK LB_getIcon(PVOID parm, uint32 n)
{
    return(-1);
}


void CALLBACK LB_onSelect(PVOID parm, UINT n)
{
	try
	{
		jumpto(matchList[n - 1].address);
	}
	CATCH()
}

void CALLBACK LB_onClose(PVOID parm)
{
    if (iconID != -1)
    {
        free_custom_icon(iconID);
        iconID = -1;
    }

	// Clean up
	clearMatchData();
	clearPatternSearchData();
	freeSignatureData();
	listWindowUp = FALSE;
}


static void idaapi pluginRun(int arg)
{
	if(!listWindowUp)
	{
        char version[16];
        sprintf(version, "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
        msg("\n>> IDA Signsrch plugin: v: %s, BD: %s, By Sirmabus\n", version, __DATE__);
		GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) &pluginRun, &myModule);
        refreshUI();

		if(autoIsOk())
		{
			// Currently we only supports8bit byte processors
			if((ph.cnbits != 8) || (ph.dnbits != 8))
			{
				msg("** Sorry only 8bit byte processors are currently supported **\n");
				msg("  The processor for this IDB is %d bit code and %d bit data.\n  Please report this issue on the IDA Signsrch support forum.\n", ph.cnbits, ph.dnbits);
				msg("** Aborted **\n\n");
				return;
			}

			// Do main dialog
			altEndianSearch     = FALSE;
			debugOutput	        = FALSE;
			includeCodeSegments = TRUE;
			placeComments       = TRUE;
			WORD optionFlags = 0;
			if(altEndianSearch)     optionFlags |= OPT_ALTENDIAN;
			if(debugOutput)		    optionFlags |= OPT_DEBUGOUT;
			if(includeCodeSegments) optionFlags |= OPT_CODESEGS;
			if(placeComments)       optionFlags |= OPT_COMMENTS;

            int uiResult = AskUsingForm_c(mainForm, version, __DATE__, &optionFlags, forumBtnHandler, luigiBtnHandler);
			if(!uiResult)
			{
				// User canceled, or no options selected, bail out
				msg(" - Canceled -\n");
				return;
			}

			altEndianSearch     = ((optionFlags & OPT_ALTENDIAN) != 0);
			debugOutput		    = ((optionFlags & OPT_DEBUGOUT) != 0);
			includeCodeSegments = ((optionFlags & OPT_CODESEGS) != 0);
			placeComments       = ((optionFlags & OPT_COMMENTS) != 0);

            WaitBox::show("Signsrch");
            WaitBox::updateAndCancelCheck(-1);
			msg("IDB: %s endian.\n", ((inf.mf == 0) ? "Little" : "Big"));
            refreshUI();

			TIMESTAMP startTime = getTimeStamp();
			if(loadSignatures())
			{
                BOOL aborted = FALSE;
				char numBuffer[32];
				msg("%s signatures loaded, size: %s.\n\n", prettyNumberString(sigList.size(), numBuffer), byteSizeString(sigDataBytes));
                refreshUI();

				// Typical matches less then 200, and this is small
				matchList.reserve(256);

				if(!sigList.empty())
				{
					totalMatches = 0;

					// Walk segments
					int count = get_segm_qty();
					for(int i = 0; (i < count) && !aborted; i++)
					{
						if(segment_t *seg = getnseg(i))
						{
							char name[64] = {0};
							get_true_segm_name(seg, name, SIZESTR(name));
							char classStr[16] = {0};
							get_segm_class(seg, classStr, SIZESTR(classStr));

							switch(seg->type)
							{
								// Types to skip
								case SEG_XTRN:
								case SEG_GRP:
								case SEG_NULL:
								case SEG_UNDF:
								case SEG_ABSSYM:
								case SEG_COMM:
								case SEG_IMEM:
								case SEG_CODE:
								if(!((seg->type == SEG_CODE) && includeCodeSegments))
								{
                                    msg("Skipping segment: \"%s\", \"%s\", %d, "EAFORMAT" - "EAFORMAT", %s\n", name, classStr, seg->type, seg->startEA, seg->endEA, byteSizeString(seg->size()));
									break;
								}

								default:
								{
                                    msg("Processing segment: \"%s\", \"%s\", %d, "EAFORMAT" - "EAFORMAT", %s\n", name, classStr, seg->type, seg->startEA, seg->endEA, byteSizeString(seg->size()));
									UINT matches = processSegment(seg);
									if(matches> 0)
									{
										if(matches != -1)
										{
											totalMatches += matches;
											msg("%u matches here.\n", matches);
										}
										else
											aborted = TRUE;
									}
								}
								break;
							};
						}
					}
                    refreshUI();

					// Sort match list by address
					if(!aborted)
						std::sort(matchList.begin(), matchList.end(), MATCH());

					clearPatternSearchData();
					clearProcessSegmentBuffer();
				}
				else
					msg("** No loaded signitures!, Aborted **\n");

				if(!aborted)
				{
					msg("\nDone: Found %u matches in %s.\n\n", totalMatches, timeString(getTimeStamp() - startTime));
                    if (debugOutput)
                        trace("%u signature matches.\n", totalMatches);
                    refreshUI();

					if(!matchList.empty())
					{
                        if (iconID == -1)
                            iconID = load_custom_icon(iconData, sizeof(iconData), "png");

						// Create list view window
						listWindowUp = !choose2(0,	// Non-modal window
							-1, -1, -1, -1,			// Window position
							&matchList,				// Pass data
							LBCOLUMNCOUNT,			// Number of columns
							aListBColumnWidth,		// Widths of columns
							LB_onGetLineCount,		// Function that returns number of lines
							LB_onMakeLine,  		// Function that generates a line
							"[ Signsrch matches ]",	// Window title
                            iconID,					// Icon for the window
							0,						// Starting line
							NULL,					// "kill" callback
							NULL,					// "new" callback
							NULL,					// "update" callback
							NULL,					// "edit" callback
							LB_onSelect,			// Function to call when the user pressed Enter
							LB_onClose,				// Function to call when the window is closed
							NULL,					// Popup menu items
							LB_getIcon);  			// Line icon function
					}
					else
					{
						clearMatchData();
						freeSignatureData();
					}
				}
				else
				{
					msg("** Plugin aborted **\n\n");
					clearMatchData();
					freeSignatureData();
				}
			}
			else
				msg("** Failed to load signitures, Aborted **\n");
		}
		else
			msg("** Please wait for autoanalysis finish first!, Aborted **\n");

		refresh_idaview_anyway();
        WaitBox::hide();
	}
	else
		PlaySound((LPCSTR) SND_ALIAS_SYSTEMEXCLAMATION, NULL, (SND_ALIAS_ID | SND_ASYNC));
}


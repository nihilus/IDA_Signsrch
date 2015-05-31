/*
    Copyright 2007,2008,2009,2010 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "show_dump.h"
#include "hal_search.h"
#define MAINPROG
#include "disasm.h"

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

#ifdef WIN32
    #include <direct.h>
    #include <windows.h>
    #include <tlhelp32.h>
    #define PATHSLASH   '\\'
#else
    #include <sys/ptrace.h>

    #define stricmp strcasecmp
    #define stristr strcasestr
    #define PATHSLASH   '/'
#endif



#define VER                 "0.1.7"
#define STD_ERR             std_err()
#define mystrdup            _strdup
#define PATHSZ              2000
#define MAX_AND_DISTANCE    3000
#define SIGNFILE            "signsrch.sig"
#define SIGNFILEWEB         "http://aluigi.org/mytoolz/signsrch.sig.zip"



#pragma pack(1)
typedef struct {
    u8      *title;
    u8      *data;
    u32     size;
    WORD    Bits;
	WORD    Flags;
} sign_t;
#pragma pack()

typedef struct {
    u8      *name;
    //int     offset; // unused at the moment
    int     size;
} files_t;



sign_t  **sign;
u32     sign_alloclen,
        fixed_rva       = 0;
int     signs,
        exe_scan        = 0,
        filememsz       = 0,
        alt_endian      = 1,
        myendian        = 1;    // big endian
u8      *filemem        = NULL;



int check_is_dir(u8 *fname);
files_t *add_files(u8 *fname, int fsize, int *ret_files);
int recursive_dir(u8 *filedir, int filedirsz);
void find_functions(u32 store_offset, int sign_num);
void myswap16(u16 *ret);
void myswap32(u32 *ret);
void myswap64(u64 *ret);
void std_err(void);
u8 *get_main_path(u8 *fname, u8 *argv0);
void free_sign(void);
u8 *fd_read(u8 *name, int *fdlen);
void fd_write(u_char *name, u_char *data, int datasz);
u32 search_file(u8 *pattbuff, int pattsize, int and);
#include "parse_exe.h"
u8 *process_list(u8 *myname, DWORD *mypid, DWORD *size);
u8 *process_read(u8 *pname, int *fdlen);
void help(u8 *arg0);



#include "signcfg.h"
#include "signcrc.h"


#if 0
int main(int argc, char *argv[]) {
    static  u8  bckdir[PATHSZ + 1]  = "",
                filedir[PATHSZ + 1] = "";
    files_t *files      = NULL;
    u32     i,
            argi,
            found,
            offset,
            listsign        = 0,
            dumpsign        = 0,
            int3            = -1;
    int     input_total_files;
    u8      *pid            = NULL,
            *dumpfile       = NULL,
            *sign_file      = NULL,
            *p;
    char    **argx          = NULL;

    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "Signsrch "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "  optimized search function from Andrew http://www.team5150.com/~andrew/\n"
        "  disassembler engine from Oleh Yuschuk\n"
        "\n", stderr);

    if(argc < 2) {
        help(argv[0]);
    }

    for(i = 1; i < (u32) argc; i++) {
        if(!_stricmp(argv[i], "--help")) help(argv[0]);
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) break;
        switch(argv[i][1]) {
            case '-':
            case 'h':
            case '?': {
                help(argv[0]);
                } break;
            case 'l': {
                listsign  = 1;
                } break;
            case 'L': {
                if(!argv[++i]) {
                    printf("\nError: signature number needed\n");
                    exit(1);
                }
                dumpsign  = atoi(argv[i]);
                } break;
            case 's': {
                if(!argv[++i]) {
                    printf("\nError: signature filename needed\n");
                    exit(1);
                }
                sign_file = argv[i];
                } break;
            case 'p': {
                pid = "";
                } break;
            case 'P': {
                if(!argv[++i]) {
                    printf("\nError: process name or pid needed\n");
                    exit(1);
                }
                pid = argv[i];
                } break;
            case 'd': {
                if(!argv[++i]) {
                    printf("\nError: dump file name needed\n");
                    exit(1);
                }
                dumpfile = argv[i];
                } break;
            case 'e': {
                exe_scan        = 1;
                } break;
            case 'F': {
                exe_scan        = 2;
                } break;
            case 'E': {
                exe_scan        = -1;
                } break;
            case 'b': {
                alt_endian      = 0;
                } break;
#ifdef WIN32
            case '3': {
                sscanf(argv[++i], "%x", &int3);
                } break;
#endif
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                exit(1);
                } break;
        }
    }
    argi = i;

    sign          = NULL;
    signs         = 0;
    sign_alloclen = 0;
    if(*(char *)&myendian) myendian = 0;    // little endian

    if(pid && !pid[0]) {
        process_list(NULL, NULL, NULL);
        goto quit;
    }

#ifdef WIN32
    if(int3 != -1) {
        STARTUPINFO         si;
        PROCESS_INFORMATION pi;
        int     cmdlen;
        char    *cmd,
                *error;

        cmdlen = 0;
        for(i = argi; i < (u32) argc; i++) {
            cmdlen += strlen(argv[i]) + 1;
        }
        cmd = malloc(cmdlen + 1);
        if(!cmd) std_err();
        cmdlen = 0;
        for(i = argi; i < (u32) argc; i++) {
            cmdlen += sprintf(cmd + cmdlen, "\"%s\" ", argv[i]);
        }

        GetStartupInfo(&si);
        if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, (char *)&error, 0, NULL);
            printf("\n"
                "Error: problems during the launching of\n"
                "       %s\n"
                "       Windows reported this error: %s\n"
                "\n", cmd, error);
            LocalFree(error);
            exit(1);
        }
        for(i = 0; i < 2; i++) {
            if(i) Sleep(2000);  // in case of packed executables
            SuspendThread(pi.hThread);
            WriteProcessMemory(pi.hProcess, (LPVOID)int3, "\xcc", 1, NULL);
            ResumeThread(pi.hThread);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("- process launched with INT3 applied at address %08x\n", int3);
        return(0);
    }
#endif

    argx = calloc(argc + 1, sizeof(char *));
    if(!argx) std_err();
    for(i = 0; i < (u32) argc; i++) {
        argx[i] = _strdup(argv[i]);
    }
    argx[i] = NULL;
    argv = argx;

redo:
    if(!listsign && !dumpsign) {
        if(pid) {
            filemem = process_read(pid, &filememsz);
            if(!exe_scan) exe_scan = 1;
        } else {
            if(argi == argc) {
                printf("\nError: you must specify the file to scan\n");
                exit(1);
            }
            if(check_is_dir(argv[argi])) {
                fprintf(stderr, "- start the scanning of the input folder: %s\n", argv[argi]);
                _getcwd(bckdir, PATHSZ);
                if(_chdir(argv[argi]) < 0) STD_ERR;
                strcpy(filedir, ".");
                recursive_dir(filedir, PATHSZ);

                files = add_files(NULL, 0, &input_total_files);
                if(input_total_files <= 0) {
                    fprintf(stderr, "\nError: the input folder is empty\n");
                    exit(1);
                }
                _chdir(bckdir);

                argv = realloc(argv, (argc + input_total_files + 1) * sizeof(char *));
                if(!argv) std_err();
                p = argv[argi]; // will be freed later!
                for(i = argc - 1; i >= argi; i--) {
                    argv[i + input_total_files] = argv[i + 1];
                }
                argv[argc + input_total_files] = NULL;
                for(i = 0; i < (u32) input_total_files; i++) {
                    argv[argi + i] = malloc(strlen(p) + 1 + strlen(files[i].name) + 1);
                    sprintf(argv[argi + i], "%s%c%s", p, PATHSLASH, files[i].name);
                }
                argc--; // remove argv[argi]
                argc += input_total_files;
                input_total_files = 0;
                free(p);
            }
            filemem = fd_read(argv[argi], &filememsz);
        }
        printf("- %u bytes allocated\n", filememsz);
    }

    if(dumpfile) {
        fd_write(dumpfile, filemem, filememsz);
        goto quit;
    }

    if(!sign) {
        printf("- load signatures\n");
        if(!sign_file) {
            read_cfg(get_main_path(SIGNFILE, argv[0]));
        } else {
            read_cfg(sign_file);
        }
        printf(
            "- %u bytes allocated for the signatures\n"
            "- %u signatures in the database\n",
            sign_alloclen,
            signs);
        if(!dumpsign) signcrc();
    }

    if(dumpsign > 0) {
        dumpsign--;
        if(dumpsign >= (u32) signs) {
            printf("\nError: wrong signature number\n");
            exit(1);
        }
        printf("  %s\n", sign[dumpsign]->title);
        show_dump(sign[dumpsign]->data, sign[dumpsign]->size, stdout);
        goto quit;
    }

    if(listsign) {
        printf("\n"
            "  num  description [bits.endian.size]\n"
            "-------------------------------------\n");
        for(i = 0; i < (u32) signs; i++) {
            printf("  %-4u %s\n", i + 1, sign[i]->title);
        }
        printf("\n");
        goto quit;
    }

    if(filememsz > (10 * 1024 * 1024)) {   // more than 10 megabytes
        printf(
            "- WARNING:\n"
            "  the file loaded in memory is very big so the scanning could take many time\n");
    }

    if(exe_scan > 0) {
        if(parse_exe() < 0) {
            printf(
                "- input is not an executable or is not supported by this tool\n"
                "  the data will be handled in raw mode\n");
            exe_scan = 0;
        }
    }

    printf(
        "- start signatures scanning:\n"
        "\n"
        "  offset   num  description [bits.endian.size]\n"
        "  --------------------------------------------\n");

    for(found = i = 0; i < (u32) signs; i++) {
        offset = search_hashed(filemem, filememsz, sign[i]->data, sign[i]->size, sign[i]->and);
        if(offset != -1) {
            if(exe_scan > 0) offset = file2rva(offset);
            if(exe_scan < 0) offset += fixed_rva;
            if(exe_scan == 2) {
                find_functions(offset, i);
                fputc('.', stderr);
            } else {
                printf("  %08x %-4u %s\n", offset, i + 1, sign[i]->title);
            }
            found++;
        }
    }
    if(exe_scan == 2) {
        fputc('\n', stderr);
        find_functions(-1, -1);
    }

    printf("\n- %u signatures found in the file\n", found);

    if(filemem) free(filemem);
    if(section) free(section);
    filemem = NULL;
    section = NULL;
    if(++argi < (u32) argc) {
        fputc('\n', stdout);
        goto redo;
    }

quit:
    if(sign) free_sign();
    return(0);
}
#endif

// =================================== ME ======================================
#include "time.h"
#define SZ(x) (sizeof(x) - 1)

// Filter reserved XML characters
LPSTR FilterXMLReservedChars(LPSTR pszInput)
{
	// Get count of reserved chars if any
	const char aReserved[5] = {"\"'<>&"};
	int l = strlen(pszInput), c = 0, i = 0;
	for(; i < l; i++){ if(memchr(aReserved, pszInput[i], 5)) c++; }
	
	if(c > 0)
	{		
		// Replace chars with XML sequence equivalences
		const char *aReplace[5] = {"&quot;", "&apos;", "&lt;", "&gt;", "&amp;"};
		const int  aRepSize[5]  = {SZ("&quot;"), SZ("&apos;"), SZ("&lt;"), SZ("&gt;"), SZ("&amp;")};
		LPSTR pS = pszInput, pD, pM;		
		int m = (l + (c * 6) + 1);
		pszInput = malloc(m);
		pD = pszInput;
		ZeroMemory(pszInput, m);

		do 
		{
			int j;
			pM = NULL;							
			for(j = 0; j < l; j++)
			{
				if(pM = memchr(aReserved, pS[j], 5))
				{	
					int n;
					memcpy(pD, pS, j); 
					pD += j, pS += (j + 1), l -= (j + 1);
					n = (pM - aReserved);
					m = aRepSize[n];
					memcpy(pD, aReplace[n], m);
					pD += m;									
					break;
				}
			}

		} while(pM);

		if(*pS) strcpy(pD, pS);
	}

	return(pszInput);
}

// ME: Quick and dirty "signsrch.sig" to "signsrch.xml"
int main()
{
	sign          = NULL;
	signs         = 0;
	sign_alloclen = 0;
	if(*(char *)&myendian) myendian = 0;    // DEfault little endian

	// Alternate endian (PC is little)
	// http://en.wikipedia.org/wiki/Endianness
	alt_endian = 1;
	
	read_cfg(SIGNFILE);

	// ME: Write "signs" back out as XML
	// "signsrch.xml"
	printf("Saving %d patterns to XML file\n", signs);
	if(signs > 0)
	{
		FILE *fp;
		fp = fopen("signsrch.xml", "wb");
		if(fp)
		{	
			#define P(_str) fputs(_str, fp);			

			time_t aclock;
			char szTimeString[48] = {0};
			time(&aclock);			
			strcpy(szTimeString, asctime(localtime(&aclock)));
			strtok(szTimeString,"\n");

			P("<?xml version=\"1.0\"?>\n");
			fprintf(fp, "<!-- Generated by Signsrch2XML by Sirmaus %s -->\n", szTimeString);			
			P("<pattern>\n");

			{
				int i = 0;				
				for(; i < signs; i++)
				{
					// Title and size									
					LPSTR pszTitle = FilterXMLReservedChars(sign[i]->title);
					PBYTE pData = sign[i]->data;
					int   iSize = sign[i]->size;
					int   Flags = (sign[i]->Bits | (sign[i]->Flags << 8));
					// Size, etc., already embeded in the title
					//fprintf(fp,"\t<p t=\"%s\" s=\"%X\" f=\"%X\">", pszTitle, iSize, Flags);
					fprintf(fp,"\t<p t=\"%s\">", pszTitle);
					if(pszTitle != sign[i]->title) free(pszTitle);					

					// Patern bytes
					while(iSize--){ fprintf(fp,"%02X", *pData++); };
					
					P("</p>\n");
				}
			}

			P("</pattern>\n");
			fclose(fp);
		}
	}

	if(sign)
		free_sign();
}


int check_is_dir(u8 *fname) {
	/*
    struct stat xstat;

    if(!fname) return(1);
    if(stat(fname, &xstat) < 0) return(0);
    if(!S_ISDIR(xstat.st_mode)) return(0);
    return(1);
	*/
	return(0);
}



files_t *add_files(u8 *fname, int fsize, int *ret_files) {
    static int      filesi  = 0,
                    filesn  = 0;
    static files_t  *files  = NULL;
    files_t         *ret;

    if(ret_files) {
        *ret_files = filesi;
        files = realloc(files, sizeof(files_t) * (filesi + 1)); // not needed, but it's ok
        if(!files) STD_ERR;
        files[filesi].name   = NULL;
        //files[filesi].offset = 0;
        files[filesi].size   = 0;
        ret    = files;
        filesi = 0;
        filesn = 0;
        files  = NULL;
        return(ret);
    }

    if(!fname) return(NULL);
    //if(filter_in_files && (check_wildcard(fname, filter_in_files) < 0)) return(NULL);

    if(filesi >= filesn) {
        filesn += 1024;
        files = realloc(files, sizeof(files_t) * filesn);
        if(!files) STD_ERR;
    }
    files[filesi].name   = mystrdup(fname);
    //files[filesi].offset = 0;
    files[filesi].size   = fsize;
    filesi++;
    return(NULL);
}



#define recursive_dir_skip_path 0
//#define recursive_dir_skip_path 2
int recursive_dir(u8 *filedir, int filedirsz) {
    int     plen,
            namelen,
            ret     = -1;
    
#ifdef WIN32
    static int      winnt = -1;
    OSVERSIONINFO   osver;
    WIN32_FIND_DATA wfd;
    HANDLE          hFind = INVALID_HANDLE_VALUE;

	if(!filedir) return(ret);

    if(winnt < 0) {
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        if(osver.dwPlatformId >= VER_PLATFORM_WIN32_NT) {
            winnt = 1;
        } else {
            winnt = 0;
        }
    }

    plen = strlen(filedir);
    if((plen + 4) >= filedirsz) goto quit;
    strcpy(filedir + plen, "\\*.*");
    plen++;

    if(winnt) { // required to avoid problems with Vista and Windows7!
        hFind = FindFirstFileEx(filedir, FindExInfoStandard, &wfd, FindExSearchNameMatch, NULL, 0);
    } else {
        hFind = FindFirstFile(filedir, &wfd);
    }
    if(hFind == INVALID_HANDLE_VALUE) goto quit;
    do {
        if(!strcmp(wfd.cFileName, ".") || !strcmp(wfd.cFileName, "..")) continue;

        namelen = strlen(wfd.cFileName);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, wfd.cFileName);
        memcpy(filedir + plen, wfd.cFileName, namelen);
        filedir[plen + namelen] = 0;

        if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + recursive_dir_skip_path, wfd.nFileSizeLow, NULL);
        }
    } while(FindNextFile(hFind, &wfd));
    ret = 0;

quit:
    if(hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
#else
    struct  stat    xstat;
    struct  dirent  **namelist;
    int     n,
            i;

    n = scandir(filedir, &namelist, NULL, NULL);
    if(n < 0) {
        if(stat(filedir, &xstat) < 0) {
            fprintf(stderr, "**** %s", filedir);
            STD_ERR;
        }
        add_files(filedir + recursive_dir_skip_path, xstat.st_size, NULL);
        return(0);
    }

    plen = strlen(filedir);
    if((plen + 1) >= filedirsz) goto quit;
    strcpy(filedir + plen, "/");
    plen++;

    for(i = 0; i < n; i++) {
        if(!strcmp(namelist[i]->d_name, ".") || !strcmp(namelist[i]->d_name, "..")) continue;

        namelen = strlen(namelist[i]->d_name);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, namelist[i]->d_name);
        memcpy(filedir + plen, namelist[i]->d_name, namelen);
        filedir[plen + namelen] = 0;

        if(stat(filedir, &xstat) < 0) {
            fprintf(stderr, "**** %s", filedir);
            STD_ERR;
        }
        if(S_ISDIR(xstat.st_mode)) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + recursive_dir_skip_path, xstat.st_size, NULL);
        }
        free(namelist[i]);
    }
    ret = 0;

quit:
    for(; i < n; i++) free(namelist[i]);
    free(namelist);
#endif
    filedir[plen - 1] = 0;
    return(ret);
}



void find_functions(u32 store_offset, int sign_num) {
typedef struct {
    u32     offset;
    int     sign_num;
    int     done;
} offsets_array_t;

    static  int offsets = 0;
    static  offsets_array_t *offsets_array  = NULL;
    t_disasm da;
    u32     func;
    int     i,
            asm_size,
            section_exe,
            offset;
    u8      *addr,
            *limit;

    lowercase   = 1;
    extraspace  = 1;
    showmemsize = 1;

    if(sign_num >= 0) {
        offsets_array = realloc(offsets_array, (offsets + 1) * sizeof(offsets_array_t));
        if(!offsets_array) std_err();
        offsets_array[offsets].offset   = store_offset;
        offsets_array[offsets].sign_num = sign_num;
        offsets_array[offsets].done     = 0;
        offsets++;
        return;
    }

    for(section_exe = 0; section_exe < sections; section_exe++) {
        if(!(section[section_exe].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))) continue;

        i = section[section_exe].PointerToRawData + section[section_exe].SizeOfRawData;
        if(i > filememsz) continue;
        limit = filemem + i;
        addr  = filemem + section[section_exe].PointerToRawData;

    // from dump2func
    for(        ; addr < limit; addr += asm_size) {
        asm_size = Disasm(addr, limit - addr, 0, &da, DISASM_CODE); // DISASM_DATA);
        if(asm_size <= 0) break;

        func = file2rva(addr - filemem);
        for(i = 0; i < offsets; i++) {
            if(offsets_array[i].done) continue;
            if((func <= offsets_array[i].offset) && ((func + asm_size) >= offsets_array[i].offset)) break;
        }
        if(i < offsets) goto set_offset;

        if(!(
            ((da.cmdtype & C_TYPEMASK) == C_CMD) ||
            ((da.cmdtype & C_TYPEMASK) == C_PSH) ||
            ((da.cmdtype & C_TYPEMASK) == C_DAT) ||
            ((da.cmdtype & C_TYPEMASK) == C_JMP))) {
            continue;
        }

        for(i = 0; i < 2; i++) {
            switch(i) {
                case 0: offset = da.adrconst;   break;  // mov eax, dword ptr [4*ecx+OFFSET]
                case 1: offset = da.immconst;   break;  // mov eax, OFFSET
                default: break;
            }
            if(offset <= 0) continue;
            if(offset <= (int) imagebase) continue;
            break;
        }
        if(i >= 2) continue;

        for(i = 0; i < offsets; i++) {
            if(offsets_array[i].done) continue;
            if(offset == offsets_array[i].offset) break;
        }
        if(i >= offsets) continue;

set_offset:
        offsets_array[i].offset = func;
        offsets_array[i].done   = 1;
        fputc('.', stderr);
    }
    }
    fputc('\n', stderr);

    for(i = 0; i < offsets; i++) {
        printf("  %08x %-4u %s\n", offsets_array[i].offset, offsets_array[i].sign_num + 1, sign[offsets_array[i].sign_num]->title);
    }

    // free the offsets for reusing them later!
    offsets = 0;
    // no need of freeing offsets_array
}



void myswap16(u16 *ret) {
    u16     n = *ret;
    n = (((n & 0xff00) >> 8) |
         ((n & 0x00ff) << 8));
    *ret = n;
}



void myswap32(u32 *ret) {
    u32     n = *ret;
    n = (((n & 0xff000000) >> 24) |
         ((n & 0x00ff0000) >>  8) |
         ((n & 0x0000ff00) <<  8) |
         ((n & 0x000000ff) << 24));
    *ret = n;
}



void myswap64(u64 *ret) {
    u64     n = *ret;
    n = (u64)(((u64)(n) & 0xffLL) << (u64)56) |
        (u64)(((u64)(n) & 0xff00LL) << (u64)40) |
        (u64)(((u64)(n) & 0xff0000LL) << (u64)24) |
        (u64)(((u64)(n) & 0xff000000LL) << (u64)8) |
        (u64)(((u64)(n) & 0xff00000000LL) >> (u64)8) |
        (u64)(((u64)(n) & 0xff0000000000LL) >> (u64)24) |
        (u64)(((u64)(n) & 0xff000000000000LL) >> (u64)40) |
        (u64)(((u64)(n) & 0xff00000000000000LL) >> (u64)56);
    *ret = n;
}



u8 *get_main_path(u8 *fname, u8 *argv0) {
    static u8   fullname[2000];
    u8      *p;

#ifdef WIN32
    GetModuleFileName(NULL, fullname, sizeof(fullname));
#else
    sprintf(fullname, "%.*s", sizeof(fullname), argv0);
#endif

    p = strrchr(fullname, '\\');
    if(!p) p = strrchr(fullname, '/');
    if(!p) p = fullname - 1;
    sprintf(p + 1, "%.*s", sizeof(fullname) - (p - fullname), fname);
    return(fullname);
}



void free_sign(void) {
    int     i;

    for(i = 0; i < signs; i++) {
        free(sign[i]->title);
        free(sign[i]->data);
        free(sign[i]);
    }
    free(sign);
}



u8 *fd_read(u8 *name, int *fdlen) {
    struct  stat    xstat;
    FILE    *fd;
    int     len,
            memsize,
            filesize;
    u8      *buff;

    if(!strcmp(name, "-")) {
        printf("- open %s\n", "stdin");
        filesize = 0;
        memsize  = 0;
        buff     = NULL;
        for(;;) {
            if(filesize >= memsize) {
                memsize += 0x80000;
                buff = realloc(buff, memsize);
                if(!buff) std_err();
            }
            len = fread(buff + filesize, 1, memsize - filesize, stdin);
            if(!len) break;
            filesize += len;
        }
        buff = realloc(buff, filesize);
        if(!buff) std_err();

    } else {
        printf("- open file \"%s\"\n", name);
        fd = fopen(name, "rb");
        if(!fd) std_err();
        fstat(_fileno(fd), &xstat);
        filesize = xstat.st_size;
        buff = malloc(filesize);
        if(!buff) std_err();
        fread(buff, filesize, 1, fd);
        fclose(fd);
    }

    *fdlen = filesize;
    return(buff);
}



void fd_write(u_char *name, u_char *data, int datasz) {
    FILE    *fd;

    printf("- create file %s\n", name);
    fd = fopen(name, "rb");
    if(fd) {
        fclose(fd);
        printf("- file already exists, do you want to overwrite it (y/N)?\n  ");
        fflush(stdin);
        if(tolower(fgetc(stdin)) != 'y') exit(1);
    }
    fd = fopen(name, "wb");
    if(!fd) std_err();
    fwrite(data, datasz, 1, fd);
    fclose(fd);
}



u32 search_file(u8 *pattbuff, int pattsize, int and) {
    u32     offset     = 0,
            min_offset = -1;
    u8      *pattlimit,
            *limit,
            *patt,
            *p;

    if(filememsz < pattsize) return(-1);

    and >>= 3;
    limit     = filemem + filememsz - pattsize;
    pattlimit = pattbuff + pattsize - and;

    if(and) {
        p = filemem;
        for(patt = pattbuff; patt <= pattlimit; patt += and) {
            for(p = filemem; p <= limit; p++) {
                if(!memcmp(p, patt, and)) {
                    offset = p - filemem;
                    if(offset < min_offset) min_offset = offset;
                    if((offset - min_offset) > MAX_AND_DISTANCE) return(-1);
                    break;
                }
            }
            if(p > limit) return(-1);
        }
        return(min_offset);
    } else {
        for(p = filemem; p <= limit; p++) {
            if(!memcmp(p, pattbuff, pattsize)) {
                return(p - filemem);
            }
        }
    }
    return(-1);
}



    // thanx to the extalia.com forum

u8 *process_list(u8 *myname, DWORD *mypid, DWORD *size) {
#ifdef WIN32
    PROCESSENTRY32  Process;
    MODULEENTRY32   Module;
    HANDLE          snapProcess,
                    snapModule;
    DWORD           retpid = 0;
    int             len;
    BOOL            b;
    u8              tmpbuff[60],
                    *process_name,
                    *module_name,
                    *module_print,
                    *tmp;

    if(mypid) retpid = *mypid;
    if(!myname && !retpid) {
        printf(
            "  pid/addr/size       process/module name\n"
            "  ---------------------------------------\n");
    }

#define START(X,Y) \
            snap##X = CreateToolhelp32Snapshot(Y, Process.th32ProcessID); \
            X.dwSize = sizeof(X); \
            for(b = X##32First(snap##X, &X); b; b = X##32Next(snap##X, &X)) { \
                X.dwSize = sizeof(X);
#define END(X) \
            } \
            CloseHandle(snap##X);

    Process.th32ProcessID = 0;
    START(Process, TH32CS_SNAPPROCESS)
        process_name = Process.szExeFile;

        if(!myname && !retpid) {
            printf("  %-10lu ******** %s\n",
                Process.th32ProcessID,
                process_name);
        }
		/*
        if(myname && stristr(process_name, myname)) {
            retpid = Process.th32ProcessID;
        }
		*/

        START(Module, TH32CS_SNAPMODULE)
            module_name = Module.szExePath; // szModule?

            len = strlen(module_name);
            if(len >= 60) {
                tmp = strrchr(module_name, '\\');
                if(!tmp) tmp = strrchr(module_name, '/');
                if(!tmp) tmp = module_name;
                len -= (tmp - module_name);
                sprintf(tmpbuff,
                    "%.*s...%s",
                    54 - len,
                    module_name,
                    tmp);
                module_print = tmpbuff;
            } else {
                module_print = module_name;
            }

            if(!myname && !retpid) {
                printf("    %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
            }
			/*
            if(!retpid) {
                if(myname && stristr(module_name, myname)) {
                    retpid = Process.th32ProcessID;
                }
            }
			*/
            if(retpid && mypid && (Process.th32ProcessID == retpid)) {
                printf("- %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
                *mypid = retpid;
                if(size) *size = Module.modBaseSize;
                return(Module.modBaseAddr);
            }

        END(Module)

    END(Process)

#undef START
#undef END

#else

    //system("ps -eo pid,cmd");
    printf("\n"
        "- use ps to know the pids of your processes, like:\n"
        "  ps -eo pid,cmd\n");

#endif

    return(NULL);
}



#ifdef WIN32
void winerr(void) {
    u8      *message = NULL;

    FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      0,
      (char *)&message,
      0,
      NULL);

    if(message) {
        printf("\nError: %s\n", message);
        LocalFree(message);
    } else {
        printf("\nError: unknown Windows error\n");
    }
    exit(1);
}
#endif



u8 *process_read(u8 *pname, int *fdlen) {

#ifdef WIN32

    HANDLE  process;
    DWORD   pid,
            size;
    int     len;
    u8      *baddr,
            *buff;

    if(!pname && !pname[0]) return(NULL);

    if(pname) {
        len = 0;
        sscanf(pname, "%lu%n", &pid, &len);
        if(len != strlen(pname)) pid = 0;
    }

    baddr = process_list(pid ? NULL : pname, &pid, &size);
    if(!baddr) {
        printf("\nError: process name/PID not found, use -p\n");
        exit(1);
    }

    fixed_rva = (u32)baddr;
    printf(
        "- pid %u\n"
        "- base address 0x%08x\n",
        (u32)pid, fixed_rva);

    process = OpenProcess(
        PROCESS_VM_READ,
        FALSE,
        pid);
    if(!process) winerr();

    buff = malloc(size);
    if(!buff) std_err();

    if(!ReadProcessMemory(
        process,
        (LPCVOID)baddr,
        buff,
        size,
        &size)
    ) winerr();

    CloseHandle(process);

#else

    pid_t   pid;
    u32     rva,
            size,
            memsize,
            data;
    u8      *buff;

    pid = atoi(pname);
    rva = 0x8048000;    // sorry, not completely supported at the moment

    fixed_rva = rva;
    printf(
        "- pid %u\n"
        "- try using base address 0x%08x\n",
        pid, fixed_rva);

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) std_err();

    size     = 0;
    memsize  = 0;
    buff     = NULL;

    for(errno = 0; ; size += 4) {
        if(!(size & 0xfffff)) fputc('.', stdout);

        data = ptrace(PTRACE_PEEKDATA, pid, (void *)rva + size, NULL);
        if(errno) {
            if(errno != EIO) std_err();
            break;
        }

        if(size >= memsize) {
            memsize += 0x7ffff;
            buff = realloc(buff, memsize);
            if(!buff) std_err();
        }
        memcpy(buff + size, &data, 4);
    }
    fputc('\n', stdout);
    buff = realloc(buff, size);
    if(!buff) std_err();

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) std_err();

#endif

    *fdlen = size;
    return(buff);
}



void help(u8 *arg0) {
    printf("\n"
        "Usage: %s [options] [file1] ... [fileN]\n"
        "\n"
        "Options:\n"
        "-l       list the available signatures in the database\n"
        "-L NUM   show the data of the signature NUM\n"
        "-s FILE  use the signature file FILE ("SIGNFILE")\n"
        "-p       list the running processes and their modules\n"
        "-P PID   use the process/module identified by its pid or part of name/path\n"
        "-d FILE  dump the process memory (like -P) in FILE\n"
        "-e       consider the input file as an executable (PE/ELF), can be useful\n"
        "         because will show the rva addresses instead of the file offsets\n"
        "-F       as above but returns the address of the first instruction that points\n"
        "         to the found signature, for example where is used the AES Td0 table,\n"
        "         something like an automatic \"Find references\" of Ollydbg\n"
        "-E       disable the automatic executable parsing used with -P\n"
        "-b       disable the scanning of the big endian versions of the signatures\n"
#ifdef WIN32
        "-3 OFF   execute the file applying an INT3 (0xcc) byte at the specified\n"
        "         offset (rva memory address, not file offset!) in hexadecimal notation\n"
        "         and remember to have a debugger set as \"Just-in-time\" debugger\n"
#endif
        "\n"
        "use - for stdin\n"
        "URL for the updated "SIGNFILE": "SIGNFILEWEB"\n"
        "\n", arg0);
    exit(1);
}



void std_err(void) {
    perror("\nError");
    exit(1);
}


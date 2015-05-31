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

    http://www.gnu.org/licenses/gpl.txt
*/
#pragma once

#ifdef WIN32
    #include <windows.h>
#else
    #include "pe_nonwin.h"
#endif

#define SECNAMESZ   32
#define MYPAD(X)    ((X + (sec_align - 1)) & (~(sec_align - 1)))
#define MYALIGNMENT 0x1000  // default in case not available


typedef struct {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} MYIMAGE_NT_HEADERS32;

typedef struct {    // from http://hte.sf.net
    u32     vsize;
    u32     base_reloc_addr;
    u32     flags;
    u32     page_map_index;
    u32     page_map_count;
    u8      name[4];
} vxd_section_t;

typedef struct {
    u8      e_ident[16];
    u16     e_type;
    u16     e_machine;
    u32     e_version;
    u32     e_entry;
    u32     e_phoff;
    u32     e_shoff;
    u32     e_flags;
    u16     e_ehsize;
    u16     e_phentsize;
    u16     e_phnum;
    u16     e_shentsize;
    u16     e_shnum;
    u16     e_shstrndx;
} elf32_header_t;

typedef struct {
    u32     sh_name;
    u32     sh_type;
    u32     sh_flags;
    u32     sh_addr;     
    u32     sh_offset;
    u32     sh_size;
    u32     sh_link;
    u32     sh_info;
    u32     sh_addralign;
    u32     sh_entsize;
} elf32_section_t;

typedef struct {
    u8      Name[SECNAMESZ + 1];
    u32     VirtualAddress;
    u32     VirtualSize;
    int     VirtualSize_off;
    u32     PointerToRawData;
    u32     SizeOfRawData;
    u32     Characteristics;
} section_t;



section_t   *section            = NULL;
u32     imagebase               = 0;
int     sections                = 0;



int parse_PE(void) {
    IMAGE_DOS_HEADER        *doshdr;
    MYIMAGE_NT_HEADERS32    *nt32hdr;
    IMAGE_ROM_HEADERS       *romhdr;
    IMAGE_OS2_HEADER        *os2hdr;
    IMAGE_VXD_HEADER        *vxdhdr;
    IMAGE_SECTION_HEADER    *sechdr;
    vxd_section_t           *vxdsechdr;
    u32     tmp;
    int     i;
    u8      *p;
    u32     sec_align,
            entrypoint;

    if(!filemem) return(-1);
    p = filemem;
    doshdr  = (IMAGE_DOS_HEADER *)p;
#ifndef WIN32
    if(myendian) {  // big endian
        myswap16(&doshdr->e_magic);
        myswap16(&doshdr->e_cs);
        myswap16(&doshdr->e_cparhdr);
        myswap32(&doshdr->e_lfanew);
        myswap16(&doshdr->e_ip);
    }
#endif
    if(doshdr->e_magic != IMAGE_DOS_SIGNATURE) return(-1);

    if(doshdr->e_cs) {  // note that the following instructions have been tested on various executables but I'm not sure if they are perfect
        tmp = doshdr->e_cparhdr * 16;
        if(doshdr->e_cs < 0x8000) tmp += doshdr->e_cs * 16;
        p += tmp;
    } else {
        if(doshdr->e_lfanew && (doshdr->e_lfanew < filememsz)) {
            p += doshdr->e_lfanew;
        } else {
            p += sizeof(IMAGE_DOS_HEADER);
        }
    }

    nt32hdr = (MYIMAGE_NT_HEADERS32 *)p;
    romhdr  = (IMAGE_ROM_HEADERS *)p;
    os2hdr  = (IMAGE_OS2_HEADER *)p;
    vxdhdr  = (IMAGE_VXD_HEADER *)p;
#ifndef WIN32
    if(myendian) {  // big endian
        myswap32(&nt32hdr->Signature);
        myswap16(&nt32hdr->OptionalHeader.Magic);
        myswap32(&nt32hdr->OptionalHeader.ImageBase);
        myswap32(&nt32hdr->OptionalHeader.SectionAlignment);
        myswap32(&nt32hdr->OptionalHeader.AddressOfEntryPoint);
        myswap16(&nt32hdr->FileHeader.NumberOfSections);

        myswap16(&romhdr->OptionalHeader.Magic);
        myswap32(&romhdr->OptionalHeader.AddressOfEntryPoint);

        myswap16(&os2hdr->ne_magic);
        myswap16(&os2hdr->ne_align);
        myswap32(&os2hdr->ne_csip);

        myswap16(&vxdhdr->e32_magic);
        myswap32(&vxdhdr->e32_pagesize);
        myswap32(&vxdhdr->e32_objcnt);
        myswap32(&vxdhdr->e32_datapage);
        myswap32(&vxdhdr->e32_eip);
    }
#endif

    if(nt32hdr->Signature == IMAGE_NT_SIGNATURE) {
        if(nt32hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            p += sizeof(MYIMAGE_NT_HEADERS32);
            imagebase   = nt32hdr->OptionalHeader.ImageBase;
            sec_align   = nt32hdr->OptionalHeader.SectionAlignment;
            entrypoint  = imagebase + nt32hdr->OptionalHeader.AddressOfEntryPoint;
            sections    = nt32hdr->FileHeader.NumberOfSections;
        //} else if(nt64hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { not supported, the tool is 32 bit oriented
        } else if(romhdr->OptionalHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
            p += sizeof(IMAGE_ROM_HEADERS);
            imagebase   = 0;
            sec_align   = MYALIGNMENT;
            entrypoint  = imagebase + romhdr->OptionalHeader.AddressOfEntryPoint;
            sections    = 0;
            section     = NULL;
            return(0);
        } else {
            return(-1);
        }

        section = calloc(sizeof(section_t), sections);
        if(!section) std_err();

        sechdr = (IMAGE_SECTION_HEADER *)p;
        for(i = 0; i < sections; i++) {
#ifndef WIN32
            if(myendian) {
                myswap32(&sechdr[i].VirtualAddress);
                myswap32(&sechdr[i].Misc.VirtualSize);
                myswap32(&sechdr[i].PointerToRawData);
                myswap32(&sechdr[i].SizeOfRawData);
                myswap32(&sechdr[i].Characteristics);
            }
#endif
            strncpy(section[i].Name, sechdr[i].Name, IMAGE_SIZEOF_SHORT_NAME);
            section[i].VirtualAddress   = sechdr[i].VirtualAddress;
            section[i].VirtualSize      = sechdr[i].Misc.VirtualSize;
            section[i].VirtualSize_off  = ((u8 *)&(sechdr[i].Misc.VirtualSize)) - filemem;
            section[i].PointerToRawData = sechdr[i].PointerToRawData;
            section[i].SizeOfRawData    = sechdr[i].SizeOfRawData;
            section[i].Characteristics  = sechdr[i].Characteristics;
            if(!section[i].VirtualSize) section[i].VirtualSize = section[i].SizeOfRawData;  // Watcom
        }

    } else if(os2hdr->ne_magic == IMAGE_OS2_SIGNATURE) {
        p += sizeof(IMAGE_OS2_HEADER);
        imagebase   = 0;
        sec_align   = os2hdr->ne_align;
        entrypoint  = imagebase + os2hdr->ne_csip;
        sections    = 0;
        sechdr      = NULL;

    } else if(
      (vxdhdr->e32_magic == IMAGE_OS2_SIGNATURE_LE) ||  // IMAGE_VXD_SIGNATURE is the same signature
      (vxdhdr->e32_magic == 0x3357) ||                  // LX, W3 and W4: I guess they are the same... I hope
      (vxdhdr->e32_magic == 0x3457) ||
      (vxdhdr->e32_magic == 0x584C)) {
        p += sizeof(IMAGE_VXD_HEADER);
        imagebase   = 0;
        sec_align   = vxdhdr->e32_pagesize;
        entrypoint  = 0;    // handled later
        sections    = vxdhdr->e32_objcnt;

        section = calloc(sizeof(section_t), sections);
        if(!section) std_err();

        tmp = vxdhdr->e32_datapage;
        vxdsechdr = (vxd_section_t *)p;
        for(i = 0; i < sections; i++) {
#ifndef WIN32
            if(myendian) {
                myswap32(&vxdsechdr[i].base_reloc_addr);
                myswap32(&vxdsechdr[i].vsize);
                myswap32(&vxdsechdr[i].flags);
            }
#endif
            strncpy(section[i].Name, vxdsechdr[i].name, 4);
            section[i].VirtualAddress   = vxdsechdr[i].base_reloc_addr;
            section[i].VirtualSize      = vxdsechdr[i].vsize;
            section[i].VirtualSize_off  = ((u8 *)&(vxdsechdr[i].vsize)) - filemem;
            section[i].PointerToRawData = tmp;
            section[i].SizeOfRawData    = vxdsechdr[i].vsize;
            section[i].Characteristics  = vxdsechdr[i].flags;
            tmp += MYPAD(section[i].SizeOfRawData);
            if(!entrypoint && (tmp > vxdhdr->e32_eip)) {    // I'm not totally sure if this is correct but it's not an important field
                entrypoint = section[i].VirtualAddress + vxdhdr->e32_eip;
            }
        }
    } else {
        imagebase   = 0;
        sec_align   = 0;
        entrypoint  = imagebase + (doshdr->e_cs < 0x8000) ? doshdr->e_ip : 0;
        sections    = 0;
    }
    return(p - filemem);
}



int parse_ELF32(void) {
    elf32_header_t  *elfhdr;
    elf32_section_t *elfsec;
    int     i;
    u8      *p;
    u32     sec_align,
            entrypoint;

    if(!filemem) return(-1);
    p = filemem;
    elfhdr = (elf32_header_t *)p;     p += sizeof(elf32_header_t);
    if(memcmp(elfhdr->e_ident, "\x7f""ELF", 4)) return(-1);
    if(elfhdr->e_ident[4] != 1) return(-1); // only 32 bit supported
    //if(elfhdr->e_ident[5] != 1) return(-1); // only little endian

    if(((elfhdr->e_ident[5] == 1) && myendian) || ((elfhdr->e_ident[5] != 1) && !myendian)) {
        myswap32(&elfhdr->e_entry);
        myswap16(&elfhdr->e_shnum);
        myswap32(&elfhdr->e_shoff);
        myswap16(&elfhdr->e_shstrndx);
    }

    imagebase   = 0;
    sec_align   = 0;
    entrypoint  = elfhdr->e_entry;

    sections = elfhdr->e_shnum;
    section = calloc(sizeof(section_t), sections);
    if(!section) std_err();

    elfsec = (elf32_section_t *)(filemem + elfhdr->e_shoff);
    for(i = 0; i < sections; i++) {
        if(((elfhdr->e_ident[5] == 1) && myendian) || ((elfhdr->e_ident[5] != 1) && !myendian)) {
            myswap32(&elfsec[i].sh_addr);
            myswap32(&elfsec[i].sh_name);
            myswap32(&elfsec[i].sh_offset);
            myswap32(&elfsec[i].sh_size);
            myswap32(&elfsec[i].sh_flags);
        }
        strncpy(section[i].Name, filemem + elfsec[elfhdr->e_shstrndx].sh_offset + elfsec[i].sh_name, SECNAMESZ);
        section[i].Name[SECNAMESZ]  = 0;
        section[i].VirtualAddress   = elfsec[i].sh_addr;
        section[i].VirtualSize      = elfsec[i].sh_size;
        section[i].VirtualSize_off  = ((u8 *)&(elfsec[i].sh_size)) - filemem;
        section[i].PointerToRawData = elfsec[i].sh_offset;
        section[i].SizeOfRawData    = elfsec[i].sh_size;
        section[i].Characteristics  = elfsec[i].sh_flags;
        if(!section[i].VirtualSize) section[i].VirtualSize = section[i].SizeOfRawData;  // Watcom
    }
    return(p - filemem);
}



u32 rva2file(u32 va) {
    u32     diff;
    int     i,
            ret;

    va  -= imagebase;
    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((sections > 1) && !section[i].VirtualAddress) continue;
        if((va >= section[i].VirtualAddress) && (va < (section[i].VirtualAddress + section[i].VirtualSize))) {
            if((va - section[i].VirtualAddress) < diff) {
                diff = va - section[i].VirtualAddress;
                ret  = i;
            }
        }
    }
    //if(ret < 0) return(-1);
    if(ret < 0) return(va);
    return(section[ret].PointerToRawData + va - section[ret].VirtualAddress);
}



u32 file2rva(u32 file) {
    u32     diff;
    int     i,
            ret;

    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((file >= section[i].PointerToRawData) && (file < (section[i].PointerToRawData + section[i].SizeOfRawData))) {
            if((file - section[i].PointerToRawData) < diff) {
                diff = file - section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    //if(ret < 0) return(-1);
    if(ret < 0) return(imagebase + file);
    return(imagebase + section[ret].VirtualAddress + file - section[ret].PointerToRawData);
}



int get_section(u32 file) {
    u32     diff;
    int     i,
            ret;

    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((file >= section[i].PointerToRawData) && (file < (section[i].PointerToRawData + section[i].SizeOfRawData))) {
            if((file - section[i].PointerToRawData) < diff) {
                diff = file - section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    return(ret);
}



int parse_exe(void) {
    int     offset;

                   offset = parse_PE();
    if(offset < 0) offset = parse_ELF32();
    if(offset < 0) return(-1);

    if(!sections || !section) { // possible work-around in case of errors
        section = realloc(section, sizeof(section_t));
        if(!section) std_err();
        section[0].VirtualAddress   = 0;
        section[0].VirtualSize      = filememsz - offset;
        section[0].VirtualSize_off  = -1;
        section[0].PointerToRawData = offset;
        section[0].SizeOfRawData    = filememsz - offset;
        section[0].Characteristics  = 0;
        sections = 1;
    }
    return(0);
}



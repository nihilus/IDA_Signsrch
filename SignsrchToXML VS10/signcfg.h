/*
    Copyright 2007,2008,2009 Luigi Auriemma

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

#define TYPE_8BIT       1
#define TYPE_16BIT      2
#define TYPE_32BIT      4
#define TYPE_64BIT      8
#define TYPE_FLOAT      16
#define TYPE_DOUBLE     32
#define TYPE_CRC        64
#define TYPE_FORCE_HEX  128
#define TYPE_AND        256
#define TYPE_NOBIG      512



#define ENDIAN_LITTLE   0
#define ENDIAN_BIG      1



enum {
    CMD_TITLE,
    CMD_TYPE,
    CMD_DATA,
    CMD_NONE = -1
};



u64     current_type;
u8      *current_title;



int delimit(u8 *data) {
    u8      *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



int lowstr(u8 *data) {
    u8      *p;

    for(p = data; *p; p++) {
        *p = tolower(*p);
    }
    return(p - data);
}



u64 readbase(u8 *data, int size, int *ret_len) {
    static const u8 table[] = "0123456789abcdef";
    u64     num;
    int     sig = 0;
    u8      c,
            *p,
            *start;

    if(ret_len) *ret_len = 0;
    start = data;
    if(!data) return(0);
    if(!*data) return(0);

    if(*data == '-') {  // useless in calcc but can useful in other programs
        sig = 1;
        data++;
    }
    if((strlen(data) > 2) && (data[0] == '0') && (data[1] == 'x')) {
        size = 16;      // hex
        data += 2;
    }
    if((size == 10) && (data[0] == '0')) {
        size = 8;       // octal
        data++;
    }
    for(num = 0; *data; data++) {
        c = tolower(*data); // needed
        p = memchr(table, c, size);
        if(!p) break;
        num = (num * size) + (p - table);
    }
    if(sig) num = -num;
    if(ret_len) *ret_len = data - start;
    return(num);
}



u64 get_fmt_char(u8 **data) {
    u64     num = 0;
    int     len;
    u8      *str;

    str = *data;
    if(!str || !str[0]) {
        *data = NULL;
        return(0);
    }

	// \n and so on
    if(str[0] == '\\')
	{    
        len = 0;
        switch(str[1]) 
		{
            case 0:    num = 0;    break;
            case '0':  num = '\0'; break;
            case 'a':  num = '\a'; break;
            case 'b':  num = '\b'; break;
            case 'e':  num = '\e'; break;
            case 'f':  num = '\f'; break;
            case 'n':  num = '\n'; break;
            case 'r':  num = '\r'; break;
            case 't':  num = '\t'; break;
            case 'v':  num = '\v'; break;
            case '\"': num = '\"'; break;
            case '\'': num = '\''; break;
            case '\\': num = '\\'; break;
            case '?':  num = '\?'; break;
            case '.':  num = '.';  break;
            case 'x':  num = readbase(str + 2, 16, &len);   break;  // hex
            default:   num = readbase(str + 1,  8, &len);   break;  // auto
        }
        len += 2;
    } else {
        len = 1;
        num = str[0];       // 'a'
    }

    str += len;
    if(!str[0]) {
        *data = NULL;
    } else {
        *data = str;
    }
    return(num);
}



int check_num_type(u8 *data) {
    int     c,
            ret = 0;
    u8      *p;

    for(p = data; (c = *p); p++) {
        if((c >= '0') && (c <= '9')) {
            // ret = 0;
        } else if((c >= 'a') && (c <= 'f')) {
            ret = TYPE_FORCE_HEX;
        } else if(c == '.') {
            ret = TYPE_FLOAT;
            break;
        }
    }
    return(ret);
}



u64 get_num(u8 *data) {
    float   numf;
    double  numlf;
    int     chk;
    u64     num;
    u32     tmp32;
    u8      *p;

    if(!data || !data[0]) return(0);

    num = 0;
    if(data[0] == '\'') {
        p = data + 1;
        num = get_fmt_char(&p);
    } else {
        lowstr(data);

        if(data[0] == '_') data++;
        chk = check_num_type(data);

        if(!strcmp(data, "int_min")) {                                  // INT_MIN
            num = (u64)0x80000000;
        } else if(!strcmp(data, "int_max")) {                           // INT_MAX
            num = (u64)0x7fffffff;
        } else if(!strcmp(data, "i64_min")) {                           // I64_MIN
            num = (u64)0x8000000000000000ULL;
        } else if(!strcmp(data, "i64_max")) {                           // I64_MAX
            num = (u64)0x7fffffffffffffffULL;
        } else if(current_type & TYPE_DOUBLE) {                         // DOUBLE
            //if(chk != TYPE_FLOAT) printf("- %s\n  a double without dot???\n", current_title);
            numlf = atof(data);
            memcpy(&num, &numlf, sizeof(numlf));
        } else if(strchr(data, '.') || (current_type & TYPE_FLOAT)) {   // FLOAT
            //if(chk != TYPE_FLOAT) printf("- %s\n  a float without dot???\n", current_title);
            numf = (float) atof(data);
            memcpy(&tmp32, &numf, 4);
            num = tmp32;
        } else if(strstr(data, "0x") || strchr(data, '$') || strchr(data, 'h') || (current_type & TYPE_FORCE_HEX)){
            if(chk == TYPE_FLOAT) goto error;                           // HEX
            num = readbase(data, 16, NULL);
        } else {                                                        // DECIMAL
            if((chk == TYPE_FORCE_HEX) || (chk == TYPE_FLOAT)) goto error;
            num = readbase(data, 10, NULL);
        }
    }

    return(num);

error:
    printf("\n"
        "Error: %s\n"
        "       the number \"%s\" doesn't match the type specified\n",
        current_title,
        data);
    free_sign();
    exit(1);
}



u8 *get_cfg_cmd(u8 *line, int *cmdnum) {
    int     i,
            cmdret;
    u8      *cmd,
            *p,
            *l;
    static const u8 *command[] = {
            "TITLE",
            "TYPE",
            "DATA",
            NULL };

    cmdret  = CMD_NONE;
    *cmdnum = CMD_NONE;

    l = line + delimit(line);

    for(p = line; *p; p++) {        // clear start
        if((*p != ' ') && (*p != '\t')) break;
    }
    if(!*p) return(NULL);

    cmd = p;                        // cmd

    for(l--; l > p; l--) {          // clear end
        if(*l > ' ') break;
    }
    *(l + 1) = 0;

    if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return(NULL);

    for(p = cmd; *p > ' '; p++);    // find where the command ends

    for(i = 0; command[i]; i++) {
        if(!memcmp(cmd, command[i], p - cmd)) {
            cmdret = i;
            break;
        }
    }

    if(cmdret != CMD_NONE) {        // skip the spaces between the comamnd and the instructions
        for(; *p; p++) {
            if((*p != ' ') && (*p != '\t')) break;
        }
        cmd = p;
    }

    // do not enable this or will not work!
    // if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return("");

    *cmdnum = cmdret;
    return(cmd);
}



    /* here we catch each line (till line feed) */
    /* returns a pointer to the next line       */
u8 *get_line(u8 *data) {
    u8      *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    if(!*p) return(NULL);
    *p = 0;
    for(p++; *p && ((*p == '\n') || (*p == '\r')); p++);
    if(!*p) return(NULL);
    return(p);
}



    /* here we catch each element of the line */
    /* returns a pointer to the next element  */
u8 *get_element(u8 **data, int *isastring) {
    u8      *p;

    p = *data;

    if(p[0] == '\'') {
        for(p++; *p; p++) {
            if(p[0] == '\'') {
                p++;
                break;
            }
        }
    } else if((p[0] == '/') && (p[1] == '*')) {    // /* comment */
        for(p += 2; *p; p++) {
            if((p[0] == '*') && (p[1] == '/')) {
                p += 2;
                break;
            }
        }
    } else if(*p == '"') {                  // string
        if(isastring) *isastring = 1;
        p++;
        for(*data = p; *p && (*p != '\"'); p++) {
            if(*p == '\\') p++;
            if(!*p) break;
        }
    } else {
        if(isastring) *isastring = 0;   // the following are delimiters
        while(*p && (*p != '\t') && (*p != ' ') && (*p != ',') && (*p != '{') && (*p != '}') && (*p != '(') && (*p != ')') && (*p != '\\')) {
            if((*p == '%') || (*p == '*')) {    // + and - are ok, it's not easy to make distinction between inline operations and negative/positive numbers of exponential floats
                fprintf(stderr, "\nError: found some invalid chars in the list\n");
                exit(1);
            }
            p++;
        }
    }

    if(!*p) return(NULL);                   // end of line
    *p = 0;

    for(p++; *p && ((*p == '\t') || (*p == ' ')); p++);
    if(!*p) return(NULL);                   // start of next line
    return(p);
}


void cfg_title(u8 *line) {
    if(current_title) free(current_title);
    current_title = _strdup(line);
}



void cfg_type(u8 *line) {
    u8      *next,
            *sc,
            *scn;

    current_type = 0;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, NULL);

            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments, ';' is used also at the end of the C structures

            lowstr(sc);

#define C(X)    !strcmp(sc, X)
#define S(X)    strstr(sc, X)
            if(C("unsigned")) continue;
            if(!memcmp(sc, "u_", 2)) sc += 2;
            if(sc[0] == 'u') sc++;

            if(S("int8")  || C("8")  || S("char"))              current_type |= TYPE_8BIT;
            if(S("int16") || C("16") || S("short"))             current_type |= TYPE_16BIT;
            if(S("int32") || C("32") || C("int") || S("long"))  current_type |= TYPE_32BIT;
            if(S("int64") || C("64"))                           current_type |= TYPE_64BIT;
            if(C("float"))                                      current_type |= TYPE_FLOAT;
            if(C("crc")   || C("checksum"))                     current_type |= TYPE_CRC;
            if(C("hex")   || C("forcehex"))                     current_type |= TYPE_FORCE_HEX;
            if(C("and")   || C("&&"))                           current_type |= TYPE_AND;
            if(C("nobig"))                                      current_type |= TYPE_NOBIG;
#undef C
#undef S

            sc = scn;
        } while(scn);

        line = next;
    } while(next);
}



u8 *cfg_add_element(u8 *op, int *oplen, u64 num, int size, int endian) {
    int     len = *oplen;

    if(!alt_endian && (endian == ENDIAN_BIG)) return(op);
    if((size == 8) && (endian == ENDIAN_BIG)) return(op);

    if((int64_t)num >= 0) {
        if((size == 8)  && (num > 0xff))        goto error;
        if((size == 16) && (num > 0xffff))      goto error;
        if((size == 32) && (num > 0xffffffff))  goto error;
    }

    len += size >> 3;
    op = realloc(op, len);
    if(!op) std_err();

    if(size == 8) {
        op[len - 1] = (u8) num;

    } else if(size == 16) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 2] = (num      );
            op[len - 1] = (num >>  8);
        } else {
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(size == 32) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 4] = (num      );
            op[len - 3] = (num >>  8);
            op[len - 2] = (num >> 16);
            op[len - 1] = (num >> 24);
        } else {
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(size == 64) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 8] = (num      );
            op[len - 7] = (num >>  8);
            op[len - 6] = (num >> 16);
            op[len - 5] = (num >> 24);
            op[len - 4] = (num >> 32);
            op[len - 3] = (num >> 40);
            op[len - 2] = (num >> 48);
            op[len - 1] = (num >> 56);
        } else {
            op[len - 8] = (num >> 56);
            op[len - 7] = (num >> 48);
            op[len - 6] = (num >> 40);
            op[len - 5] = (num >> 32);
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }
    }

    *oplen = len;
    return(op);

error:
    printf("\n"
        "Error: %u) %s\n"
        "       the number 0x%08x%08x is bigger than %d bits\n"
        "       check your signature file, probably you must increate the TYPE size\n",
        signs, current_title,
        (u32)((num >> 32) & 0xffffffff), (u32)(num & 0xffffffff), size);
    free_sign();
    exit(1);
}    



void add_sign(u8 *type, u8 *endian, u8 *data, int datasize, int bits) {
    static int  signs_blocks    = 0; // limits a realloc massacre
    int     len;

    if(!datasize) return;
    if(!*type) endian = "";
    if(signs >= signs_blocks) {
        signs_blocks += 8000;   // a big amount, I doubt that signsrch.sig will reach this number of entries
        sign = realloc(sign, sizeof(sign_t *) * signs_blocks);
        if(!sign) std_err();
    }
    sign[signs]        = malloc(sizeof(sign_t));
    if(!sign[signs]) std_err();
    sign[signs]->title = malloc(strlen(current_title) + strlen(type) + strlen(endian) + 10 + 5 + 1);
    len = sprintf(sign[signs]->title, "%s [%s.%s.%u%s]",
        current_title, type, endian, datasize, (current_type & TYPE_AND) ? "&" : "");
    sign[signs]->data  = data;
    sign[signs]->size  = datasize;
    sign[signs]->Bits  = 0;
    if(current_type & TYPE_AND) sign[signs]->Bits = bits;

	// KW: Store endian
	// 0 = N/a
	// 1 = Little
	// 2 = Big
 // ** Not used right now anyhow
	sign[signs]->Flags = 0;
	if(endian[0])
	{
		if(*((PWORD) endian) == MAKEWORD('l','e'))
			sign[signs]->Flags = 1;
		else
		if(*((PWORD) endian) == MAKEWORD('b','e'))
			sign[signs]->Flags = 2;		
	}

    sign_alloclen +=
        + sizeof(sign_t *)
        + sizeof(sign_t)
        + len
        + datasize;
    signs++;
}



#define BITMASK(SIZE)   ((u64)1 << (u64)(SIZE))



u64 reflect(u64 v, int b) {
    u64     t;
    int     i;

    t = v;
    for(i = 0; i < b; i++) {
        if(t & (u64)1) {
            v |= BITMASK((b - 1) - (u64)i);
        } else {
            v &= (BITMASK((b - 1) ^ (u64)0xffffffffffffffffLL) - (u64)i);
        }
        t >>= (u64)1;
    }
    return(v);
}



u64 widmask(int size) {
    return((((u64)1 << (u64)(size - 1)) - (u64)1) << (u64)1) | (u64)1;
}



u64 cm_tab(int inbyte, u64 poly, int size, int rever) {
    u64     r,
            topbit;
    int     i;

    topbit = BITMASK(size - 1);

    if(rever) inbyte = (int) reflect(inbyte, 8);

    r = (u64)inbyte << (u64)(size - 8);

    for(i = 0; i < 8; i++) {
        if(r & topbit) {
            r = (r << (u64)1) ^ poly;
        } else {
            r <<= (u64)1;
        }
    }

    if(rever) r = reflect(r, size);

    return(r & widmask(size));
}



u8 *make_crc(u8 *op, int *oplen, u64 poly, int size, int endian, int rever) {
    u64     num;
    int     i,
            len = *oplen;

    for(i = 0; i < 256; i++) {
        num = cm_tab(i, poly, size, rever);
        op = cfg_add_element(op, &len, num, size, endian);
    }

    *oplen = len;
    return(op);
}



void cfg_data(u8 *line) {
    int     opi8len   = 0,
            opi16len  = 0,
            opi32len  = 0,
            opi64len  = 0,
            opifltlen = 0,
            opidbllen = 0;
    u8      *opi8     = NULL,
            *opi16    = NULL,
            *opi32    = NULL,
            *opi64    = NULL,
            *opiflt   = NULL,
            *opidbl   = NULL;

    int     opb8len   = 0,
            opb16len  = 0,
            opb32len  = 0,
            opb64len  = 0,
            opbfltlen = 0,
            opbdbllen = 0;
    u8      *opb8     = NULL,   // NEVER used
            *opb16    = NULL,
            *opb32    = NULL,
            *opb64    = NULL,
            *opbflt   = NULL,
            *opbdbl   = NULL;

    int     opicrclen = 0,
            opbcrclen = 0;
    u8      *opicrc   = NULL,
            *opbcrc   = NULL;

    int     opstrlen  = 0;
    u8      *opstr    = NULL;

    u64     num;
    int     isastring = 0;
    u8      *next,
            *sc,
            *scn,
            *p;

    if(!current_type) current_type |= TYPE_8BIT;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, &isastring);

            if((sc[0] == '/') && (sc[1] == '*')) goto scn_continue; // don't touch
            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments, ';' is used also at the end of the C structures
            if(!sc[0]) goto scn_continue;

            if(isastring) {
                for(p = sc; p;) {
                    num = get_fmt_char(&p);
                    opstr = cfg_add_element(opstr, &opstrlen, num, 8, ENDIAN_LITTLE);
                }
                goto scn_continue;
            }

            num = get_num(sc);

            if(current_type & TYPE_CRC) {
                    /* ONLY ONE CRC AT TIME IS ALLOWED */

#define DOIT(TYPENAME, BITS, TYPE)  \
                if(current_type & TYPE_##TYPENAME) {                                        \
                    opicrc = make_crc(NULL, &opicrclen, num, BITS, ENDIAN_LITTLE, 1);       \
                    add_sign(TYPE, "le rev", opicrc, opicrclen, BITS);                      \
                    if((num != 1) && (current_type & TYPE_NOBIG)) {                         \
                        opicrclen = 0;                                                      \
                        opicrc = make_crc(NULL, &opicrclen, num, BITS, ENDIAN_LITTLE, 0);   \
                        add_sign(TYPE, "le", opicrc, opicrclen, BITS);                      \
                    }                                                                       \
                    if(BITS > 8) {                                                          \
                        opbcrc = make_crc(NULL, &opbcrclen, num, BITS, ENDIAN_BIG, 1);      \
                        add_sign(TYPE, "be rev", opbcrc, opbcrclen, BITS);                  \
                        if(current_type & TYPE_NOBIG) {                                     \
                            opbcrclen = 0;                                                  \
                            opbcrc = make_crc(NULL, &opbcrclen, num, BITS, ENDIAN_BIG, 0);  \
                            add_sign(TYPE, "be", opbcrc, opbcrclen, BITS);                  \
                        }                                                                   \
                    }                                                                       \
                }

                DOIT(8BIT,   8,   "")
                DOIT(16BIT,  16,  "16")
                DOIT(32BIT,  32,  "32")
                DOIT(64BIT,  64,  "64")

#undef DOIT

                return;
            }

#define DOIT(TYPENAME, NAME, BITS)  \
            if(current_type & TYPE_##TYPENAME) {  \
                opi##NAME = cfg_add_element(opi##NAME, &opi##NAME##len, num, BITS, ENDIAN_LITTLE);  \
                opb##NAME = cfg_add_element(opb##NAME, &opb##NAME##len, num, BITS, ENDIAN_BIG);     \
            }

            DOIT(8BIT,   8,   8)
            DOIT(16BIT,  16,  16)
            DOIT(32BIT,  32,  32)
            DOIT(64BIT,  64,  64)
            DOIT(FLOAT,  flt, 32)

                /* stupid and lame work-around for double and float */
                /* but it works 8-) */
            if(current_type & TYPE_FLOAT) {     // if float = do double too
                current_type |= TYPE_DOUBLE;    // enable double
                num = get_num(sc);              // re-read the number
                DOIT(DOUBLE, dbl, 64)           // add it
                current_type ^= TYPE_DOUBLE;    // disable double
            }

#undef DOIT

scn_continue:
            sc = scn;
        } while(scn);

        line = next;
    } while(next);

#define DOIT(NAME, BITS, TYPE)    \
    if(opi##NAME) add_sign(TYPE, "le", opi##NAME, opi##NAME##len, BITS);    \
    if(current_type & TYPE_NOBIG) {                                         \
        free(opb##NAME);                                                    \
        opb##NAME = NULL;                                                   \
    }                                                                       \
    if(opb##NAME) {                                                         \
        if(opi##NAME) { /* remove duplicates! */                            \
            if(!memcmp(opi##NAME, opb##NAME, opb##NAME##len)) {             \
                free(opb##NAME);                                            \
            } else {                                                        \
                add_sign(TYPE, "be", opb##NAME, opb##NAME##len, BITS);      \
            }                                                               \
        }                                                                   \
    }

    DOIT(8,     8,      "")
    DOIT(16,    16,     "16")
    DOIT(32,    32,     "32")
    DOIT(64,    64,     "64")
    DOIT(flt,   32,     "float")
    DOIT(dbl,   64,     "double") 
    if(opstr) 
		add_sign("", "", opstr, opstrlen, 8);

#undef DOIT
}



void cfg_cmd(int cmdnum, u8 *line) {
    switch(cmdnum) {
        case CMD_TITLE: cfg_title(line);    break;
        case CMD_TYPE:  cfg_type(line);     break;
        case CMD_DATA:  cfg_data(line);     break;
        default:                            break;
    }
}



void read_cfg(u8 *filename) {
    FILE    *fd;
    int     len,
            currlen,
            bufflen,
            oldnum,
            cmdnum,
            tmp;
    u8      line[256],
            *buff,
            *buff_limit,
            *data,
            *ins;

    printf("- open file %s\n", filename);
    fd = fopen(filename, "rb");
    if(!fd) std_err();

    bufflen    = 256;
    buff       = malloc(bufflen);
    if(!buff) std_err();
    data       = buff;
    buff_limit = buff + bufflen;
    buff[0]    = 0;
    line[0]    = 0;
    oldnum     = CMD_NONE;

    while(fgets(line, sizeof(line), fd)) {
        ins = get_cfg_cmd(line, &cmdnum);
        if(!ins) continue;

        if(oldnum == CMD_NONE) oldnum = cmdnum;
        if(cmdnum == CMD_NONE) cmdnum = oldnum;
        if(cmdnum != oldnum) {
            tmp    = cmdnum;
            cmdnum = oldnum;
            oldnum = tmp;

            cfg_cmd(cmdnum, buff);

            data = buff;
        }

        len = strlen(ins);  // allocation
        if((data + len) >= buff_limit) 
		{
            currlen    = data - buff;
            bufflen    = currlen + 1 + len + 1; // 1 for \n and 1 for the final NULL byte
            buff       = realloc(buff, bufflen);
            if(!buff) std_err();
            data       = buff + currlen;
            buff_limit = buff + bufflen;
        }

        if(data > buff) data += sprintf(data, "\n");
        data += sprintf(data, "%s", ins);
        line[0] = 0;
    }
        // the remaining line
    cmdnum = oldnum;
    if((cmdnum != CMD_NONE) && (data != buff)) cfg_cmd(cmdnum, buff);

    free(buff);
    fclose(fd);
}

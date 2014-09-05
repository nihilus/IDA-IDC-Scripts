// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>

// this script contains fucntios to which search for relative references to the current address
//
// find_arm_relative();
// find_thumb_relative();
// find_x86_relative();
//
static find_arm_relative()
{
    auto sea, ea, d, start;
    sea= ScreenEA();
    start=NextAddr(sea-(1<<25)-1);
    if (start==BADADDR)
        start=FirstSeg();
    for (ea=start ; ea < sea+(1<<25) && ea!=BADADDR ; ea=NextAddr(ea+3)) {
        if ((Dword(ea)&0xfe000000)==0xea000000) {
            d= Dword(ea)&0xffffff;
            if (d&0x800000) {
                d=d-0x1000000;
            }
            if (ea+8+d*4==sea) {
                Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
            }
        }
    }
}
static find_thumb_relative()
{
    auto sea, ea, d,eea, start;
    sea= ScreenEA();
    if (isData(GetFlags(sea))) {
        start= NextAddr(sea-(1<<10)-1);
        if (start==BADADDR)
            start=FirstSeg();
        // find a LDR Rx,=value  type reference.
        for (ea=start ; ea < sea+(1<<10) && ea!=BADADDR ; ea=NextAddr(ea+1)) {
            if ((Word(ea)&0xf800) ==0x4800) {
                d= (Word(ea)&0xff)<<2;
                if ((ea&~3)+4+d==sea) {
                    Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
                }
            }
        }
    }
    else {
        // find a B type reference.
        start= NextAddr(sea-(1<<12)-1);
        if (start==BADADDR)
            start=FirstSeg();
        for (ea=start; ea < sea+(1<<12) && ea!=BADADDR ; ea=NextAddr(ea+1)) {
            if ((Word(ea)&0xf800) ==0xe000) {
                d= (Word(ea)&0x7ff)<<1;
                if (d&(0x400<<1)) {
                    d= d-(0x800<<1);
                }
                if (ea+4+d==sea) {
                    Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
                }
            }
        }
        // find a BL[x] type reference.
        start= NextAddr(sea-(1<<22)-1);
        if (start==BADADDR)
            start=FirstSeg();
        for (ea=start ; ea < sea+(1<<22) && ea!=BADADDR ; ea=NextAddr(ea+1)) {
            if ((Dword(ea)&0xe800e800) ==0xe800e000) {
                d= ((Dword(ea)&0x7ff0000)>>15) | ((Dword(ea)&0x7ff)<<12);
                if (d&(0x400<<12)) {
                    d= d-(0x800<<12);
                }
                if (ea+4+d==sea) {
                    Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
                }
            }
        }
    }
}
static find_x86_relative()
{
    auto sea, ea, d,eea;
    sea= ScreenEA();
    for (ea=sea-0x81 ; ea<sea+0x81; ea=ea+1) {
        d= Byte(ea);
        if (ea+d+1==sea) {
            Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
        }
    }
    for (ea=sea-0x8001 ; ea<sea+0x8001; ea=ea+1) {
        d= Word(ea);
        if (ea+d+2==sea) {
            Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
        }
    }

    for (eea=FirstSeg() ; eea!=BADADDR ; eea=NextSeg(eea)) {
        for (ea= SegStart(eea) ; ea<SegEnd(eea) ; ea=ea+1) {
            d= Dword(ea);
            if (ea+d+4==sea) {
                Message("%08lx -> %08lx : %s\n", ea, sea, GetDisasm(ea));
            }
        }
    }
}

static find_pattern(str) {
    auto ea;
    ea=FirstSeg();
    while ((ea=FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN, str))!=BADADDR) {
        if ((ea&3)==0) {
            Message("%08lx - abs\n", ea);
        }
    }
}
static find_abs()
{
    auto ea; ea=here;
    find_pattern(form("%02x %02x %02x %02x", ea&0xff, (ea>>8)&0xff, (ea>>16)&0xff, (ea>>24)&0xff));
    ea=ea+1;
    find_pattern(form("%02x %02x %02x %02x", ea&0xff, (ea>>8)&0xff, (ea>>16)&0xff, (ea>>24)&0xff));
}

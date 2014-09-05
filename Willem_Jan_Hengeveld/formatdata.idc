// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
//
// the useful function in this script are:
//   ParsePdata();  ... will parse the currently selected data as 'pdata'
//         ( and create functions accordingly )
//   FixFunctions();   ... will set the function 'ends' to include the
//                     constant pools at the end of each function, such
//                     that xrefs from there show belonging to this function
//   Table(pattern);   format the current selection as 'pattern'
//
//   fix4033()         isolate EdbgVendorIds blocks, in windows ce binaries.
//   memcmp, memcpy, memset - like the clib functions
//   summarize_unk     create dwords, or byte arrays from undefined area's
//
// PATTERNS:
//   a sequence of format characters ( letters )
//   followed by a count.
//
// format specifiers:
//    o    - pointer to data
//    s    - pointer to ascii string
//    s    - pointer to unicode string
//    d[N] - dword
//    w[N] - word
//    b[N] - byte
//    u[N] - double
//    f[N] - fload
//    c    - pointer to code
//    p    - pointer to proc ( function )
//    A[N] - fixed length or zero terminated ascii or unicode string
//    a[N] - ascii string
//    i    - instructions
//    l[N] - align dword, or N: align 1<<N
//    g    - guid

//
#include <idc.idc>

//  commented out, did not work very well.
//#include <fixframe.idc>

// todo: force creation of functions in ParsePdata
// todo: ask user about whether to include data after fn in FixFunctions.
// todo: add processor dependend flags, code address alignment.
// todo: add settable flags: like ascii+unicode, or only ascii strings, and alignment.
// done:  add '*' to automatically find the next ref/name
//
static ParsePdata(ea,end)
{
    auto x, fn, pd;
    if (ea==BADADDR) {
        ea=SelStart();
        end=SelEnd();
    }
    if (ea==BADADDR) {
        return;
    }
    MakeTable(ea, end, "cd");
    x= ea;
    while (x<end)
    {
        fn= Dword(x);
        pd= Dword(x+4);
        //Message("making fn %08lx %08lx  : l=%08lx end=%08lx\n", fn, pd, (pd&0xffff0)>>6, ((pd&0xffff0)>>6) + fn);
        MakeFunction(fn, ((pd&0xffff0)>>6) + fn);
        x=x+8;
    }
}

static FixFunctions()
{
    auto next;
    auto ofs, name;
    auto f,g; 
    next= 0;
    f= NextFunction(0);
    while (f!=BADADDR && (g= NextFunction(f))!=BADADDR)
    {
        //analyzefuncframe(f, 1);
        //todo: think of better condition why it might not be a func.
        if (g-FindFuncEnd(f) > 0x80) {
            //Message("function %08lx - %08lx : +%08lx\n", f, g, g-FindFuncEnd(f));
            if (f>ScreenEA() && next==0) { next= f; }
        }
        else {
           SetFunctionEnd(f, g);
        }
        f= g;
    }
    ofs=NextFunction(0);
    while (ofs!=0xffffffff) {
        name= GetFunctionName(ofs);
        if (substr(name, 0, 4)=="sub_" || substr(name, 0, 8)=="nullsub_" || name=="start")
            SetFunctionFlags(ofs, GetFunctionFlags(ofs)&~FUNC_LIB);
        else
            SetFunctionFlags(ofs, GetFunctionFlags(ofs)|FUNC_LIB);
        ofs= NextFunction(ofs);
    }
    if (next) {
        Jump(PrevHead(NextFunction(next), next));
    }
    else {
        Message("no more constant pool found\n");
    }
}
static FixJumpCalls()
{
    auto ea,r; ea= NextFunction(0);
    while (ea!=-1) {
        r=RfirstB(ea);
        while (r!=-1) {
            if (XrefType()!=fl_CF && XrefType()!=fl_CN) {
                Message("%08lx -> %08lx : %d\n", r, ea, XrefType());
                AddCodeXref(r, ea, fl_CN);
            }
            r= RnextB(ea,r);
        }
        ea= NextFunction(ea);
    }
}
static CodeOffset(ea)
{
    if ((Dword(ea)&1) && GetReg(Dword(ea), "T")==0) {
        SetReg(Dword(ea)&~1, "T", 1);
        Wait();
    }
    if (GetReg(Dword(ea), "T"))
        return Dword(ea)&~1;
    else
        return Dword(ea);
}
static MakeTable(ea, end, pattern)
{
    auto ofs, i, c, alen, nlen;
    auto ofs2;

    if (ea==0 && end==0) {
        ea=SelStart();
        end=SelEnd();
        if (ea==BADADDR) {
            return;
        }
    }
    if (end==BADADDR) {
        end=  FindExplored(ea, SEARCH_DOWN);
    }
    if (end==BADADDR) {
        end= SegEnd(ea);
    }
    if (end==BADADDR) {
        return;
    }

    ofs= ea;
    i= 0;

    //Message("making table %08lx-%08lx %s\n", ea, end, pattern);
    while (ofs<end) {
        c= substr(pattern,i,i+1);

        nlen= GetNrOfDigits(pattern, i+1);
        if (nlen) {
            alen= atol(substr(pattern, i+1,i+nlen+1));
            i= i+nlen;
        }
        else if (substr(pattern,i+1,i+2)=="*") {
            // -1: make array until next name or xref 
            alen= -1;
            i=i+1;
        }
        else {
            alen= c=="l" ? 2  // default for align = 2 ( dword )
                : c=="a" || c=="A" ? 0 
                : 1;
        }

        if (c=="c" || c=="p") {
            if (Dword(ofs)) {
                OpOff(ofs, 0, 0);
                MakeCode(CodeOffset(ofs));
                if (c=="p") {
                    Wait();
                    MakeFunction(CodeOffset(ofs), BADADDR);
                }
            }
            else {
                MakeDword(ofs);
            }
        }
        else if (c=="d") { MakeDword(ofs); OpNumber(ofs, 0); }
        else if (c=="w") { MakeWord(ofs); OpNumber(ofs, 0); }
        else if (c=="b") { MakeByte(ofs); OpNumber(ofs, 0); }
        else if (c=="f") { MakeFloat(ofs); OpNumber(ofs, 0); }
        else if (c=="u") { MakeDouble(ofs); OpNumber(ofs, 0); }
        else if (c=="i") { MakeUnkn(ofs, alen>1?alen:4); MakeCode(ofs); }
        else if (c=="o") {
            if (Dword(ofs) && SegStart(Dword(ofs))!=BADADDR) {
                OpOff(ofs, 0, 0);
            }
            else {
                MakeDword(ofs);
            }
            // ??? somehow sometimes ida forgets to create a xref
            if (Dfirst(ofs)!=Dword(ofs))
                add_dref(ofs, Dword(ofs), dr_O);
        }
        else if (c=="s" || c=="S") {
            if (Dword(ofs)) {
                SetLongPrm(INF_STRTYPE, ((Word(Dword(ofs))>=0) && (Word(Dword(ofs))<0x100) && (c=="S"))?ASCSTR_UNICODE:ASCSTR_TERMCHR);
                OpOff(ofs, 0, 0); MakeUnkn(Dword(ofs),1); MakeStr(Dword(ofs), -1);
            }
            else {
                MakeDword(ofs);
            }
        }
        else if (c=="a" || c=="A") {
            // if at ofs there are at 2 unicode chars in the ascii set then str is unicode
            SetLongPrm(INF_STRTYPE, ((Word(ofs)>=0) && (Word(ofs)<0x100 && Word(ofs+2)>0 && Word(ofs+2)<0x100) && (c=="A"))?ASCSTR_UNICODE:ASCSTR_TERMCHR);

            if (alen>=1) {
                MakeUnknownX(ofs, ofs+alen);
                MakeStr(ofs, ofs+alen);
            }
            else if (alen==0) {
                // no length specified: look for terminating NUL
                MakeStr(ofs, -1);
                alen= ItemSize(ofs);
                if (alen==1 && Byte(ofs)==0) {
                    // empty string
                    MakeByte(ofs);
                }
            }
            else {
                // ... todo, think of action for 'a*'
            }
        }
        else if (c=="l") {
            //Message("Makeing %d alignment %08lx\n", alen, ofs);
            if (ofs&((1<<alen)-1)) {
                if (!CheckEmpty(ofs,ofs+(1<<alen)-(ofs&((1<<alen)-1))))
                    return;
                MakeAlign(ofs,(1<<alen)-(ofs&((1<<alen)-1)),alen);
            }
        }
        else if (c=="g") {
            MakeGuid(ofs);
        }
        else {
            Message("invalid format spec '%s' in pattern %s\n", c, pattern);
            return;
        }
        if (c!="l" && c!="a" && c!="A") {
            if (alen==-1) {
                ofs2= findnext_ref_or_name(ofs);
                if (ofs2==BADADDR)
                    ofs2= end;
                if (ofs2!=BADADDR)
                    alen= (ofs2-ofs)/ItemSize(ofs);
            }
            if (alen>1)
                MakeArray(ofs, alen);
        }
        //Message("%08lx:c=%s alen=%d isize=%d\n", ofs, c, alen, ItemSize(ofs));
        if (ItemSize(ofs)==0)
            break;
        if (c!="l" || isAlign(GetFlags(ofs)))
            ofs= ofs+ItemSize(ofs);

        i= i+1; 
        if (i==strlen(pattern)) { i= 0; }
    }
}
static findnext_ref_or_name(ea)
{
    auto end; end= NextHead(ea, SegEnd(ea));
    if (end==BADADDR)
        return BADADDR;
    ea=NextAddr(ea);
    while (ea<end && (GetFlags(ea)&FF_ANYNAME)==0) {
        ea=NextAddr(ea);
    }
    return (ea==end) ? BADADDR : ea;
}
static MakeUnknownX(ea, end)
{
    while(ea<end)
    {
        MakeUnkn(ea,1);
        ea = ea+1;
    }
}


static GetNrOfDigits(str, i)
{
    auto l, n;
    l= strlen(str);
    n= 0;

    while(i<l && isdigit(substr(str, i, i+1))) {
        i= i+1;
        n= n+1;
    }

    return n;
}
static isdigit(c) {
    return c>="0" && c<="9";
}
static isxdigit(c) {
    return isdigit(c) || (c>="a" && c<="f") || (c>="A" && c<="F");
}
static CheckEmpty(ea, end)
{
    auto ofs, b, p;
    for (ofs=ea ; ofs<end ; ofs=ofs+1)
    {
        b= Byte(ofs);
        // not NUL or x86-nop
        if (b!=0 && b!=0x90) {
            // is it a ARM nop?
            p= ofs-ea;
            if ((p==0 && b!=0xc0)
                || (p==1 && b!=0x46)
                || (p==2 && b!=0xc0))
                return 0;
        }
    }
    return 1;
}
static String(ea)
{
    auto s,b;
    auto t;
    if (!hasValue(GetFlags(ea)))
        return "";
    t= GetStringType(ea);
    if (t>=0) {
        return GetString(ea, -1,t);
    }
    else {
        s=""; 
        while(b=Byte(ea)) {
            s=s+form("%c", b);
            ea=ea+1;
        }
        return s; 
    }
}
static WString(ea)
{
    auto s,w;
    s=""; 
    while(w=Word(ea)) {
        s=s+form("%c", w);
        ea=ea+2;
    }
    return s; 
}
static MakeGuid(ea)
{
    auto s,suffix;
    s=form("DGUID {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", 
        Dword(ea), Word(ea+4), Word(ea+6), Byte(ea+8), Byte(ea+9),
        Byte(ea+10), Byte(ea+11), Byte(ea+12), Byte(ea+13), Byte(ea+14), Byte(ea+15));
    MakeUnknownX(ea, ea+16);
    MakeByte(ea); MakeArray(ea, 16);
    SetManualInsn(ea, s);

    if (!hasUserName(GetFlags(ea))) {
        suffix=0;
        while (!MakeNameEx(ea, form("guid_%08lx_%04x_%04x_%02x%02x_%02x%02x%02x%02x%02x%02x%s", 
            Dword(ea), Word(ea+4), Word(ea+6), Byte(ea+8), Byte(ea+9),
            Byte(ea+10), Byte(ea+11), Byte(ea+12), Byte(ea+13), Byte(ea+14), Byte(ea+15), suffix?form("_%d",suffix):""), SN_NOWARN)) 
        {
            suffix=suffix+1;
        }
    }
}
//  auto ea, o, s; 
//  ea=SelStart();
//  while (ea<SelEnd())
//  {
//       s=Dword(ea);
//       o= Dword(ea+4);
//       MakeName(o, form("handle_cmd_%s_%08lx", String(s), o));
//       o= Dword(ea+8);
//       MakeName(o, form("usage_cmd_%s_%08lx", String(s), o));
//       ea= ea+12;
//  }
//  
static Continue()
{
    auto x;
    x= ScreenEA(); 
    AddCodeXref( x, x+4, fl_F);
}
static Table(fmt)
{
    auto ea, end;
    ea= SelStart(); end= SelEnd();
    if (ea==BADADDR) {
        ea= ScreenEA();
        end= NextHead(ea, BADADDR);

        // todo: find something better for this.
        //while(DfirstB(end)==BADADDR)
        //    end=end+4;
    }
    MakeUnknownX(ea, end);
    MakeTable(ea, end, fmt);
}

static summarize_unk()
{
    auto ea, end, start;
    ea= SelStart(); end= SelEnd();

    while (ea<end && isUnknown(GetFlags(ea)) && DfirstB(ea)==BADADDR)
        ea++;
    while (ea<end) {
        start=ea;
        ea=ea+ItemSize(ea);
        while (ea<end && isUnknown(GetFlags(ea)) && !hasName(GetFlags(ea)) && DfirstB(ea)==BADADDR)
            ea=ea+ItemSize(ea);

        if ( !(isUnknown(GetFlags(start)) && !hasName(GetFlags(ea))) ) {
            MakeArray(start, (ea-start)/ItemSize(start));
        }
        else if (ea-start==4 && (start&3)==0) {
            MakeDword(start);
        }
        else if (ea-start==2 && (start&1)==0) {
            MakeWord(start);
        }
        else {
            MakeByte(start);
            MakeArray(start,ea-start);
        }
    }
}
static dword_to_findstr(dw)
{
    return form("%02x %02x %02x %02x", dw&0xff, (dw>>8)&0xff, (dw>>16)&0xff, (dw>>24)&0xff);
}
// changes exception handler data from instruction to dwords.
static fix_exccalls(dw)
{
    auto ea,str; 
    str= dword_to_findstr(dw);
    ea= FindBinary(0, SEARCH_DOWN, str);
    while (ea!=BADADDR) {
        MakeUnkn(ea, 1);
        MakeDword(ea);
        OpNumber(ea, 0);
        MakeArray(ea,2);
        ea= FindBinary(ea+8, SEARCH_DOWN, str);
    }
}

// these functions allow you to peek at the internals of IDA.
static lpeek(ea)
{
    return _peek(ea) | (_peek(ea+1)<<8) | (_peek(ea+2)<<16) | (_peek(ea+3)<<24);
}
static peekstring(ea)
{
    auto s,b;
    s=""; 
    while(b=_peek(ea)) {
        s=s+form("%c", b);
        ea=ea+1;
    }
    return s; 
}

static memset(ea, v, len)
{
    auto vvvv;
    vvvv= (v)|(v<<8)|(v<<16)|(v<<24);
    while (len && (ea&3)) {
        PatchByte(ea++, v);
        --len;
    }
    while (len>=4) {
        PatchDword(ea, vvvv);
        ea=ea+4; len=len-4;
    }
    while (len--) {
        PatchByte(ea++, v);
    }
}

static memcpy(dst, src, len)
{
    if ((dst&3)==(src&3)) {
        while (len && (dst&3)) {
            PatchByte(dst++, Byte(src++));
            --len;
        }
        while (len>=4) {
            PatchDword(dst, Dword(src));
            dst=dst+4; src=src+4; len=len-4;
        }
        while (len--) {
            PatchByte(dst++, Byte(src++));
        }
    }
    else if ((dst&1)==(src&1)) {
        while (len && (dst&1)) {
            PatchByte(dst++, Byte(src++));
            --len;
        }
        while (len>=2) {
            PatchWord(dst, Word(src));
            dst=dst+2; src=src+2; len=len-2;
        }
        while (len--) {
            PatchByte(dst++, Byte(src++));
        }
    } else {
        while (len--) {
            PatchByte(dst++, Byte(src++));
        }
    }
}
static memcmp(eal, ear, len)
{
    while (len && Byte(eal)==Byte(ear)) {
        --len; ++eal; ++ear;
    }
    if (len==0) 
        return 0;
    else if (Byte(eal)<Byte(ear)) 
        return -1;
    else if (Byte(eal)>Byte(ear)) 
        return 1;
    else 
        return 0;
}

// creates arrays from 0, 0x4033, 0x444101, ... sequences.
static fix4033()
{
    auto ea;

    ea=0;
    while (1)
    {
      ea= FindBinary(ea, 0x23, 
                "00 00 00 00 33 40 00 00 01 41 44 00") ;
      if (ea==BADADDR) break;
      Message("%08lx 4033 sequence\n", ea);
      MakeUnknownX(ea, ea+36*4);
      MakeDword(ea);
      MakeArray(ea, 36);
      ExtLinA(ea, 0, ""); ExtLinA(ea, 1, "");
      ExtLinB(ea, 0, ""); ExtLinB(ea, 1, "");
    }

    ea=0;
    while (1)
    {
      ea= FindBinary(ea, 0x23, 
                "85E0B100 11D104FA A000DAB7 D64803C9") ;
      if (ea==BADADDR) break;
      Message("%08lx 85e0b100 sequence\n", ea);
      MakeUnknownX(ea, ea+16);
      MakeDword(ea);
      MakeArray(ea, 4);
      ExtLinA(ea, 0, ""); ExtLinA(ea, 1, "");
      ExtLinB(ea, 0, ""); ExtLinB(ea, 1, "");
    }

}
static hexdump(ea, n)
{
    auto s, i;

    s= "";
    for (i=0 ; i<n ; i++)
    {
        if (i) {
            s=s+" ";
        }
        s=s+form("%02x", Byte(ea+i));
    }
    return s;
}

/*
 *  todo: add this: changes undeffed area between names to dword lists
auto ea,ea0;
ea0=SelStart();
for (ea=ea0+1 ; ea<SelEnd() ; ea=ea+1) {
    if (hasName(GetFlags(ea))) {
        if ((ea-ea0)&3) {
           break;
        }
        MakeDword(ea0);
        MakeArray(ea0, (ea-ea0)/4);
        ea0=ea;
    }
}

todo: add format option to change selection to function

todo: add function to create struct based on pattern


auto ea;
for (ea=SelStart() ; ea<SelEnd() ; ea=ea+4) {
    MakeDword(ea);
    if (hasName(GetFlags(Dword(ea)))) {
        OpOff(ea,0,0);
    }
}

// ... fix incorrect 'noreturn' funcs
auto ea,fea, f0;
ea=PrevHead(here, here-0x100);
fea=Rfirst(ea);
Message("%08lx : %08lx\n", ea, fea);
SetFunctionFlags(fea, GetFunctionFlags(fea)&~FUNC_NORET);
AnalyzeArea(ea, ea+ItemSize(ea));
f0=GetFunctionAttr(ea, FUNCATTR_START);
DelFunction(f0);
Wait();
MakeFunction(f0,BADADDR);

*/

// remove unwanted references to 'ea'
static removerefs(ea)
{
    auto dr,ddr;
    for (dr=DfirstB(ea) ; dr!=BADADDR ; dr=DnextB(ea, dr)) {
        if (isCode(GetFlags(dr))) {
            OpNumber(dr,1);
        }
        else {
           for (ddr=DfirstB(dr) ; ddr!=BADADDR ; ddr=DnextB(dr,ddr)) {
               if (GetMnem(ddr)=="LDR") {
                   OpNumber(ddr,1);
               }
           }
       }
    }
}

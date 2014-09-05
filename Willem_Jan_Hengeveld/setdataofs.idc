// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>
// note: since ida5.20 optypes.idc is included in idc.idc
//#include <optypes.idc>

// this script contains 3 useful functions:
//
// setregofs   - traces register values, and sets the offset base
// setthis     - assumes functions are named 'OBJNAME_funcname', and a struct exists named 'struc_OBJNAME"
//               then traces 'R0' - the 'this' ptr, and sets struct references, and renames
//               functions called with 'this' as first parameter.
// setregstruc - like setthis, but for a user specified register, and struct.
//
// note that all these functions just do a linear scan of the current function, until a fixed
// value for the register is found. it is easily confused by branches.
// most of the time this is sufficient.

// todo: add x86 support
// todo: use SetType to convey the parameter types.
// todo:  after   [Rx,#xxx]!   or  [Rx],#xxx   Rx has changed value!!
//
//
//

static isTestInsn(ea)
{
    auto s;
    s= GetMnem(ea);
    return s=="CMP" || s=="TST" || s=="TEQ" || s=="CMN";
}
static isLoadInsn(ea)
{
    auto s;
    s= GetMnem(ea);
    if (GetOpType(ea,0)!=o_reg) {
        return 0;
    }
    if ((s=="MOV" || s=="MOVL" || s=="ADR") && GetOpType(ea,1)==o_imm) {
        return 1;
    }
    if (s=="LDR" && GetOpType(ea,1)==o_mem) {
        return 1;
    }
    return 0;
}

// 'setdataofs' is an old functions i used before i wrote 'setregofs'.

// idc script to easily fix structure offsets in cases like:
//
//  LDR R4, =dataseg.field_124
//  LDR R3, =dataseg.field_100
//  ...
//  MOV R0, [R4,#-0x10]
//  ...
//  MOV R1, [R3,#0x14]
//
// how to use:
//   - create a struct from the whole data segment, name the struct 'struc_dataseg'
//   and name the start of the data seg 'dataseg'.
//   
//  the data segment i mean, is the one that usually starts after the import data,
//  and ends with undefined bytes ( '?' )
//
static setdataofs(lineea)
{
    auto ea, minea, ofsreg, regval, id, dataseg, ofsopnd, substract;
    substract=0;
    if (GetOpType(lineea,1)==o_displ) {
        ofsreg= regfromoperand(GetOpnd(lineea, 1));
        ofsopnd= 1;
    }
    else if (GetOpType(lineea,1)==o_reg && GetOpType(lineea,2)==o_imm && (GetMnem(lineea)=="ADD" || GetMnem(lineea)=="SUB")) {
        ofsreg= GetOpnd(lineea,1);
        ofsopnd= 2;
        if (GetMnem(lineea)=="SUB") {
            substract=1;
        }
    }
    minea=GetFunctionAttr(lineea, FUNCATTR_START);
    if (minea==BADADDR) {
        Message("%08lx not in a function\n", lineea);
        return;
    }
    regval= 0;
    Message("searching %s in %08lx-%08lx\n", ofsreg, minea, lineea);
    for (ea=PrevHead(lineea, minea) ; ea!=BADADDR && ea>=minea ; ea= PrevHead(ea, minea))
    {
        if (isLoadInsn(ea) && GetOpnd(ea, 0)==ofsreg) {
            if (GetMnem(ea)=="LDR") {
                regval= Dword(GetOperandValue(ea, 1));
            }
            else {
                regval= GetOperandValue(ea, 1);
            }
            Message("%08lx found regval %08lx\n", ea, regval);
            break;
        }
    }

    // !!! these 2 should be replaced by the datasegment name, and structure type
    dataseg= LocByName("dataseg");
    id= GetStrucIdByName("struc_dataseg");
    if (regval && regval>=dataseg && regval-dataseg<=GetStrucSize(id)) {
        if (GetOperandValue(lineea, ofsopnd)<0)
            OpSign(lineea, ofsopnd);
        OpStroffEx(lineea, ofsopnd, id, regval-dataseg-2*substract*GetOperandValue(lineea, ofsopnd));
    }
    else {
        Message("out of range: regval=%08lx dataseg=%08lx ofs=%08lx size=%04x id=%08lx\n", regval, dataseg, regval-dataseg, GetStrucSize(id), id);
    }
}

static setregofs(lineea)
{
    auto ea, minea, ofsreg, regval, ofsopnd, substract;
    substract=0;
    if (GetOpType(lineea,1)==o_displ) {
        ofsreg= regfromoperand(GetOpnd(lineea, 1));
        ofsopnd= 1;
    }
    else if (GetOpType(lineea,1)==o_reg && GetOpType(lineea,2)==o_imm && (GetMnem(lineea)=="ADD" || GetMnem(lineea)=="SUB")) {
    // handle arm32  ADD Rx,Ry,#imm
        ofsreg= GetOpnd(lineea,1);
        ofsopnd= 2;
        if (GetMnem(lineea)=="SUB") {
            substract=1;
        }
    }
    else if (GetOpType(lineea,0)==o_reg && GetOpType(lineea,1)==o_imm && (GetMnem(lineea)=="ADD" || GetMnem(lineea)=="SUB")) {
    // handle thumb  ADD Rx,#imm
        ofsreg= GetOpnd(lineea,0);
        ofsopnd= 1;
        if (GetMnem(lineea)=="SUB") {
            substract=1;
        }
    }
    minea=GetFunctionAttr(lineea, FUNCATTR_START);
    if (minea==BADADDR) {
//        Message("%08lx not in a function\n", lineea);
        return;
    }
    regval= 0;
    for (ea=PrevHead(lineea, minea) ; ea!=BADADDR && ea>=minea ; ea= PrevHead(ea, minea))
    {
        if (isLoadInsn(ea) && GetOpnd(ea, 0)==ofsreg) {
            if (GetMnem(ea)=="LDR") {
                regval= Dword(GetOperandValue(ea, 1));
            }
            else {
                regval= GetOperandValue(ea, 1);
            }
            Message("%08lx  found value for %s  at %08lx : %08lx\n", lineea, ofsreg, ea, regval);
            break;
        }
        else if (GetMnem(ea)!="STM" && GetMnem(ea)!="STR" && !isTestInsn(ea) && GetOpnd(ea, 0)==ofsreg) {
//            Message("%08lx  %s  is modified with %s on %08lx\n", lineea, ofsreg, GetMnem(ea), ea);
            return;
        }
        else if (GetMnem(ea)=="BL" && ofsreg>="R0" && ofsreg<="R3" && strlen(ofsreg)==2) {
//            Message("%08lx  %s  is modified with %s on %08lx\n", lineea, ofsreg, GetMnem(ea), ea);
            return;

        }
    }
    if (regval==0 || regval==0xFFFFFFFF)
        return;

//    if (regval && (SegName(regval) == ".data" || SegName(regval) == ".text")) {
        if (GetOperandValue(lineea, ofsopnd)<0)
            OpSign(lineea, ofsopnd);
        del_dref(lineea, Dfirst(lineea));
        OpOffEx(lineea,ofsopnd, REFINFO_NOBASE|REF_OFF32,-1,regval-2*substract*GetOperandValue(lineea, ofsopnd), 0);
        Wait();
        del_dref(lineea, Dfirst(lineea));
        add_dref(lineea, regval+(1-2*substract)*GetOperandValue(lineea, ofsopnd), dr_O);
//    }
//  else {
//      Message("regval in %s segment  - need .data or .text\n", SegName(regval));
//  }
}
static regfromoperand(opnd)
{
    auto rlen;
    if (substr(opnd,0,1)!="[")  {
        Message("expected opnd %s to contain [ - in '%s'\n", substr(opnd,0,1), opnd);
        return "";
}
    rlen= 2;
    if (0x30<=ord(substr(opnd,3,4)) && ord(substr(opnd,3,4))<=0x39)
        rlen++;
    if (substr(opnd,1+rlen,3+rlen)!=",#" && substr(opnd,1+rlen,2+rlen)!="]") {
        Message("expected opnd %s to contain ,# - in '%s'\n", substr(opnd,1+rlen,3+rlen), opnd);
        return "";
}
    return substr(opnd,1,1+rlen);
}

static objname_for_func(ea)
{
    auto n;       // function name
    auto ix__;    // string index of _
    auto sname;   // name of obj struct
    n= GetFunctionName(ea);
    ix__= strstr(n, "_");
    if (ix__==-1) {
        Message("function %s is not formatted as objname_methodname\n", n);
        return;
    }
    return substr(n, 0, ix__);
}
static setthis(funcea)
{
    auto fstart, fend;
    auto oname;

    fstart=GetFunctionAttr(funcea, FUNCATTR_START);
    fend= GetFunctionAttr(funcea, FUNCATTR_END);
    if (fstart==0 || fend==0 || fstart==-1 || fend==-1) {
        Message("error getting func start/end\n");
        return;
    }

    oname= objname_for_func(funcea);
    if (oname!="")
        setregstruct(fstart, fend, "R0", "struc_"+oname);
}
static FF_to_size(ff)
{
    return (ff==FF_DWRD)? 4 : (ff==FF_WORD) ? 2 : 1;
}
static arm32_ldrstr_type(opc)
{
//   instruction bits:
// cccc01IPU0WSnnnnddddaaaaaaaaaaaa  D
// cccc01IPU1WSnnnnddddaaaaaaaaaaaa  B
// cccc000PU1WSnnnnddddaaaaaaaaaaaa  H
    if ((opc&0x04400000)==0x04000000) return FF_DWRD;
    if ((opc&0x04400000)==0x04400000) return FF_BYTE;
    if ((opc&0x04400000)==0x00400000) return FF_WORD;
    return FF_BYTE;
}
static setregstruc(reg, strucname)
{
    auto start, end;
    auto ea; ea=ScreenEA();
    if (SelStart()!=BADADDR) {
        setregstruct(SelStart(), SelEnd(), reg, strucname);
    }
    else {
        start=GetFunctionAttr(ea, FUNCATTR_START);
        end= GetFunctionAttr(ea, FUNCATTR_END);

        setregstruct(start, end, reg, strucname);
    }
}
// before calling this function you should manually create the structs for the object
//  named "struct_<objname>"
// and name the function "<objname>_method"

// todo:
//   standarize embedded object handling
//   -> when a field has type X,
//   and  ADD R0, this, #<objname>_field   was encountered -> R0 has type '<objname>'
// 
//   or when a field points to type X
//   and  LDR R0, [this, #p<objname>_field]  was encountered -> R0 has type '<objname>'
static setregstruct(fstart, fend, thisreg, sname)
{
    auto ea;      // current addr
    auto id;      // id of object struct
    auto ofsopnd; // which operand we currently operate upon.
    auto ofsreg;  // registername of current opnd.
    auto ofsreg2;  // registername of current opnd.
    auto ofsbase;
    auto dstreg;
    auto reftype;
    auto objofs;
    auto oname;
    auto calledfn;
    auto this_in_r0;
    auto err;

    this_in_r0= 1;


    id= GetStrucIdByName(sname);
    if (id==-1) {
        Message("setthis: cannot find obj struct %s\n", sname);
        return;
    }

    for (ea=fstart ; ea!=BADADDR ; ea=NextHead(ea+1, fend))
    {

        ofsopnd= 0;
        ofsreg= "";
        ofsbase= 0;

        if (thisreg=="R0" && GetMnem(ea)=="MOV" && GetOpType(ea,0)==o_reg && GetOpType(ea,1)==o_reg && GetOperandValue(ea,1)==0) {
            thisreg= GetOpnd(ea,0);
            Message("%08lx: this = %s\n", ea, thisreg);
        }
        else if (thisreg!="") {
            reftype= FF_BYTE;
            if (GetMnem(ea)!="STR" && GetOpType(ea,0)==o_reg && GetOperandValue(ea,0)==0) {
                // XXX R0, ...
                this_in_r0= 0;
            }
            if (GetOpType(ea,1)==o_displ) {   // STR or LDR
                // STR  Rx, [ ]   or  LDR  Rx, [ ]
                ofsreg= regfromoperand(GetOpnd(ea, 1));
                ofsopnd= 1;
                reftype= arm32_ldrstr_type(Dword(ea));
            }
            else if (GetOpType(ea,1)==o_reg && GetOpType(ea,2)==o_imm && (GetMnem(ea)=="ADD" || GetMnem(ea)=="SUB")) {
                ofsreg= GetOpnd(ea,1);
                dstreg= GetOpnd(ea,0);
                if (ofsreg==thisreg && dstreg==GetOpnd(ea+4,1) && GetOpType(ea+4,1)==o_reg && GetMnem(ea+4)=="ADD") {
                    // statements look like this:
                    // ea --  ADD Rx, Rthis, #imm1
                    // ea+4   ADD Ry, Rx, #imm2
                    ofsbase= GetOperandValue(ea,2);
                    ea=ea+4;
                    ofsopnd= 2;
                }
                else if (GetOpType(ea+4,1)==o_displ) {   // STR or LDR
                    // ADD Rx, Rthis, #imm1
                    // STR  Ry, [Rx,#imm2]   or  LDR  Ry, [Rx,#imm2]
                    ofsreg2= regfromoperand(GetOpnd(ea+4, 1));
                    if (ofsreg2==dstreg) {
                        ofsbase= GetOperandValue(ea,2);
                        ofsopnd= 1;
                        reftype= arm32_ldrstr_type(Dword(ea+4));
                        ea=ea+4;
                    }
                    else {
                        ofsopnd= 2;
                    }
                }
                else {
                    // just ADD, no combining instruction on next line
                    ofsopnd= 2;
                }
            }
            else if (GetMnem(ea)=="MOV" && GetOpType(ea,0)==o_reg && GetOpType(ea,1)==o_reg && GetOperandValue(ea,0)==0 && GetOpnd(ea,1)==thisreg) {
                // MOV R0, Ry
                this_in_r0= 1;
            }
            else if (GetMnem(ea)=="BL" && this_in_r0) {
                calledfn= Rfirst0(ea);
                oname= objname_for_func(calledfn);
                if (oname && "struc_"+oname!=sname) {
                    Message("%08lx: this=%s,   function for %s\n", ea, sname, oname);
                }
                else if (substr(GetFunctionName(calledfn), 0, 4)!="sub_") {
                    if (substr(GetFunctionName(calledfn),0,strlen(sname)-5)!=sname+"_")
                        Message("%08lx: function %s is probably type %s\n", ea, GetFunctionName(calledfn), sname);
                }
                else {
                    MakeName(calledfn, form("%s_sub_%X", substr(sname, 6, -1), calledfn));
                    Message("%08lx: function %s is now type %s\n", ea, GetFunctionName(calledfn), sname);
                }
            }
            else {
                //Message("%08lx: %s %x %x %x %x\n", ea, GetMnem(ea), GetOpType(ea,0), GetOpType(ea,1), GetOperandValue(ea,1), GetOperandValue(ea,0));
            }
            objofs=  GetOperandValue(ea,ofsopnd)+ofsbase;
            //Message("%08lx: ofsopnd=%d ofsreg=%s  opnd=%x\n", ea, ofsopnd, ofsreg, objofs);

            if (ofsopnd && ofsreg==thisreg) {
                OpStroffEx(ea, ofsopnd, id, ofsbase);
//  if member does not exist, create it.
                err=AddStrucMember(id, form("field_%X", objofs), objofs, reftype, -1, FF_to_size(reftype));
            }
        }
        else if (ea>fstart+0x20) {
            Message("this not found %s\n", thisreg);
            return;
        }
    }
}

/*

// ... extend dataseg with dwords
auto id, ofs;
id=GetStrucIdByName("struc_dataseg");
for (ofs=0 ; ofs<0x2b4 ; ofs=ofs+4)
  AddStrucMember(id, form("field_%X", ofs), ofs, FF_DWRD|FF_DATA,0, 4);

// rename anon to field_xx 
auto id;
auto ofs;
auto n;
id= GetStrucIdByName("struc_dataseg");
for (ofs=0 ; ofs!=BADADDR ; ofs= GetStrucNextOff(id, ofs)) {
  n= GetMemberName(id, ofs);
  if (substr(n, 0, 10)=="anonymous_") {
    SetMemberName(id, ofs, form("field_%X", ofs));
  }
}

OpStroffEx(ScreenEA(), 2, GetStrucIdByName("struc_dataseg"), 0x8DC);

// find dataseg references in whole program
auto ea;
auto first;
auto last;
first= NextFunction(0);
for (ea=first; ea!=BADADDR ; ea=NextFunction(ea))
{
   last= GetFunctionAttr(ea, FUNCATTR_END);
}
for (ea= first ; ea!=BADADDR ; ea= NextHead(ea+1, last)) {
    setdataofs(ea);
}


auto id, ofs, n;
id=GetStrucIdByName("struc_dataseg");
for (ofs=0 ; ofs<GetStrucSize(id) ; ofs=ofs+4) {
  n= GetMemberName(id, ofs);
  if (n=="")
     AddStrucMember(id, form("field_%X", ofs), ofs, FF_DWRD|FF_DATA,0,4);
  else
     SetMemberType(id, ofs, FF_DWRD|FF_DATA,0, 1);

}

auto ea;
for (ea=SelStart() ; ea<SelEnd() ; ea=ea+4)
  MakeName(Dword(ea), form("obj0_fn%02x", ea-SelStart()) );

// more advanced method namer.
auto ea;
auto c;
c=substr(Name(SelStart()), 4,5);
for (ea=SelStart() ; ea<SelEnd() ; ea=ea+4) {
  if (substr( Name(Dword(ea)), 0, 4)=="sub_") {
    MakeName(Dword(ea), form("obj%s_fn%02x", c, ea-SelStart()) );
  }
}


auto ea, obj, regname, nea, id;
obj= LocByName("rapi3_object");
id = GetStrucIdByName("struc_rapi3")
for (ea=DfirstB(obj) ; ea!=BADADDR ; ea=DnextB(obj, ea)) {
    if (GetOpType(ea, 0)==o_reg && GetOpType(ea, 1)==o_mem) {
        regname=GetOpnd(ea, 0);
        for (nea=NextHead(ea, ea+16) ; nea<ea+16 ; nea=NextHead(nea, ea+16)) {
            if (GetOpType(nea, 1)==o_displ && substr(GetOpnd(nea, 1),1,3) == regname) {
                OpStroffEx(nea, 1, id, 0);
            }
        }
    }
}

// replace string in comments
auto comment,i,ea,search,replace, start, end;
start=SelStart(); end=SelEnd();
if (start==BADADDR) start=FirstSeg();

search="io_display2_clock";
replace="io_display_control";
for (ea=start ; ea!=BADADDR ; ea=NextHead(ea,end)) {
    comment=CommentEx(ea,0);
    i=strstr(comment, search);
    if (i>=0)
        MakeComm(ea, substr(comment, 0,i)+replace+substr(comment,i+strlen(search),-1));
}


// create xrefs for first comment symbol
auto comment;
auto i;
auto ea;
auto symbol;
auto sea;
auto i8,i9;
auto opnd;
auto regnr;
auto found,last;
auto start, end;
start=SelStart(); end=SelEnd();
if (start==BADADDR) start=FirstSeg();

for (ea=start ; ea!=BADADDR ; ea=NextHead(ea,end)) {
    comment=CommentEx(ea,0);
    i=strstr(comment, " ");
    symbol=substr(comment, 0, i);
    sea=LocByName(symbol);
    if (sea!=BADADDR) {
        if (isCode(GetFlags(sea))) {
            if (GetMnem(ea)=="jsr")
                AddCodeXref(ea, sea, fl_CN);
            else
                Message("not handling %08lx: %s  ; %s\n", ea, GetMnem(ea), symbol);
        }
        else {
            found=0; last=-1;
            for (i=0 ; i<2 ; i++) {
                opnd=GetOpnd(ea,i);
                i8=strstr(opnd, "(");
                i9=strstr(opnd, ")");
                if (i8>=0 && i9>=0 && i9-i8==2) {
                    regnr=substr(opnd,i9-1,i9);
                    if (regnr>="0" && regnr<="9") {
                        found++;
                        last=i;
                    }
                }
            }
            if (found>0)
                add_dref(ea, sea, found>1?dr_I:last==0?dr_R:dr_W);
            else {
                Message("%08lx:  expected (reg) -> %s\n", ea, symbol);
            }
            if (found>1)
                Message("%08lx (reg)->(reg)\n", ea);
        }
    }
    else if (strlen(symbol)>1) {
        Message("%08lx : %s  not a symbol\n", ea, symbol);
    }
}

*/

/* cpustate is a string:
 *   substr(state, i*8,i*8+8) = Reg[i]
 *   substr(state, 128+cpsrbit, 28+cpsrbit) = (cpsr>>cpsrbit)&1
 *   substr(state, 160+i*8, 160+i*8+8) = stackvar[i]
 *
 * special meaning:
 *   "        " or " "   : undefined
 * todo:
 *   "=Rn     "          : reg argn
 *   "=An     "          : stack arg_n
 *   "=Vn     "          : stack var_n 
 *   "&An     "          : address of stack arg_n 
 *   "&Vn     "          : address of stack var_n
 *    - todo: figure out where args start
 */
static isundefined(x)
{
    return strlen(x)==0 || substr(x,0,1)==" ";
}
static issymbollic(x)
{
    return strlen(x)>0 && substr(x,0,1)=="=";
}
static isnumeric(x)
{
    return !isundefined(x) && !issymbollic(x);
}
static undefined(size)
{
    if (size==1) return "  ";
    if (size==2) return "    ";
    if (size==4) return "        ";
}

static xvalue(x)
{
    if (isundefined(x)) return "        ";
    if (issymbollic(x)) return form("%-8s", x);
    return form("%08lx", x);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//   cpu register functions
////////////////////////////////////////////////////////////////////////////////////////////////////
static getcpureg(cpustate, regnr)
{
    auto s; s= substr(cpustate, regnr*8,regnr*8+8);
    return isundefined(s) ? " " : issymbollic(s) ? s : xtol(s);
}
static hascpureg(cpustate, regnr)
{
    return !isundefined(substr(cpustate, regnr*8,regnr*8+8));
}
static hascpuregvalue(cpustate, regnr)
{
    return isnumeric(substr(cpustate, regnr*8,regnr*8+8));
}

static setcpureg(cpustate, regnr, regval)
{
    //Message("reg%x from %s to %s\n", regnr, xvalue(getcpureg(cpustate, regnr)), xvalue(regval));
    return (regnr?substr(cpustate, 0, regnr*8):"") 
        + (isundefined(regval) ? undefined(4)
                : issymbollic(regval) ? form("%-8s", regval)
                : form("%08lx", regval)
          )
        + substr(cpustate, regnr*8+8, -1);
}
static undefcpureg(cpustate, regnr)
{
    return (regnr?substr(cpustate, 0, regnr*8):"") + undefined(4) + substr(cpustate, regnr*8+8, -1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//   stack value functions
////////////////////////////////////////////////////////////////////////////////////////////////////
static getstackval(cpustate, spofs, size)
{
    auto s;
    while (strlen(cpustate)<160+spofs*2) { cpustate = cpustate+undefined(size); }
    s= substr(cpustate, 160+spofs*2,160+(spofs+size)*2);
    return isundefined(s) ? " " : issymbollic(s) ? s : xtol(s);
}
static hasstackval(cpustate, spofs, size)
{
    return (strlen(cpustate)>160+spofs*2) && !isundefined(substr(cpustate, 160+spofs*2,160+(spofs+size)*2));
}

// note: bytesized symbollic values are truncated.
static setstackval(cpustate, spofs, argval, size)
{
    while (strlen(cpustate)<160+spofs*2) { cpustate = cpustate+undefined(size); }
    return substr(cpustate, 0, 160+spofs*2) 
        + (isundefined(argval) ? undefined(size)
                : issymbollic(argval) ? substr(form("%-8s", argval),8-size*2,8) 
                : substr(form("%08lx", argval),8-size*2,8) 
          )
        + substr(cpustate, 160+(spofs+size)*2, -1);
}
static undefstackval(cpustate, spofs, size)
{
    while (strlen(cpustate)<160+spofs*2) { cpustate = cpustate+undefined(size); }
    return substr(cpustate, 0, 160+spofs*2) + undefined(size) + substr(cpustate, 160+(spofs+size)*2, -1);
}
static clearstackvals(cpustate)
{
    return substr(cpustate, 0, 160);
}
static nrstackvals(cpustate, size)
{
    return (strlen(cpustate)-160)/(size*2);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//   cpu status functions
////////////////////////////////////////////////////////////////////////////////////////////////////
static cpsrbitnr(bitname)
{
    if (bitname=="N") return 31;
    if (bitname=="Z") return 30;
    if (bitname=="C") return 29;
    if (bitname=="V") return 28;
}
static getcpsr(cpustate, bitname)
{
    auto bitnr;
    bitnr= cpsrbitnr(bitname);
    return substr(cpustate, 128+bitnr,128+bitnr+1);
}
static setcpsr(cpustate, bitname, bitval)
{
    auto bitnr;
    bitnr= cpsrbitnr(bitname);
    return substr(cpustate, 0,128+bitnr) + (isundefined(bitval)?" " : bitval?"1":"0") + substr(cpustate, 128+bitnr+1,-1);
}
static undefcpsr(cpustate, bitname)
{
    auto bitnr;
    bitnr= cpsrbitnr(bitname);
    return substr(cpustate, 0,128+bitnr) + " " + substr(cpustate, 128+bitnr+1,-1);
}
static hascpsr(cpustate, bitname)
{
    auto bitnr;
    bitnr= cpsrbitnr(bitname);
    return substr(cpustate, 128+bitnr,128+bitnr+1)!=" ";
}
static initcpustate()
{
    auto i;
    auto cpu;
    cpu="";
    for (i=0 ; i<16+4 ; i++)
        cpu = cpu + "        ";
    cpu=setcpureg(cpu, 0, "=0");
    cpu=setcpureg(cpu, 1, "=1");
    cpu=setcpureg(cpu, 2, "=2");
    cpu=setcpureg(cpu, 3, "=3");
    return cpu;
}
static dumpcpustate(cpustate)
{
    auto i;
    Message("r0-r3: %s %s %s %s\n", xvalue(getcpureg(cpustate, 0)), xvalue(getcpureg(cpustate, 1)), xvalue(getcpureg(cpustate, 2)), xvalue(getcpureg(cpustate, 3)));
    Message("r4-r7: %s %s %s %s\n", xvalue(getcpureg(cpustate, 4)), xvalue(getcpureg(cpustate, 5)), xvalue(getcpureg(cpustate, 6)), xvalue(getcpureg(cpustate, 7)));
    Message("r8-r11 %s %s %s %s\n", xvalue(getcpureg(cpustate, 8)), xvalue(getcpureg(cpustate, 9)), xvalue(getcpureg(cpustate, 10)), xvalue(getcpureg(cpustate, 11)));
    Message("r12,sp,lr,pc: %s %s %s %s\n", xvalue(getcpureg(cpustate, 12)), xvalue(getcpureg(cpustate, 13)), xvalue(getcpureg(cpustate, 14)), xvalue(getcpureg(cpustate, 15)));
    Message("      NZCV\n");
    Message("cpsr: %s\n", substr(cpustate, 128,128+32));
    for (i=0 ; i<nrstackvals(cpustate, 4) ; i++)
        Message("var_%X: %s\n", i*4, xvalue(getstackval(cpustate, i*4, 4)));
}
static applyshifter(val, shiftop, sval)
{
    if (shiftop==0) {   // LSL
        if (sval)
            val= val<<sval;
    }
    else if (shiftop==1) {  // LSR
        val= (val>>sval)&0x7fffffff;
    }
    else if (shiftop==2) {  // ASR
        val= val>>sval;
    }
    else if (shiftop==3) {
        if (sval==0) { // RRX
        }
        else {  // ROR
            val=( (val>>sval)&((1<<(32-sval))-1) ) | (val<<(32-sval)) ;
        }
    }
    return val;
}
static bits(val, start,end)
{
    return (val>>end)&((1<<(start-end+1))-1);
}
static evalinsn(cpustate, ea)
{
    auto mnem;
    auto value, rvalue, lvalue, sval, imm;
    auto rx,ry,rz,rs,v,c,shiftop;
    auto addr, rval, pw,lsh;
    auto store, size, signext;
    mnem= GetMnem(ea);

    //Message("cpu: %s\n", cpustate);
    cpustate= setcpureg(cpustate, 15, ea+8);
    value= " ";

    if (mnem=="MOV" || mnem=="MOVL" || mnem=="ADR" || mnem=="MVN") {
        //Message("... mov\n");
        if (GetOpType(ea,1)==o_imm) {
            // MOV Rx,#imm
            value= GetOperandValue(ea,1);
        }
        else if (GetOpType(ea,1)==o_reg) {
            // MOV Rx,Ry
            ry= GetOperandValue(ea,1);
            if (hascpureg(cpustate, ry))
                value= getcpureg(cpustate, ry);
        }

        if (mnem=="MVN") {
            if (issymbollic(value))
                value=undefined(4);
            else
                value= ~value;
        }
        cpustate= setcpureg(cpustate, GetOperandValue(ea,0), value);
    }
    else if (mnem=="LDR" || mnem=="STR" ) {
        //Message("... ld/st r\n");
        addr= " ";
        if (GetOpType(ea,1)==o_mem) {
            // LDR Rx,[PC,#imm]
            addr= GetOperandValue(ea,1);
        }
        else if (GetOpType(ea,1)==o_displ) {
            // LDR Rx,[Ry,#imm]
            ry= bits(Dword(ea), 19,16);
            imm= bits(Dword(ea), 11,0);
            if (!bits(Dword(ea), 23,23))
                imm = -imm;
            if (hascpuregvalue(cpustate, ry)) {
                rval= getcpureg(cpustate, ry);
                addr= rval+imm;
            }
        }
        else if (GetOpType(ea,1)==o_phrase) {
            // LDR Rx,[Ry,Rz]
            ry= bits(Dword(ea), 19,16);
            sval=bits(Dword(ea),11,7);
            shiftop=bits(Dword(ea),6,5);
            rz= bits(Dword(ea),3,0);
            if (hascpuregvalue(cpustate, rz)) {
                imm= getcpureg(cpustate, rz);
                // todo: extract carry
                imm= applyshifter(imm, shiftop, sval);
                if (!bits(Dword(ea),23,23))
                    imm = -imm;

                if (hascpuregvalue(cpustate, ry)) {
                    addr= getcpureg(cpustate, ry)+imm;
                }
            }
        }
        pw= (bits(Dword(ea),24,24)<<1)|bits(Dword(ea),21,21);
/*
 *
cond 0 1 0 P U B W L Rn   Rd   offset_12     
cond 0 1 1 P U B W L Rn   Rd   SBZ               Rm 
cond 0 1 1 P U B W L Rn   Rd   shift_imm shift 0 Rm
                               
cond 0 1 0 1 U B 0 L Rn   Rd   offset_12              [<Rn>, #+/-<offset_12>] 
cond 0 1 0 1 U B 1 L Rn   Rd   offset_12              [<Rn>, #+/-<offset_12>]!
cond 0 1 0 0 U B 0 L Rn   Rd   offset_12              [<Rn>], #+/-<offset_12>
                               
cond 0 1 1 1 U B 0 L Rn   Rd   SBZ               Rm   [<Rn>, +/-<Rm>]
cond 0 1 1 1 U B 1 L Rn   Rd   SBZ               Rm   [<Rn>, +/-<Rm>]!
cond 0 1 1 0 U B 0 L Rn   Rd   SBZ               Rm   [<Rn>], +/-<Rm>
                               
cond 0 1 1 1 U B 0 L Rn   Rd   shift_imm shift 0 Rm   [<Rn>, +/-<Rm>, LSL #<shift_imm>]
cond 0 1 1 1 U B 1 L Rn   Rd   shift_imm shift 0 Rm   [<Rn>, +/-<Rm>, LSL #<shift_imm>]!
cond 0 1 1 0 U B 0 L Rn   Rd   shift_imm shift 0 Rm   [<Rn>], +/-<Rm>, LSL #<shift_imm>


 
fedc b a 9 8 7 6 5 4 3210 fedc ba987     65    4 3210
cond 0 1 1 P U B W L Rn   Rd   shift_imm shift 0 Rm      LD|ST R{B}  Rd, Rn+-shifter
cond 0 1 0 P U B W L Rn   Rd   offset_12                 LD|ST R{B}  Rd, Rn+-#imm

B=0 : word
B=1 : byte
L=0 : store
L=1 : load
U=0 : Rn-shifter
U=1 : Rn+shifter

cccc 011P UBWL nnnn dddd iiii iss0 mmmm
cccc 010P UBWL nnnn dddd oooo oooo oooo

# gen all variants
my ($Rn,$Rd,$Rm)=(1,2,3);
for my $U (0,1) { for my $B (0,1) { for my $L (0,1) {
my ($P,$W)=(1,0);
my ($imm,$sh)=(2,0);
  printf("PatchDword(here+0x%x, 0x%x);\n", 4*$i++, 0xe6000000+($P<<24)+($U<<23)+($B<<22)+($W<<21)+($L<<20)+($Rn<<16)+($Rd<<12)+($S<<6)+$Rm+($imm<<7)+($sh<<5));
}}}
for my $P (0,1) { for my $W (0,1) {
my ($U,$B,$L)=(0,1,0);
my ($imm,$sh)=(2,0);
  printf("PatchDword(here+0x%x, 0x%x);\n", 4*$i++, 0xe6000000+($P<<24)+($U<<23)+($B<<22)+($W<<21)+($L<<20)+($Rn<<16)+($Rd<<12)+($S<<6)+$Rm+($imm<<7)+($sh<<5));
}}
for my $sh (0..3) {
for my $imm (0,1,2,5,16,17,30,31) {
my ($U,$B,$L)=(0,1,0);
my ($P,$W)=(1,0);
  printf("PatchDword(here+0x%x, 0x%x);\n", 4*$i++, 0xe6000000+($P<<24)+($U<<23)+($B<<22)+($W<<21)+($L<<20)+($Rn<<16)+($Rd<<12)+($S<<6)+$Rm+($imm<<7)+($sh<<5));
}
}


cond 0 0 0 1 U 1 0 L Rn   Rd   immedH 1 S H 1 immedL   [<Rn>, #+/-<offset_8>]
cond 0 0 0 1 U 1 1 L Rn   Rd   immedH 1 S H 1 ImmedL   [<Rn>, #+/-<offset_8>]!
cond 0 0 0 0 U 1 0 L Rn   Rd   immedH 1 S H 1 ImmedL   [<Rn>], #+/-<offset_8>

cond 0 0 0 1 U 0 0 L Rn   Rd   SBZ    1 S H 1 Rm       [<Rn>, +/-<Rm>]
cond 0 0 0 1 U 0 1 L Rn   Rd   SBZ    1 S H 1 Rm       [<Rn>, +/-<Rm>]!
cond 0 0 0 0 U 0 0 L Rn   Rd   SBZ    1 S H 1 Rm       [<Rn>], +/-<Rm>

cccc 000P U0WL nnnn dddd 0000 1SH1 mmmm

# gen all variants
my ($Rn,$Rd,$Rm)=(1,2,3);
for my $L (0,1) { for my $S (0,1) { for my $H (0,1) {
my ($P,$W)=(1,0);
  printf("PatchDword(here+0x%x, 0x%x);\n", 4*$i++, 0xe0000090+($P<<24)+($W<<21)+($L<<20)+($Rn<<16)+($Rd<<12)+($S<<6)+($H<<5)+$Rm);
}}}
for my $P (0,1) { for my $W (0,1) {
my ($L,$S,$H)=(0,1,0);
  printf("PatchDword(here+0x%x, 0x%x);\n", 4*$i++, 0xe0000090+($P<<24)+($W<<21)+($L<<20)+($Rn<<16)+($Rd<<12)+($S<<6)+($H<<5)+$Rm);
}}

fedc b a 9 8 7 6 5 4 3210 fedc ba98   7 6 5 4 3210
cond 0 0 0 P U 1 W L Rn   Rd   immedH 1 S H 1 ImmedL     LD|ST R{S}{B|H|D}  Rd, Rn+-#imm
cond 0 0 0 P U 0 W L Rn   Rd   SBZ    1 S H 1 Rm         LD|ST R{S}{B|H|D}  Rd, Rn+-Rm

L S H
0 0 0 ?
0 0 1 Store halfword. 
0 1 0 Load doubleword. 
0 1 1 Store doubleword. 
1 0 0 ?
1 0 1 Load unsigned halfword. 
1 1 0 Load signed byte. 
1 1 1 Load signed halfword. 

P W
0 0  postindexed
0 1  ?
1 0  offset addressing
1 1  preindexed
*/
        if (pw==3) {
            // preindexed
            if (!isundefined(addr))
                cpustate=setcpureg(cpustate, ry, addr);
            Message("preindexed: R%x = %s\n", ry, xvalue(addr));
        }
        if ((Dword(ea)&0x0e000090)==0x90) {
            lsh=(bits(Dword(ea),20,20)<<2)|bits(Dword(ea),6,5);
            if (lsh==1) { store=1; size=2; signext=0; }
            if (lsh==2) { store=0; size=8; signext=0; }
            if (lsh==3) { store=1; size=8; signext=0; }
            if (lsh==5) { store=0; size=2; signext=0; }
            if (lsh==6) { store=0; size=1; signext=1; }
            if (lsh==7) { store=0; size=2; signext=1; }
        }
        else if ((Dword(ea)&0x0c000000)==0x04000000) {
            size= bits(Dword(ea),22,22)? 1 : 4;
            signext=0;
            store= bits(Dword(ea),20,20)? 0 : 1;
        }
        else {
            Message("insn %08lx  1=%08lx  2=%08lx: size=4!!\n", Dword(ea), Dword(ea)&0x0f000090, Dword(ea)&0x0f000010);
            size=4;
            signext=0;
            store=0;

        }

        rx= GetOperandValue(ea,0);
        if (store) {
            value= getcpureg(cpustate, rx);
            if (size==1) value=value&0xff;
            else if (size==2) value=value&0xffff;

            Message("ry=%d   ry==13: %d\n", ry, ry==13);
            if (ry==13) {
                // stack operation
                Message("STstackop: %s%04x: %d : %s\n", (imm<0?"-":" "), (imm<0?-imm:imm), size, xvalue(value));
                cpustate= setstackval(cpustate, imm, value, size);
                if (size==8)
                    cpustate= setstackval(cpustate, imm, getcpureg(cpustate, rx+1), 4);
            }
            else if (!isundefined(addr)) {
                Message("%08lx: %s\t[%s] := [%s]\n", ea, GetDisasm(ea), xvalue(addr), xvalue(value));
                if (size==8) {
                    Message("%08lx: %s\t[%s]+4 := [%s]\n", ea, GetDisasm(ea), xvalue(addr), xvalue(getcpureg(cpustate, rx+1)));
                }
            }
            else {
                Message("not handling store %08lx: %s, [addr=%s]\n", ea, GetDisasm(ea), xvalue(addr));
                Message("rx=%d ry=%d  imm=%s%04x\n", rx, ry, imm<0?"-":" ", imm<0?-imm:imm);
            }
        }
        else {
            if (hasValue(GetFlags(addr))) {
                value= size==1?Byte(addr)
                    : size==2?Word(addr)
                    : Dword(addr);
            }
            else if (ry==13) {
                //Message("LDstackop: %s%04x: %d : %s\n", imm<0?"-":" ", imm<0?-imm:imm, size, xvalue(value));
                value= getstackval(cpustate, imm, size);
            }
            if (!isundefined(value)) {
                if (signext && isnumeric(value)) {
                    if (size==1 && (value&0x80)) { value=value|0xffffff00; }
                    if (size==2 && (value&0x8000)) { value=value|0xffff0000; }
                }
                cpustate= setcpureg(cpustate, rx, value);
                if (size==8) {
                    cpustate= setcpureg(cpustate, rx+1, Dword(addr+4));
                }
            }
            else {
                Message("not handling load  %08lx: %s, [addr=%s]\n", ea, GetDisasm(ea), xvalue(addr));
                Message("rx=%d ry=%d  imm=%s%04x\n", rx, ry, imm<0?"-":" ", imm<0?-imm:imm);
            }
        }
        if (pw==0) {
            // postindexed
            cpustate=setcpureg(cpustate, ry, addr);
        }

    }
    else if (mnem=="ADD" || mnem=="ADC" || mnem=="SUB" || mnem=="SBC" || mnem=="RSB" || mnem=="RSC"
            || mnem=="ORR" || mnem=="EOR" || mnem=="AND" || mnem=="BIC"
            || mnem=="TEQ" || mnem=="CMP" || mnem=="CMN" || mnem=="TST") {
        //Message("... data op\n");
        rvalue= " ";
        lvalue= " ";
        c= getcpsr(cpustate, "C");
        v= "0";
        ry= bits(Dword(ea),19,16);
        if (hascpureg(cpustate, ry)) {
            lvalue= getcpureg(cpustate, ry);
            //Message("lval: %s  r=%x\n", xvalue(lvalue), ry);
        }
        if (GetOpType(ea,2)==o_imm) {
            // ADD Rx,Ry,#imm
            rvalue= GetOperandValue(ea,2);
        }
        else if (GetOpType(ea,2)==o_reg) {
            // ADD Rx,Ry,Rz
            rz= bits(Dword(ea),3,0);
            if (hascpureg(cpustate, rz))
                rvalue = getcpureg(cpustate, rz);
        }
        else if (GetOpType(ea,2)==8) {
            // ADD Rx,Ry,Rz LS..
            rz= bits(Dword(ea),3,0);
/*
00000 000 mmmm    Rm
iiiii 000 mmmm    Rm<<iiiii
ssss0 001 mmmm    Rm<<Rs
iiiii 010 mmmm    Rm>>iiiii
ssss0 011 mmmm    Rm>>Rs
iiiii 100 mmmm    Rm->>iiiii
ssss0 101 mmmm    Rm->>Rs
00000 110 mmmm    C,Rm>>>1
iiiii 110 mmmm    Rm>>>iiiii
ssss0 111 mmmm    Rm>>>Rs
*/
            if (hascpureg(cpustate, rz)) {
                rvalue = getcpureg(cpustate, rz);
                sval= " ";
                if (bits(Dword(ea),4,4)) {
                    rs= bits(Dword(ea),11,8);
                    if (hascpureg(cpustate, rs))
                        sval= getcpureg(cpustate,rs);
                }
                else {
                    sval= bits(Dword(ea),11,7);
                }
                shiftop= bits(Dword(ea),6,5);
                if (!isundefined(sval)) {
                    // todo: calc shifter carry
                    rvalue=applyshifter(rvalue, shiftop, sval);

                }
            }
        }
        if (isnumeric(rvalue) && isnumeric(lvalue)) {
            // todo: C result
            //Message("[%s] %s [%s] c=%s\n", xvalue(lvalue), mnem, xvalue(rvalue), c);
            if (mnem=="ADD" || mnem=="CMN") { value= lvalue+rvalue; v=(lvalue>0==rvalue>0)&&(lvalue>0!=value>0); }
            else if (mnem=="ADC") { value= lvalue+rvalue+c;  v=(lvalue>0==rvalue>0)&&(lvalue>0!=value>0); }
            else if (mnem=="SUB" || mnem=="CMP") { value= lvalue-rvalue;  v=(lvalue>0!=rvalue>0)&&(lvalue>0!=value>0); }
            else if (mnem=="SBC") { value= lvalue-rvalue-!c;  v=(lvalue>0!=rvalue>0)&&(lvalue>0!=value>0); }
            else if (mnem=="RSB") { value= rvalue-lvalue; v=(lvalue>0!=rvalue>0)&&(rvalue>0!=value>0); }
            else if (mnem=="RSC") { value= rvalue-lvalue-!c; v=(lvalue>0!=rvalue>0)&&(rvalue>0!=value>0); }
            else if (mnem=="ORR") value= lvalue|rvalue;
            else if (mnem=="EOR") value= lvalue^rvalue;
            else if (mnem=="AND") value= lvalue&rvalue;
            else if (mnem=="BIC") value= lvalue&~rvalue;
            else if (mnem=="TEQ") value= lvalue^rvalue;
            else if (mnem=="TST") value= lvalue&rvalue;
            if (!isundefined(value)) {
                if (!(mnem=="TEQ" || mnem=="CMP" || mnem=="CMN" || mnem=="TST"))
                    cpustate= setcpureg(cpustate, GetOperandValue(ea,0), value);
                if (bits(Dword(ea),20,20)) {
                    // todo: handle 'S' bit
                    cpustate= setcpsr(cpustate, "Z", value==0);
                    cpustate= setcpsr(cpustate, "N", value&0x80000000);
                    cpustate= setcpsr(cpustate, "C", c);
                    cpustate= setcpsr(cpustate, "V", v);
                }
            }
            else {
                Message("not handling dataop %08lx: %s\n", ea, GetDisasm(ea));
            }
        }
    }
    else if (mnem=="BL") {
        // LR= PC+4
        // R0..R3= "      "

        Message("%08lx: %s ; %s, %s, %s, %s\n", ea, GetDisasm(ea), xvalue(getcpureg(cpustate,0)), xvalue(getcpureg(cpustate,1)), xvalue(getcpureg(cpustate,2)), xvalue(getcpureg(cpustate,3)));

        cpustate=setcpureg(cpustate, 0, "=f");
        cpustate=setcpureg(cpustate, 1, " ");
        cpustate=setcpureg(cpustate, 2, " ");
        cpustate=setcpureg(cpustate, 3, " ");
    }
    else if (mnem=="LDM") {
    }
    else if (mnem=="STM") {
    }
    else {
        Message("not handling %08lx: %s\n", ea, GetDisasm(ea));
    }
    // todo: MLA, MUL, SMLAL, SMULL
    return cpustate;
}
/*
auto ea;
auto cpu;
cpu=initcpustate();

for (ea=SelStart() ; ea!=BADADDR ; ea=NextHead(ea,SelEnd())) {
cpu=evalinsn(cpu,ea);
}
dumpcpustate(cpu);
*/

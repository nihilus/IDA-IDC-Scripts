// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>

// this contains:
// 'showrefs', which dumps all references to/from the current address 
// 'showflags', which dumps the meaning of the flags of the current byte.
// 'showoperands', which dumps information on the operands of the current insn.

static hasrefs(ea) {
    return Rfirst(ea)!=BADADDR 
        || RfirstB(ea)!=BADADDR
        || Dfirst(ea)!=BADADDR 
        || DfirstB(ea)!=BADADDR;
}
static showrefs(ea) {
    auto r;
    r=Rfirst(ea);
    Message("%08lx: Rfirst/Rnext: ", ea);
    while (r!=-1) {
        Message(" %08lx(%s)", r, XrefTypeString(XrefType()));
        r=Rnext(ea,r);
    }
    Message("\n");

    r=RfirstB(ea);
    Message("%08lx: RfirstB/RnextB: ", ea);
    while (r!=-1) {
        Message(" %08lx(%s)", r, XrefTypeString(XrefType()));
        r=RnextB(ea,r);
    }
    Message("\n");

    r=Dfirst(ea);
    Message("%08lx: Dfirst/Dnext: ", ea);
    while (r!=-1) {
        Message(" %08lx(%s)", r, XrefTypeString(XrefType()));
        r=Dnext(ea,r);
    }
    Message("\n");

    r=DfirstB(ea);
    Message("%08lx: DfirstB/DnextB: ", ea);
    while (r!=-1) {
        Message(" %08lx(%s)", r, XrefTypeString(XrefType()));
        r=DnextB(ea,r);
    }
    Message("\n");
}
static XrefTypeString(xt)
{
    if (xt==fl_CF) return "CallFar";
    if (xt==fl_CN) return "CallNear";
    if (xt==fl_JF) return "JumpFar";
    if (xt==fl_JN) return "JumpNear";
    if (xt==fl_F) return "flow";
    if (xt==dr_O) return "Offset";
    if (xt==dr_W) return "Write";
    if (xt==dr_R) return "Read";
    if (xt==dr_T) return "Text";
    if (xt==dr_I) return "Info";
    return form("xref_%d", xt);
}
static showoperands(ea)
{
 auto i;
 for (i=0 ; GetOpType(ea, i) ; i++) {
  Message("operand %d: %s %08lx %s\n", i, OpTypeString(GetOpType(ea, i)), GetOperandValue(ea, i), GetOpnd(ea, i));
 }
}
static OpTypeString(t)
{
 if (t==o_reg) return "register";         // General Register (al,ax,es,ds...)    reg                     
 if (t==o_mem) return "memref";           // Direct Memory Reference  (DATA)      addr
 if (t==o_phrase) return "base+index";    // Memory Ref [Base Reg + Index Reg]    phrase
 if (t==o_displ) return "base+index+disp";// Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
 if (t==o_imm) return "immediate";        // Immediate Value                      value
 if (t==o_far) return "immfar";           // Immediate Far Address  (CODE)        addr
 if (t==o_near) return "immnear";         // Immediate Near Address (CODE)        addr
 if (cpu_isARM()) {
  if (t==8) return "shiftedreg";          // o_shreg
  if (t==o_reglist) return "reglist";
  if (t==o_creglist) return "cpreglist";
  if (t==o_creg) return "cpreg";          // Coprocessor register (for LDC/STC)
  if (t==o_fpreg) return "fpreg";
  if (t==o_fpreglist) return "fpreglist";
  if (t==o_text) return "text";
 }
 if (cpu_isX86()) {
  if (t==o_trreg) return "x86trace";
  if (t==o_dbreg) return "x86debug";
  if (t==o_crreg) return "x86ctl";
  if (t==o_fpreg) return "fpp";
  if (t==o_mmxreg) return "mmx";
  if (t==o_xmmreg) return "xmm";
 }
}
static showflags(ea)
{
 auto f;
 f= GetFlags(ea);
 Message("flags: val=%02x class=%s hasflags{%s%s%s%s%s%s%s%s} arg0=%s arg1=%s data=%s\n", 
   byteValue(f),
   isCode(f)?"code":
   isData(f)?"data":
   isTail(f)?"tail":
       "unknown",
   hasValue(f)?" value":"", 
   (f&FF_COMM)!=0?" comment":"",
   isRef(f)?" refs":"",
   isExtra(f)?" cmts":"",
   hasName(f)?" username":"",
   (f&FF_LABL )!=0?" dummyname":"",
   (f&FF_FLOW )!=0?" flow":"",
   (f&FF_VAR  )!=0?" var":"",

   typestring((f>>20)&0xf),
   typestring((f>>24)&0xf),
   datatypestring((f>>28)&0xf)
   );
}
static typestring(t)
{
 if (t==0) return "void";
 if (t==1) return "hexadecimal";
 if (t==2) return "decimal";
 if (t==3) return "character";
 if (t==4) return "segment";
 if (t==5) return "offset";
 if (t==6) return "binary";
 if (t==7) return "octal";
 if (t==8) return "enum";
 if (t==9) return "forcedopnd";
 if (t==10) return "structoffset";
 if (t==11) return "stackvar";
 return form("UNKNOWN_%x", t);
}
static datatypestring(t)
{
 if (t==0) return "byte";
 if (t==1) return "word";
 if (t==2) return "dword";
 if (t==3) return "qword";
 if (t==4) return "tbyte";
 if (t==5) return "ascii";
 if (t==6) return "struct";
 if (t==7) return "octaword";
 if (t==8) return "float";
 if (t==9) return "double";
 if (t==10) return "packedbcdread";
 if (t==11) return "align";
 return form("UNKNOWN_%x", t);
}


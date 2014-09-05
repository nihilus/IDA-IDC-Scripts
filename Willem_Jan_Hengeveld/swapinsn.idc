// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>

// this script contains 'ExchangeInstructions', which swaps 2 instructions,
// correcting any pc-relative addressing offsets.
//
// this works for ARM and X86 code
//
// todo: copy struct references ... but don't know how to find what struct is referenced.
//

// rotate left.
static rol(val, r)
{
 while (r--) {
  val= ((val<<1)&0xfffffffe)|((val>>31)&1);
 }
 return val;
}

// rotate right
static ror(val, r)
{
 Message("ror(%08lx, %d)\n", val, r);
 while (r--) {
  val= ((val>>1)&0x7fffffff)|(val<<31);
 }
 return val;
}
// convert offset to ror+imm8 value
static packofs(ofs)
{
 auto r;
 auto o; o= ofs;
 r=0;
 if (ofs==0) { return 0; }
 while ((ofs&3)==0) {
  ofs= ror(ofs,2);
  r++;
 }
 if (ofs&~0xff) {
  return -1;
 }
 if (r) { r=16-r; }
 Message("offset %08lx == ror(%02x, 2*%d)\n", o, ofs, r);
 return ofs | (r<<8);
}
// relocate instruction at ea by delta d.
static thumb_relocate(ea, d)
{
 if ((Word(ea)&0xF800)==0x4800) {
     PatchWord(ea, Word(ea)+d/2);
 }
 return 1;
}
static arm_relocate(ea, d)
{
 auto packedoffset, offset;
 if ((Dword(ea)&0x0e000000)==0x0a000000) {
  Message("relocating branch %08lx by %d\n", Dword(ea), d);
  // is branch with 24 bit signed offset
  if ((d&3)!=0) {
   Message("can't move to odd offset\n");
   return 0;
  }
  PatchDword(ea, Dword(ea)+(d>>2));
 }
 else if ((Dword(ea)&0x0f3f0000)==0x051f0000) {
  Message("relocating LDR ?, [PC, #ofs] by %d\n", d);
  // fedc ba9 87654 3210 fedc ba9876543210
  // cccc 010 1UB0L _Rn_ _Rd_ ___offset___
  // ---- !!! !--!! !!!! ---- ------------
  // 0x0  f    3    f    0    0   0   0

  // is PC relative load
  if (Dword(ea)&0x00800000) {
   PatchDword(ea, Dword(ea)+d);
  }
  else {
   PatchDword(ea, Dword(ea)-d);
  }
 }
 else if ( ((Dword(ea)&0x0fef0000)==0x028f0000) || ((Dword(ea)&0x0fef0000)==0x024f0000) ) {
  Message("relocating XXX ?, PC, #ofs by %d\n", d);
  // fedc ba9 8765 4 3210 fedc ba9876543210
  // cccc 001 0100 S _Rn_ _Rd_ _sh_ _offset_
  // ---- !!! !!!! 0 !!!! ---- ---- --------
  // 0x0  f    e     f    0    0    0   0

  // ADD Rx, PC, #imm
  offset= ror(Dword(ea)&0xff, (Dword(ea)&0xf00)>>7);
  if (((Dword(ea)>>21)&0xf)==2) {    // SUB
   Message("instr is SUB ?, PC, #%08lx\n", offset);
   offset = -offset;
  }
  else {
   Message("instr is ADD ?, PC, #%08lx\n", offset);
  }
  offset = offset + d;
  
  packedoffset= packofs(offset<0?-offset:offset);
  if (packedoffset==-1) {
   Message("cannot add delta to %08lx\n", ea);
   return 0;
  }
  Message("changing %08lx to %08lx\n", Dword(ea), (Dword(ea)&~0xfff)|packedoffset);
  PatchDword(ea, (Dword(ea)&0xfe1ff000)|packedoffset|(offset<0?2<<21:4<<21));
 }
 else if ((Dword(ea)&0x000f0000)==0x000f0000) {
  Message("WARNING: cannot swap PC relative instr: %08lx\n", Dword(ea));
  return 0;
 }
 return 1;
}

static relocate(ea, d)
{
 if (cpu_isARM()) {
  if (GetReg(ea, "T"))
   return thumb_relocate(ea, d);
  else
   return arm_relocate(ea, d);
 }
 Message("cpu unsupported\n");
 return 0;
}
static ExchangeInstructions(ea1, ea2)
{
 //auto ea1; // start of first instruction
 //auto ea2; // start of original 2nd instruction
 auto eea; // end of 2nd instruction
 auto l1;  // length of first instruction
 auto l2;  // length of second instruction
 auto i;   // loop counter
 auto s1;   // used to keep copy of first instruction
 auto newea1; // new address of second ( orig first ) instruction

 auto cmt1,cmt2;
 auto flags1,flags2;

 eea= NextNotTail(ea2);

 newea1= ea1+eea-ea2;
 l1= ea2-ea1;
 l2= eea-ea2;

 if (RfirstB0(ea1)!=-1 || RfirstB0(ea2)!=-1) {
  Message("can't change control flow\n");
  // todo: also relocate xrefs to.
  return;
 }
 cmt1= Comment(ea1);
 flags1 = GetFlags(ea1);
 cmt2= Comment(ea2);
 flags2 = GetFlags(ea2);
 Message("1:%08lx: %08lx %s\n", ea1, flags1, cmt1);
 Message("2:%08lx: %08lx %s\n", ea2, flags2, cmt2);

 // make unknown first
 for (i=0 ; i<l1+l2 ; i++) {
  MakeUnkn(ea1+i, 0);
 }

 // relocate
 if (!relocate(ea1, -l2)) { MakeCode(ea1); return; }
 if (!relocate(ea2, l1)) { relocate(ea1, l2); MakeCode(ea1); return; }

 // copy first instruction
 s1="";
 for (i=0 ; i<l1 ; i++) {
  s1 = s1 + form("%02x", Byte(ea1+i));
 }
 // move second to start
 for (i=0 ; i<l2 ; i++) {
  PatchByte(ea1+i, Byte(ea2+i));
 }
 // put first instruction
 for (i=0 ; i<l1 ; i++) {
  PatchByte(newea1+i, xtol(substr(s1, 2*i, 2*i+2)));
 }

 MakeCode(ea1);
 Wait();
 if (isHead(GetFlags(ea1))) {
     //Message("1: update flags for %08lx (cur=%08lx) to %08lx\n", ea1, GetFlags(ea1), flags2);
     MakeComm(ea1, cmt2);
     SetFlags(ea1, flags2);
 }
 else if (cmt2!="") {
     Message("1: lost comment: %s\n", cmt2);
 }
 else {
     Message("1: not updating flags for %08lx  (cur=%08lx)  to %08lx\n", ea1, GetFlags(ea1), flags2);
 }

 if (isHead(GetFlags(ea1+l2))) {
     //Message("2: update flags for %08lx (cur=%08lx) to %08lx\n", ea1+l2, GetFlags(ea1+l2), flags1);
     MakeComm(ea1+l2, cmt1);
     SetFlags(ea1+l2, flags1);
 }
 else if (cmt1!="") {
     Message("2: lost comment: %s\n", cmt1);
 }
 else {
     Message("2: not updating flags for %08lx  (cur=%08lx)  to %08lx\n", ea1+l2, GetFlags(ea1+l2), flags1);
 }
}

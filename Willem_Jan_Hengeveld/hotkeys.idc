// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */

// this scripts loads some convenient hotkeys for ida.
// initialize by running 'addhotkeys();'
//
// Shift-I	_idc0 	repeat last manual idc script
// Shift-H	HK_Help 	show help + info (like xrefs and flags) on current line
// Shift-C	HK_Code 	covert selection to code
// Shift-O	HK_Offset 	convert selection to offsets, also correctly handling Thumb offsets ( which have bit0 set )
// Shift-G	HK_Guid 	convert current data to a GUID
// Shift-L	HK_Align 	
// Shift-A	HK_String_mixed 	detect and convert to string, unicode and ascii strings
// Shift-D	HK_Dwords 	convert to dwords
// Shift-P	HK_ParsePdata 	process the .pdata section, and update function definitions accordingly
// Shift-F	FixFunctions 	change function bounds to include constant pools, this makes it easier to see where data is referenced from
// Shift-J	FixJumpCalls 	
// Shift-R	findstrange 	find incorrect offsets ( like off_20000, when an immediate was intended )
// Shift-U	summarize_unk 	group all unknown data
// Shift-X	HK_ExchangeUp 	rotate selected instruction range up
// Shift-Y	HK_ExchangeDown 	rotate selected instruction range down
// Shift-V	HK_setregofs 	try to find the value of the current REG+ofs expression
// Shift-T	HK_setthis 	assumes the function is named like TYPE_methodname, and a struct 'struc_TYPE' exists. then it traces where R0 ends up, and creates struc_TYPE fields, and new TYPE_methodname functions accordingly
//
//todo: make this a standalone .idc, which is included from ida.idc
//
#include <formatdata.idc>
#include <findstrangerefs.idc>
#include <setdataofs.idc>
#include <swapinsn.idc>
#include <showrefs.idc>


//-----------------------------------------------------------------------
// Get name of the current processor

static get_processor(void) {
  auto i,procname,chr;

  procname = "";
  for ( i=0; i < 8; i++ ) {
    chr = GetCharPrm(INF_PROCNAME+i);
    if ( chr == 0 ) break;
    procname = procname + chr;
  }
  return procname;
}
static cpu_isX86()
{
 return get_processor()=="386";
}
static cpu_isARM()
{
 return get_processor()=="ARM";
}

static HK_NumberedNames()
{
    // todo:
    //   get name of first item,
    //   find hex/dec digits, and continue numbering these
    //   with step 1 or 4.
    //    ... think of a way of encoding the (hex,dec) and (1,4) params naturally
}

static HK_Align() {
    Table("l");
}
static HK_String_mixed() {
    Table("Al");
}
static HK_Dwords() {
    Table("d");
}
static HK_ParsePdata() {
    ParsePdata(-1,-1);
}
static HK_String_ascii() {
    Table("al");
}
static HK_Code() {
    Table("p");
}
static HK_Offset() {
    Table("o");
}
static HK_Guid() {
    Table("g");
}

// .. this function is obsolete, replaced by HK_setregofs
static HK_setdataofs()
{
    auto ea;
    if (SelStart()!=BADADDR) {
       for (ea= SelStart() ; ea!=BADADDR ; ea= NextHead(ea+1, SelEnd())) {
          setdataofs(ea);
       }
    }
    else {
        setdataofs(ScreenEA());
    }
}

static HK_setregofs()
{
    auto ea;
    if (SelStart()!=BADADDR) {
       for (ea= SelStart() ; ea!=BADADDR ; ea= NextHead(ea+1, SelEnd())) {
          setregofs(ea);
       }
    }
    else {
        setregofs(ScreenEA());
    }
}
static HK_setthis()
{
    setthis(ScreenEA());
}

static HK_ExchangeUp()
{
    auto ea;
    if (SelStart()!=BADADDR) {
        ea= PrevNotTail(SelEnd());
        while (ea>SelStart()) {
            ExchangeInstructions(PrevNotTail(ea), ea);
            ea= PrevNotTail(ea);
        }
    }
    else {
        ExchangeInstructions(PrevNotTail(ScreenEA()), ScreenEA());
    }
}
static HK_ExchangeDown()
{
    auto ea;
    if (SelStart()!=BADADDR) {
        ea=SelStart();
        while (ea<PrevNotTail(SelEnd())) {
            ExchangeInstructions(ea, NextNotTail(ea));
            ea= NextNotTail(ea);
        }
    }
    else {
        ExchangeInstructions(ScreenEA(), NextNotTail(ScreenEA()));
    }
}

static HK_Help() {
 auto ea,i; ea= ScreenEA();
 Message("shift+ H=Help  C=Code O=offset L=Align A=unicode+ascii ^A=ascii G=guid I=current idc\n");
 Message("shift+ F=FixFuncs J=FixJumpCalls R=strange U=summarize_unk P=ParsePdata X=xchg V=setregofs\n");

 Message("NextAddr=%08lx PrevAddr=%08lx NextNotTail=%08lx PrevNotTail=%08lx NextHead=%08lx PrevHead=%08lx\n",
   NextAddr(ea), PrevAddr(ea), NextNotTail(ea), PrevNotTail(ea), NextHead(ea, ea+0x100), PrevHead(ea, ea-0x100));
 Message("ItemEnd=%08lx ItemSize=%08lx mnem=%s\n", ItemEnd(ea), ItemSize(ea), GetMnem(ea));
 showoperands(ea);
 for (i=0 ; i<ItemSize(ea) ; i++) {
     showflags(ea+i);
     if (hasrefs(ea+i)) {
         showrefs(ea+i);
     }
 }
}

static addhotkeys() {
    // prior to ida5.6 this was "_idc0"
    AddHotkey("Shift-I", "___idc0");
    AddHotkey("Shift-H", "HK_Help");
    AddHotkey("Shift-C", "HK_Code");
    AddHotkey("Shift-O", "HK_Offset");
    AddHotkey("Shift-G", "HK_Guid");
    AddHotkey("Shift-L", "HK_Align");
    AddHotkey("Shift-A", "HK_String_mixed");
    AddHotkey("Shift-D", "HK_Dwords");
    AddHotkey("Ctrl-Shift-A", "HK_String_ascii");
    AddHotkey("Shift-P", "HK_ParsePdata");
    AddHotkey("Shift-F", "FixFunctions");
    AddHotkey("Shift-J", "FixJumpCalls");
    AddHotkey("Shift-R", "findstrange");
    AddHotkey("Shift-U", "summarize_unk");
    AddHotkey("Shift-X", "HK_ExchangeUp");
    AddHotkey("Shift-Y", "HK_ExchangeDown");
    AddHotkey("Shift-V", "HK_setregofs");
    AddHotkey("Shift-T", "HK_setthis");
//    AddHotKey("Shift-N", "HK_NumberedNames");
}


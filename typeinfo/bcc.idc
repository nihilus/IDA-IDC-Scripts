#include <idc.idc>
//Borland C++/C++ Builder RTTI support for IDA
//Version 1.0 24.02.2003 Igor Skochinsky <skochinsky@mail.ru>

static Enums(void) {
        auto id;                // enum id

	id = AddEnum(-1,"tpMask",0x1100000);
	SetEnumBf(id,1);
	AddConstEx(id,"TM_IS_STRUCT",	0x1,	0x1);
	AddConstEx(id,"TM_IS_CLASS",	0x2,	0x2);
	AddConstEx(id,"TM_IS_PTR",	0x10,	0x10);
	AddConstEx(id,"TM_IS_REF",	0x20,	0x20);
	AddConstEx(id,"TM_IS_VOIDPTR",	0x40,	0x40);
	AddConstEx(id,"TM_LOCALTYPE",	0x80,	0x80);
	AddConstEx(id,"TM_IS_CONST",	0x100,	0x100);
	AddConstEx(id,"TM_IS_VOLATILE",	0x200,	0x200);
	AddConstEx(id,"TM_IS_ARRAY",	0x400,	0x400);
	id = AddEnum(-1,"tpcFlags",0x1100000);
	SetEnumBf(id,1);
	AddConstEx(id,"CF_HAS_CTOR",	0x1,	0x1);
	AddConstEx(id,"CF_HAS_DTOR",	0x2,	0x2);
	AddConstEx(id,"CF_HAS_BASES",	0x4,	0x4);
	AddConstEx(id,"CF_HAS_VBASES",	0x8,	0x8);
	AddConstEx(id,"CF_HAS_VTABPTR",	0x10,	0x10);
	AddConstEx(id,"CF_HAS_VIRTDT",	0x20,	0x20);
	AddConstEx(id,"CF_HAS_RTTI",	0x40,	0x40);
	AddConstEx(id,"CF_DELPHICLASS",	0x80,	0x80);
	AddConstEx(id,"CF_HAS_FARVPTR",	0x1000,	0x1000);
	AddConstEx(id,"CF_HAS_GUID",	0x2000,	0x2000);
	id = AddEnum(-1,"excBlockKind",0x1100000);
	AddConstEx(id,"XB_FINALLY",	0x0,	0xffffffff);
	AddConstEx(id,"XB_EXCEXP",	0x1,	0xffffffff);
	AddConstEx(id,"XB_EXCCNS",	0x2,	0xffffffff);
	AddConstEx(id,"XB_TRYCPP",	0x3,	0xffffffff);
	AddConstEx(id,"XB_CATCH",	0x4,	0xffffffff);
	AddConstEx(id,"XB_DEST",	0x5,	0xffffffff);
	id = AddEnum(-1,"dttFlags",0x1100000);
	SetEnumBf(id,1);
	AddConstEx(id,"DTCVF_PTRVAL",	0x1,	0x1);
	AddConstEx(id,"DTCVF_DELPTR",	0x2,	0x2);
	AddConstEx(id,"DTCVF_STACKVAR",	0x4,	0x4);
	AddConstEx(id,"DTCVF_DELETE",	0x8,	0x8);
	AddConstEx(id,"DTCVF_RETVAL",	0x10,	0x10);
	AddConstEx(id,"DTCVF_RETCTX",	0x20,	0x20);
	AddConstEx(id,"DTCVF_VECCNT",	0x40,	0x40);
	AddConstEx(id,"DTCVF_DTCADJ",	0x100,	0x100);
	AddConstEx(id,"DTCVF_THROWCTX",	0x200,	0x200);
	AddConstEx(id,"DTCVF_THISCTX",	0x400,	0x400);
}

//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;

	id = AddStrucEx(-1,"tpid_head",0);
	id = AddStrucEx(-1,"tpid_Class",0);
	id = AddStrucEx(-1,"tpid_Class_Dtor",0);
	id = AddStrucEx(-1,"tpid_Ptr",0);
	id = AddStrucEx(-1,"tpid_Arr",0);
	id = AddStrucEx(-1,"baseList",0);
	id = AddStrucEx(-1,"dMemList",0);
	id = AddStrucEx(-1,"GUID",0);
	id = AddStrucEx(-1,"BcbTls",0);
	id = AddStrucEx(-1,"REGREC_BC",0);
	id = AddStrucEx(-1,"HD",0);
	id = AddStrucEx(-1,"HTD",0);
	id = AddStrucEx(-1,"DTT",0);
	id = AddStrucEx(-1,"ERRCINFO",0);
	id = AddStrucEx(-1,"exceptDesc",0);
	id = AddStrucEx(-1,"EXCEPTION_POINTERS",0);
	id = AddStrucEx(-1,"EXCEPTION_RECORD",0);
	id = AddStrucEx(-1,"exceptVarRec",0);
	id = AddStrucEx(-1,"xbHeader",0);
	id = AddStrucEx(-1,"xbDest",0);
	id = AddStrucEx(-1,"xcTabHeader",0);

	
	
	id = GetStrucIdByName("tpid_head");
	AddStrucMember(id,"tpSize",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"tpMask",	0x4,	0x10800400,	GetEnum("tpMask"),	2);
	AddStrucMember(id,"tpName",	0x6,	0x10000400,	-1,	2);
	
	id = GetStrucIdByName("tpid_Class");
	AddStrucMember(id,"tpcVptrOffs",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"tpcFlags",	0x4,	0x20800400,	GetEnum("tpcFlags"),	4);
	AddStrucMember(id,"tpcBaseList",	0x8,	0x10000400,	-1,	2);
	AddStrucMember(id,"tpcVbasList",	0xa,	0x10000400,	-1,	2);
	AddStrucMember(id,"tpcDlOpAddr",	0xc,	0x25500400,	0x0,	4);
	AddStrucMember(id,"tpcDlOpMask",	0x10,	0x10000400,	-1,	2);
	AddStrucMember(id,"tpcDaOpMask",	0x12,	0x10000400,	-1,	2);
	AddStrucMember(id,"tpcDaOpAddr",	0x14,	0x25500400,	0x0,	4);
	
	id = GetStrucIdByName("tpid_Class_Dtor");
	AddStrucMember(id,"tpcDtorCount",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"tpcNVdtCount",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"tpcDtorAddr",	0x8,	0x20500400,	0x0,	4);
	AddStrucMember(id,"tpcDtorMask",	0xc,	0x10000400,	-1,	2);
	AddStrucMember(id,"tpcDtMembers",	0xe,	0x10000400,	-1,	2);
	
	id = GetStrucIdByName("tpid_Ptr");
	AddStrucMember(id,"tppBaseType",	0x0,	0x20500400,	0x0,	4);
	
	id = GetStrucIdByName("tpid_Arr");
	AddStrucMember(id,"tpaElemType",	0x0,	0x20500400,	0x0,	4);
	AddStrucMember(id,"tpaElemCount",	0x4,	0x20200400,	-1,	4);
	
	id = GetStrucIdByName("baseList");
	AddStrucMember(id,"blType",	0x0,	0x20500400,	0x0,	4);
	AddStrucMember(id,"blOffs",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"blFlags",	0x8,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("dMemList");
	AddStrucMember(id,"dmType",	0x0,	0x20500400,	0x0,	4);
	AddStrucMember(id,"dmOffs",	0x4,	0x20000400,	-1,	4);
	
	
	id = GetStrucIdByName("GUID");
	AddStrucMember(id,"Data1",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"Data2",	0x4,	0x10000400,	-1,	2);
	AddStrucMember(id,"Data3",	0x6,	0x10000400,	-1,	2);
	AddStrucMember(id,"Data4",	0x8,	0x000400,	-1,	8);
	
	id = GetStrucIdByName("BcbTls");
	AddStrucMember(id,"__CPPexceptionList",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"__exceptFlags",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"__throwFileName",	0x8,	0x20000400,	-1,	4);
	AddStrucMember(id,"__throwLineNumber",	0xc,	0x20000400,	-1,	4);
	AddStrucMember(id,"__throwExceptionName",	0x10,	0x20000400,	-1,	4);
	AddStrucMember(id,"__exceptStaticBuffP",	0x14,	0x20000400,	-1,	4);
	AddStrucMember(id,"__exceptMemAllocVars",	0x18,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("ERRCINFO");
	AddStrucMember(id,"ERRcUnwind",	0x0,	0x10000400,	-1,	2);
	AddStrucMember(id,"ERRcExcCode",	0x2,	0x20000400,	-1,	4);
	AddStrucMember(id,"ERRcExcInfo",	0x6,	0x20500400,	0x0,	4);
	
	id = GetStrucIdByName("REGREC_BC");
	AddStrucMember(id,"ERRcNext",	0x0,	0x20500400,	0x0,	4);
	AddStrucMember(id,"ERRcCatcher",	0x4,	0x20500400,	0x0,	4);
	AddStrucMember(id,"ERRcXtab",	0x8,	0x20500400,	0x0,	4);
	AddStrucMember(id,"ERRcSPsv",	0xc,	0x20000400,	-1,	4);
	AddStrucMember(id,"ERRcCCtx",	0x10,	0x10000400,	-1,	2);
	AddStrucMember(id,"ERRcInfo",	0x12,	0x60000400,	GetStrucIdByName("ERRCINFO"),	10);
	AddStrucMember(id,"ERRcInitDtc",	0x1c,	0x20000400,	-1,	4);
	AddStrucMember(id,"ERRflags",	0x20,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("HD");
	AddStrucMember(id,"HDhndPtr",	0x0,	0x25500400,	0x0,	4);
	AddStrucMember(id,"HDtypeID",	0x4,	0x25500400,	0x0,	4);
	AddStrucMember(id,"HDflags",	0x8,	0x20000400,	-1,	4);
	AddStrucMember(id,"HDcctrAddr",	0xc,	0x25500400,	0x0,	4);
	AddStrucMember(id,"HDcctrMask",	0x10,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("HTD");
	AddStrucMember(id,"HTDargAddr",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"HTDargSize",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"HTDtable",	0x8,	0x60000400,	GetStrucIdByName("HD"),	0);
	
	id = GetStrucIdByName("DTT");
	AddStrucMember(id,"dttType",	0x0,	0x20500400,	0x0,	4);
	AddStrucMember(id,"dttFlags",	0x4,	0x20800400,	GetEnum("dttFlags"),	4);
	AddStrucMember(id,"dttAddress",	0x8,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("exceptDesc");
	AddStrucMember(id,"xdPrevious",	0x0,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdTypeID",	0x4,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdFriendList",	0x8,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdFlags",	0xc,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdSize",	0x10,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdBase",	0x14,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdMask",	0x18,	0x10000400,	-1,	2);
	AddStrucMember(id,"xdCflg",	0x1a,	0x10000400,	-1,	2);
	AddStrucMember(id,"xdFreeFunc",	0x1c,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdCCaddr",	0x20,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdCCmask",	0x24,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdERRaddr",	0x28,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdHtabAdr",	0x2c,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdContext",	0x30,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdThrowLine",	0x34,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdThrowFile",	0x38,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdArgType",	0x3c,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdArgAddr",	0x40,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdArgBuff",	0x44,	0x000400,	-1,	1);
	AddStrucMember(id,"xdArgCopy",	0x45,	0x000400,	-1,	1);
	AddStrucMember(id,"xdOSESP",	0x46,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdOSERR",	0x4a,	0x20000400,	-1,	4);
	AddStrucMember(id,"xdOSContext",	0x4e,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xdValue",	0x52,	0x000400,	-1,	0);
	
	id = GetStrucIdByName("EXCEPTION_POINTERS");
	AddStrucMember(id,"ExceptionRecord",	0x0,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"ContextRecord",	0x4,	0x25500400,	0xffffffff,	4);
	
	id = GetStrucIdByName("EXCEPTION_RECORD");
	AddStrucMember(id,"ExceptionCode",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"ExceptionFlags",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"ExceptionRecord",	0x8,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"ExceptionAddress",	0xc,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"NumberParameters",	0x10,	0x20000400,	-1,	4);
	AddStrucMember(id,"ExceptionInformation",	0x14,	0x20000400,	-1,	60);
	
	id = GetStrucIdByName("exceptVarRec");
	AddStrucMember(id,"xvrCPPexceptionList",	0x0,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xvrExceptFlags",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"xvrThrowFileName",	0x8,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xvrThrowLineNumber",	0xc,	0x20000400,	-1,	4);
	AddStrucMember(id,"xvrThrowExceptionName",	0x10,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xvrExceptStaticBuffP",	0x14,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xvrExceptMemAllocVars",	0x18,	0x25500400,	0xffffffff,	4);
	AddStrucMember(id,"xvrExceptStaticXbuff",	0x1c,	0x000400,	-1,	128);
	
	id = GetStrucIdByName("xbHeader");
	AddStrucMember(id,"outer",	0x0,	0x10000400,	-1,	2);
	AddStrucMember(id,"kind",	0x2,	0x10800400,	GetEnum("excBlockKind"),	2);
	
	id = GetStrucIdByName("xbDest");
	AddStrucMember(id,"dtcMin",	0x0,	0x20200400,	-1,	4);
	AddStrucMember(id,"dttAdr",	0x4,	0x20500400,	0x0,	4);
	
	id = GetStrucIdByName("xcTabHeader");
	AddStrucMember(id,"xtThrowLst",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"xtBPoffs",	0x4,	0x20000400,	-1,	4);
}

static Unknown( ea, length )
{
  auto i;
//  Message("Unknown(%x,%d)\n",ea, length);
  for(i=0; i < length; i++)
     {
       MakeUnkn(ea+i,0);
     }
}

static ForceDword( x ) {  //Make dword, undefine as needed
 if (!MakeDword( x ))
 {
   Unknown(x,4);
   MakeDword(x);
 }
}

static ForceWord( x ) {  //Make word, undefine as needed
 if (!MakeWord( x ))
 {
   Unknown(x,2);
   MakeWord( x );
 }
}

static ForceByte( x ) {  //Make byte, undefine as needed
 if (!MakeByte( x ))
 {
   MakeUnkn(x,0);
   MakeByte( x );
 }
} 

static GuidToString(x)
{
  auto text;

  text=form("; ['{%08X-%04X-%04X",Dword(x),Word(x+4),Word(x+6));
  text=text+form("-%02X%02X%02X%02X%02X%02X%02X%02X}']",
  Byte(x+8),Byte(x+9),Byte(x+10),Byte(x+11),Byte(x+12),Byte(x+13),Byte(x+14),Byte(x+15));
  return text;
}

static GetStr( Address )
{
  auto Result, cByte;
  Result = "";
  for ( cByte = Byte(Address); cByte; )
  {
    Result = Result + cByte;
    Address++;
    cByte = Byte(Address);
  }
  return Result;
}

//  tpMask flags

#define TM_IS_STRUCT    0x0001
#define TM_IS_CLASS     0x0002

#define TM_IS_PTR       0x0010
#define TM_IS_REF       0x0020

#define TM_IS_VOIDPTR   0x0040

#define TM_LOCALTYPE    0x0080

#define TM_IS_CONST     0x0100
#define TM_IS_VOLATILE  0x0200

#define TM_IS_ARRAY     0x0400

#define IS_CLASS(m)     ((m) & TM_IS_CLASS )
#define IS_STRUC(m)     ((m) & TM_IS_STRUCT)

//      Class flags ('tpcFlags') follow:

#define CF_HAS_CTOR     0x00000001
#define CF_HAS_DTOR     0x00000002

#define CF_HAS_BASES    0x00000004
#define CF_HAS_VBASES   0x00000008

#define CF_HAS_VTABPTR  0x00000010
#define CF_HAS_VIRTDT   0x00000020
#define CF_HAS_RTTI     0x00000040

#ifdef  NEWXX
#define CF_DELPHICLASS  0x00000080
#endif

#define CF_HAS_FARVPTR  0x00001000

#define CF_HAS_GUID     0x00002000  // The tpcGuid field is valid and filled in

#define XB_FINALLY	0x0
#define XB_EXCEXP	0x1
#define XB_EXCCNS	0x2
#define XB_TRYCPP	0x3
#define XB_CATCH	0x4
#define XB_DEST		0x5

#define DtorName(class) (form("@%s@$bdtr$qv",class))
#define CtorName(class) (form("@%s@$bctr$qv",class))

//kinds of name
#define tkSimple 1
#define tkPtr 2
#define tkRef 3
#define tkArr 4
//make a borland mangled name of typeinfo
static BorlandTypeName(name, kind)
{
  auto result;
  result="@$xt$";
  if (kind==tkPtr) 
    result=result+"p";
  else if (kind==tkRef)
    result=result+"r";
  else if (kind==tkArr)
    result=result+"a";
  result=form("%s%d%s",result,strlen(name),name);  
  return result;
}

//get type name from tpid. "::" replaced by "@"
static GetTpidName(addr)
{
  auto Result, cByte, Address;
  Address = addr+Word(addr+6);
  Result = "";
  for ( cByte = Byte(Address); cByte; )
  {
    if ((cByte==':')&&(Byte(Address+1)==':'))
    {
      Result = Result + "@";
      Address++;
    }
    else
      Result = Result + cByte;
    Address++;
    cByte = Byte(Address);
  }
  return Result;
}

//parse a tpid of a pointer to a type
static DoTpPtr(addr)
{
  auto x, name;
  x = addr + 8;
  Unknown(x,4);
  MakeStruct(x,"tpid_Ptr");
  name = GetTpidName(Dword(x));
  MakeName(addr, BorlandTypeName(name, tkPtr));
}

//parse a tpid of a reference to a type
static DoTpRef(addr)
{
  auto x, name;
  x = addr + 8;
  Unknown(x,4);
  MakeStruct(x,"tpid_Ptr");
  name = GetTpidName(Dword(x));
  MakeName(addr, BorlandTypeName(name, tkRef));
}

//parse a tpid of an array of a type
static DoTpArray(addr)
{
  auto x, name;
  x = addr + 8;
  Unknown(x,8);
  MakeStruct(x,"tpid_Arr");
  name = GetTpidName(Dword(x));
  MakeName(addr, BorlandTypeName(name, tkArr));
}

//parse a list of base classes
static DoBases(addr, comment)
{ 
  auto x;
  x = addr;
  ExtLinA(addr,0,"; "+comment+":");
  while (Dword(x))
  {
    Unknown(x,12);
    MakeStruct(x,"baseList");
    x = x+12;
  }
  ForceDword(x);
  MakeComm(x,"End of list");
}

//parse a list of destructible members
static DoMembers(addr, comment)
{ 
  auto x;
  x = addr;
  ExtLinA(addr,0,"; "+comment+":");
  while (Dword(x))
  {
    Unknown(x,8);
    MakeStruct(x,"dMemList");
    x = x+8;
  }
  ForceDword(x);
  MakeComm(x,"End of list");
}

//parse a tpid of a class
static DoTpClass(addr)
{
  auto x, off, name, tpcFlags, dtorAddr;
  x = addr + 8;
  tpcFlags = Dword(x+4);
  Unknown(x,24);
  MakeStruct(x,"tpid_Class");
  name = GetTpidName(addr);
  MakeName(addr, BorlandTypeName(name, tkSimple));
  x = x+24;
  if (tpcFlags & CF_HAS_DTOR)
  {
    Unknown(x,16);
    MakeStruct(x,"tpid_Class_Dtor");
    dtorAddr = Dword(x+8);
    if (dtorAddr)
      MakeName(dtorAddr, DtorName(name));
    x=x+16;
  }
  if (tpcFlags & CF_HAS_GUID)
  {
    Unknown(x,16);
    MakeStruct(x,"GUID");
    MakeComm(x,GuidToString(x));
    x=x+16;
  }
  off = Word(addr+16); //tpcBaseList
  if (off) DoBases(addr+off,"Base classes");
  off = Word(addr+18); //tpcVbasList
  if (off) DoBases(addr+off,"Virtual base classes");
  if (tpcFlags & CF_HAS_DTOR)
  {
    off = Word(addr+8+24+14);//tpcDtMembers
    if (off) DoMembers(addr+off,"Destructible members");
  }
}

//parse a tpid
static DoTpid(addr)
{
  auto tpMask, x, name;
  x = addr;
  Unknown(addr,8);
  MakeStruct(addr,"tpid_head");
  tpMask = Word(x+4);
  if (tpMask & TM_IS_PTR)
    DoTpPtr(addr);
  else if (tpMask & TM_IS_REF)
    DoTpRef(addr);
  else if (tpMask & TM_IS_ARRAY)
    DoTpArray(addr);
  else if (tpMask & TM_IS_CLASS)
    DoTpClass(addr);
  else {
    name = GetTpidName(addr);
    MakeName(addr, BorlandTypeName(name, tkSimple));
  }
  x = addr+Word(addr+6);
  MakeStr(x, BADADDR);
  MakeComm(x, "Name of the type");
  MakeName(x,"");
  while (Byte(x)) x++;
  x++;
  MakeAlign(x,4-(x%4),2);
}

static DoXbDest( addr )
{
  auto x;
  x = addr;
  if (x==0) return 0;
  while(Dword(x))
  {
    Unknown(x,12);
    MakeStruct(x,"DTT");
    x = x+12;
  }
  ForceDword(x);
  return (x+4);
}

static DoXbTryCpp( addr )
{
  auto x;
  x = addr;
  if (x==0) return 0;
  Unknown(x,8);
  MakeStruct(x,"HTD");
  x = x+8;
  while(Dword(x))
  {
    Unknown(x,20);
    MakeStruct(x,"HD");
    x = x+20;
  }
  ForceDword(x);
  return (x+4);
}

static DoXbKind( kind, addr, xb_start )
{
    auto x, end;
    end = 0;
    x = addr;
    if (kind == XB_DEST )
    {
      MakeComm(x, "destructor cleanup");
      Unknown(x,8);
      MakeStruct(x,"xbDest");
      end = (DoXbDest(Dword(x+4)) == xb_start);
      x = x+8;
    }
    if (kind == XB_TRYCPP)
    {
      MakeComm(x, "try");
      Unknown(x,4);
      MakeStruct(x,"xbTryCpp");
      end = (DoXbTryCpp(Dword(x)) == xb_start);
      x = x+4;
    }
    if ( (kind == XB_FINALLY) || (kind == XB_EXCEXP ) || (kind == XB_EXCCNS ) )
    {
      //don't know how to parse those yet
      Message("Unknown kind at 0x%X!\n",x-4);
    }
    if (kind == XB_CATCH )
    {
      MakeComm(x-4, "catch");
    }

    if (end)
      return (-1);
    else
      return x;
}

static DoExceptInfo(addr)
{
  auto x, dw, kind;
  x = addr;
  ForceDword(x);
  OpOff(x,0,0);
  MakeComm(x,"Throw list");
  x = x+4;
  dw = Dword(x);
  ForceDword(x);
  if (dw<0) OpSign(x,0);
  MakeComm(x,"BP offset of ERR structure");
  x = x+4;
  kind = Word(x+2);
  while ((kind>=0) && (kind<=5))
  {
    Message("Doing kind %d at 0x%X\n",kind,x);
    Unknown(x,4);
    MakeStruct(x,"xbHeader");
    x = x+4;
    x = DoXbKind( kind, x, addr);
    if (x==-1)
      break;
    kind = Word(x+2);
  }
}

static main(void) {
        Enums();                // enumerations
        Structures();           // structure types
        AddHotkey("Alt-F7","ExceptInfo");
        AddHotkey("Shift-F7","Tpid");
	Message("Use Alt-F7 to parse Exception info\n");
	Message("Use Shift-F7 to parse Tpid\n");
}

static ExceptInfo()
{
  DoExceptInfo(ScreenEA());
}
static Tpid()
{
  DoTpid(ScreenEA());
}

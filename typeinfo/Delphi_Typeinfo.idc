#include <idc.idc>
//Borland Delphi/C++ Builder RTTI support for IDA
//Version 1.0 24.02.2003 Igor Skochinsky <skochinsky@mail.ru>

//select one of the following BEFORE loading into IDA
//#define D1 //delphi 1 (doesn't work)
//#define D2 //delphi 2
//#define D3 //delphi 3
//#define BCB //Borland C++ Builder (1.0? not sure)
#define D4 //delphi 4 and 5

//#define FPC //free pascal hack
#define BCB4 0 //

#ifdef D1
#define DELPHI_VER 1
#endif

#ifdef D2
#define DELPHI_VER 2
#endif

#ifdef D3
#define DELPHI_VER 3
#endif

#ifdef D4
#define DELPHI_VER 4
#endif

#ifdef BCB
#define DELPHI_VER 4
#define isBCB 1
#else
#define isBCB 0
#endif

//include different routines and structures/enums definitions
#include "ti_incl.idc"
#include "utils.idc"

//parse a property record.
//add members to the class structure if needed, name methods
static DoProperty( x, ClassName, parentTi ) 
{
  auto PropName,base,text,classbase, pt;
  Message("doing property at %X\n",x);
  base=x;
  PropName=GetShortString(base+0x1a);
  text=form(";property %s: %s",PropName,GetTypeName(Dword(base)));
  SoftOff(x); MakeComm(x,"PropType: PPTypeInfo;");
  if (DELPHI_VER>=3)
       pt = Dword(Dword(x));
  else
       pt = Dword(x);
  if ( pt != parentTi )
    DoTypeInfo(pt);
  x=x+4;  
  ForceDword(x); MakeComm(x,"GetProc: Pointer;");
  if (Byte(x+3)==0xFF)
  {
    AddClassEnum(ClassName, "F"+PropName, (Dword(x)&0x00FFFFFF));
    text=text+" read "+"F"+PropName;
  }
  else if (Byte(x+3)==0xFE) 
  {
    //AddClassEnum(ClassName, "Get"+PropName, (Dword(x)&0x00FFFFFF) );
    classbase=LocByName(ClassName);
    if (classbase!=BADADDR)
    {
      MakeName(Dword(classbase+(Dword(x)&0x00FFFFFF)),"@"+ClassName+"@Get"+PropName);
    }
    text=text+" read "+"Get"+PropName;
  }
  else if (Dword(x)!=0)
  { 
    OpOff(x,0,0);
    MakeName(Dword(x),"@"+ClassName+"@Get"+PropName);
    text=text+" read "+"Get"+PropName;
  }  
  x=x+4;
  ForceDword(x); MakeComm(x,"SetProc: Pointer;");
  if (Byte(x+3)==0xFF) 
  {
    AddClassEnum(ClassName,"F"+PropName, (Dword(x)&0x00FFFFFF) );
    text=text+" write "+"F"+PropName;
  }
  else if (Byte(x+3)==0xFE) 
  {
    //AddClassEnum(ClassName,"Set"+PropName,Dword(x)&0x00FFFFFF);
    classbase=LocByName(ClassName);
    if (classbase!=BADADDR)
    {
      MakeName(Dword(classbase+(Dword(x)&0x00FFFFFF)),"@"+ClassName+"@Set"+PropName);
    }
    text=text+" write "+"Set"+PropName;
  }
  else if (Dword(x)!=0)
  { 
    OpOff(x,0,0);
    MakeName(Dword(x),"@"+ClassName+"@Set"+PropName);
    text=text+" write "+"Set"+PropName;
  }  
  x=x+4;
  ForceDword(x); MakeComm(x,"StoredProc: Pointer;");
  if ( (Dword(x)&0xFFFFFF00) == 0 )
  {
    if (Byte(x)==0) text=text+" stored False";
  }
  else if (Byte(x+3)==0xFE)
  {
    AddClassEnum(ClassName,"Is"+PropName+"Stored",Dword(x)&0x00FFFFFF);
    text=text+" stored "+"Is"+PropName+"Stored";
  }
  else
  {
    OpOff(x,0,0);
    MakeName(Dword(x),"@"+ClassName+"@Is"+PropName+"Stored");
    text=text+" stored "+"Is"+PropName+"Stored";
  }
  x=x+4;
  ForceDword(x); MakeComm(x,"Index: Integer;");
  if (Dword(x)!=0x80000000)
  {
    text=text+form(" index %d",Dword(x) );
  }
  x=x+4;
  ForceDword(x); MakeComm(x,"Default: Longint;");
  if (Dword(x)!=0x80000000)
  {
    text=text+form(" default %s",GetEnName(Dword(base),Dword(x)) );
  }
  x=x+4;
  ForceWord(x); MakeComm(x,"NameIndex: SmallInt;");
  OpDecimal(x,0);
  x=x+2;
  ForceString(x); MakeComm(x,"Name: ShortString;");
  x=x+Byte(x)+1;

  text=text+";";
  ExtLinA(base,0,text);

  return x;

}

//Parse ordinal typeinfo
static MakeOrdType ( ea, tk, ClassName, start )
{
  auto text,ot,x,min,max,i;
  x = ea;
  text="; "+ClassName+" = ";
  ForceByte(x);ot=Byte(x);
  DoEnum(x,"TOrdType");
  MakeComm(x,"OrdType: TOrdType;");
  x=x+1;
  if (tk!=tkSet)
  {
    ForceDword(x);OpDecimal(x,0);MakeComm(x,"MinValue: Longint;");
    min=Dword(x);
    if ( min & 0x80000000 ) OpSign(x,0);
    x=x+4;
    ForceDword(x);OpDecimal(x,0);MakeComm(x,"MaxValue: Longint;");
    max=Dword(x);
    x=x+4;
    if (tk==tkChar)
    {
      if (ot==otUByte)
       if ((min!=0)||(max!=255)) text=text+form("'%c'..'%c';",min,max);
                           else  text=text+"Char;";
    }
    if (tk==tkInteger)
    {
      if (ot==otUByte)
       if ((min!=0)||(max!=255)) text=text+form("%d..%u;",min,max);
                           else  text=text+"Byte;";
      if (ot==otSByte)
       if ((min!=0x80)||(max!=0x7F)) text=text+form("%d..%u;",min,max);
                           else  text=text+"Shortint;";
      if (ot==otSWord)
        if ((min!=0x8000)||(max!=0x7FFF)) text=text+form("%d..%u;",min,max);
                           else  text=text+"Smallint;";
      if (ot==otUWord)
        if ((min!=0)||(max!=65535)) text=text+form("%d..%u;",min,max);
                           else  text=text+"Word;";
      if (ot==otSLong)
        if ((min!=0x80000000)||(max!=0x7FFFFFFF)) text=text+form("%d..%u;",min,max);
                           else  text=text+"Integer;";
      if (ot==otULong)
     if (DELPHI_VER>=4)
        if ((min!=0)||(max!=0xFFFFFFFF)) text=text+form("%d..%u;",min,max);
                                   else  text=text+"Cardinal;";
     else
        if ((min!=0)||(max!=0x7FFFFFFF)) text=text+form("%d..%u;",min,max);
                                   else  text=text+"Cardinal;";
    }
    if (tk==tkEnumeration)
    {
       SoftOff(x);MakeComm(x,"BaseType: PPTypeInfo;");
       x=x+4;
       //Message("Dword(x-4)=%x,start=%x\n",Dword(x-4),start);
       if (Dword(x-4)==start||Dword(Dword(x-4))==start)
       {
         text=text+"(";
         MakeComm(x,"NameList: ShortStringBase;");
         if ( (min<0)||(max-min>1000) )
           if (AskYN(0,form("Low(%s)=%d,High(%s)=%d.\nContinue?",ClassName,min,ClassName,max))!=1)
            return;
         for (i=min;i<=max;i++)
         {
           text=text+GetShortString(x);
           ForceString(x);MakeName(x,"");
           MakeComm(x,form("ord %d(0x%x)",i,i));
           AddClassEnum(ClassName,GetShortString(x),i);
           x=x+Byte(x)+1;
           if (i!=max) text=text+", ";
         }
         text=text+");";
       }
       else
       {
         text=text+GetEnName(Dword(x-4),Dword(x-12))+".."+
                   GetEnName(Dword(x-4),Dword(x-8))+";";
       }
    }
  }
  else   //tk == tkSet
  {
    SoftOff(x);
    MakeComm(x,"CompType: PPTypeInfo");
    text=text+"set of "+GetTypeName(Dword(x));
    x=x+4;
  }
  ExtLinA(start,0,text);
  return x;
}

 //x=start address of typeinfo table
static DoTypeInfo ( x )
{ 
  auto start,tk,mk,min,max,i,count,text,ot;
  auto ClassName;
  start = x;
  if (x==0) return;
  Message("Doing TypeInfo at %X\n",x);
  x = start;
  ForceByte(x);
  tk = Byte(x);
  DoEnum(x,"TTypeKind");
  MakeComm(x,"Kind: TTypeKind;");
  x=x+1;
  ForceString(x);
  MakeComm(x,"Name: ShortString;");
  ClassName=GetShortString(x);
//  if(tk==tkClass)
//    ClassName=GetShortString(x+Byte(x)+1+10)+"@"+ClassName;
  MakeName(start, "ti"+ClassName);
  if (Dword(start-4)==start)
  {
    SoftOff(start-4);
    MakeName(start-4,"pti"+ClassName);
  }
  x=x+Byte(x)+1;
  if(tk==tkInteger||tk==tkChar||tk==tkEnumeration||tk==tkSet||tk==tkWChar) 
  {
    x=MakeOrdType(x,tk,ClassName,start);
  } 
  if (tk==tkInt64)
  {
    ForceQword(x);MakeComm(x,"MinValue: Int64;");
    OpDecimal(x,0);
    if ( Byte(x+7) & 0x80 ) OpSign(x,0);
    x=x+8;
    ForceQword(x);MakeComm(x,"MaxValue: Int64;");
    OpDecimal(x,0);
    x=x+8;
  }
  if (tk==tkFloat) 
  {
    ForceByte(x); MakeComm(x,"FloatType: TFloatType");
    DoEnum(x,"TFloatType");
    x=x+1;
  }
  if (tk==tkString)
  {
//    start=x;
    text="; "+ClassName+" = string";
    ForceByte(x); MakeComm(x,"MaxLength: Byte");
    if (Byte(x)) text=text+form("[%d]",Byte(x));
    text=text+";";
    OpDecimal(x,0);
    x=x+1;
    ExtLinA(start,0,text);
  }
  if (tk==tkClass)
  {
    text="; "+ClassName+" = class";
    SoftOff(x);MakeComm(x,"ClassType: TClass;");
    x=x+4;
    SoftOff(x);MakeComm(x,"ParentInfo: PPTypeInfo;");
    if (Dword(x)) text=text+"("+GetTypeName(Dword(x))+")";
    text=text+";";
    ExtLinA(start,0,text);
    x=x+4;
    ForceWord(x);MakeComm(x,"PropCount: SmallInt;{Total}");OpDecimal(x,0);
    x=x+2;
    ForceString(x);MakeComm(x,"UnitName: ShortStringBase;");
    x=x+Byte(x)+1;
    ForceWord(x);MakeComm(x,"PropCount: SmallInt;{In this class}");OpDecimal(x,0);
    count=Word(x);
    x=x+2;
    for(i=0;i<count;i++)
     x=DoProperty(x,ClassName,start);
  }
  if (tk==tkRecord)
  {
     text="; "+ClassName+" = record ";
     ForceDword(x);MakeComm(x,"RecordSize: Longint");
     text=text+form("{%Xh bytes} end;",Dword(x));
     x=x+4;
     ForceDword(x);MakeComm(x,"DestructableFieldsCount: Longint");
     count=Dword(x);
     x=x+4;
     for(i=0;i<count;i++)
     {
       SoftOff(x);MakeComm(x,"FieldType: PPTypeInfo");
       if (DELPHI_VER>=3)
         DoTypeInfo(Dword(Dword(x)));
       else
         DoTypeInfo(Dword(x));
       x=x+4;
       ForceDword(x);MakeComm(x,"FieldOffset: Longint");
       AddClassEnum(ClassName,form("%s_%X",GetTypeName(Dword(x-4)),Dword(x)),Dword(x));
       DoEnum(x,ClassName+"_members");
       x=x+4;
     }
    ExtLinA(start,0,text);
  }
  if (tk==tkDynArray)
  {
     text="; "+ClassName+" = array of ";
     ForceDword(x);MakeComm(x,"elSize: Longint;");
     x=x+4;
     SoftOff(x);MakeComm(x,"elType: ^PDynArrayTypeInfo;");
     if (Dword(x))
       text=text+GetTypeName(Dword(x))+";";
     else
       text=text+form("{%Xh byte elements} ;",Dword(x-4));
     x=x+4;
     ForceDword(x);MakeComm(x,"varType: Integer;");
     if (!Dword(x-4)) text=text+vtName(Dword(x))+";";
     x=x+4;
     ExtLinA(start,0,text);
  }
  if (tk==tkArray)
  {
     ForceDword(x);MakeComm(x,"ArrSize: Longint;");
     x=x+4;
     text="; "+ClassName+form(" = array [1..%d] of ",Dword(x));
     ForceDword(x);MakeComm(x,"elCount: Integer;");
     x=x+4;
     SoftOff(x);MakeComm(x,"elType: PTypeInfo;");
     text=text+GetTypeName(Dword(x))+";";
     x=x+4;
     ExtLinA(start,0,text);
  }
  if (tk==tkMethod)
  {
    start=x;
    ForceByte(x); MakeComm(x,"MethodKind: TMethodKind;");
    DoEnum(x,"TMethodKind");
    mk=Byte(x);
    text="; "+ClassName+" = ";
    if (mk==mkFunction||mk==mkSafeFunction)  text=text+"function (";
    if (mk==mkClassFunction) text=text+"class function (";
    if (mk==mkProcedure||mk==mkSafeProcedure)  text=text+"procedure (";
    if (mk==mkClassProcedure) text=text+"class procedure (";
    x=x+1;
    ForceByte(x); MakeComm(x,"ParamCount: Byte;");
    OpDecimal(x,0);
    count=Byte(x);
    x=x+1;
    for (i=1;i<=count;i++)
    {
      ForceByte(x); MakeComm(x,"Flags: TParamFlags;");
      if (Byte(x)&1) text=text+"var ";
      if (Byte(x)&2) text=text+"const ";
      if (Byte(x)&4) text=text+"array of ";
      if (Byte(x)&8) text=text+"{address} ";
      if (Byte(x)&16) text=text+"{reference} ";
      if (Byte(x)&32) text=text+"out ";
      x=x+1;
      ForceString(x); MakeComm(x,"ParamName: ShortString;");
      text=text+GetShortString(x);
      x=x+Byte(x)+1;
      ForceString(x); MakeComm(x,"TypeName: ShortString;");
      if (Byte(x))
        text=text+": "+GetShortString(x);
      x=x+Byte(x)+1;
      if (i<count) text=text+"; ";
    }
    text=text+")";
    if (mk==mkFunction||mk==mkClassFunction||mk==mkSafeFunction)
    {
     ForceString(x); MakeComm(x,"ResultType: ShortString;");
     text=text+": "+GetShortString(x);
     x=x+Byte(x)+1;
    }
    text=text+" of object;";
    ExtLinA(start,0,text);
  }
  if (tk==tkInterface)
  {
    text="; "+ClassName+" = interface";
    SoftOff(x);MakeComm(x,"IntfParent : PPTypeInfo; { ancestor }");
    if (DELPHI_VER>=3)
       DoTypeInfo(Dword(Dword(x)));
    else
       DoTypeInfo(Dword(x));
    if (Dword(x)) text=text+"("+GetTypeName(Dword(x))+")";
    ExtLinA(start,0,text);
    x=x+4;
    ForceByte(x);MakeComm(x,"IntfFlags : TIntfFlagsBase;");
    x=x+1;
    ForceDword(x); MakeComm(x,"Guid : TGUID;");
    text=GuidToString(x);
    x=x+4;ForceWord(x);ForceWord(x+2);
    x=x+4;Unknown(x,8);ForceByte(x);MakeArray(x,8);
    x=x+8;
    ForceString(x);MakeComm(x,"IntfUnit : ShortStringBase;");
    x=x+Byte(x)+1;
    ForceWord(x);MakeComm(x,"PropCount: SmallInt;");OpDecimal(x,0);
    count=Word(x);
    x=x+2;
    for(i=0;i<count;i++)
     x=DoProperty(x,ClassName,start);
    ExtLinA(start,1,text);
  }
  Message("End of TypeInfo:%X\n",x);
  checkAlign(x);
}

//parse InstanceInit table
static DoInstanceInit( x, ClassName )
{
  auto count,i,start,tk;
  if (x==0) return;
  start=x;
  Message("Doing InstanceInit at %X\n",x);

  ForceByte(x);
  DoEnum(x,"TTypeKind");
  MakeComm(x,"Kind: TTypeKind;");
  x=x+1;
  ForceString(x);
  MakeComm(x,"Name: ShortString;");
  x=x+1+Byte(x);
  ForceDword(x);MakeComm(x,"RecordSize: Longint ");
  x=x+4;
  ForceDword(x);MakeComm(x,"DestructableFieldsCount: Longint");
  count=Dword(x);
  x=x+4;
  for(i=0;i<count;i++)
  {
    SoftOff(x);MakeComm(x,"FieldType: PPTypeInfo");
    x=x+4;
    ForceDword(x);MakeComm(x,"FieldOffset: Longint");
    AddClassEnum(ClassName,form("%s_%X",GetTypeName(Dword(x-4)),Dword(x)),Dword(x));
    DoEnum(x,"_cls_"+ClassName);
    x=x+4;
  }
  Message("End of InstanceInit:%X\n",x);
  MakeName(start,"ii"+ClassName);
  checkAlign(x);
}

//parse Method Table
static DoMethodTable( x, ClassName )
{
  auto start,count,i;
  if (x==0) return;
  Message("Doing Method table at %X\n",x);
  start=x;
  count = Word(x);
  ForceWord(x);MakeComm(x,"Method count");
  OpDecimal(x,0);
  ProposeName(start, "mt"+ClassName);
  x=x+2;
  for (i=0;i<count;i++)
  {
    ForceWord(x);MakeComm(x,"Offset to next method record");
    MakeMethod(x+2,"Method address");
    MakeName(Dword(x+2),"@"+ClassName+"@"+GetShortString(x+6));
    ForceString(x+6);MakeComm(x+6,"Method name");
    MakeName(x+6,"");
    x=x+Word(x);
  }
  Message("End of MethodTable:%X\n",x);
  checkAlign(x);
}

//parse Field Table
static DoFieldTable( x, ClassName )
{
  auto start,i,typestbl,count,fieldname,text;
  if (x==0) return;
  Message("Doing Field table at %X\n",x);
  start=x;
  ForceWord(x);MakeComm(x,"Field count");
  OpDecimal(x,0);
  x=x+2;
  SoftOff(x);MakeComm(x,"Field types table offset");
  typestbl=Dword(x);
  x=typestbl;
  ForceWord(x);MakeComm(x,"Field types count");
  count=Word(x);
  x=x+2;
  for(i=0;i<count;i++)
  {
    SoftOff(x);
    DoIfNotAnalyzed(Dword(x));
    x=x+4;
  }
  checkAlign(x);
  x=start+6;
  count=Word(start);
  for (i=0;i<count;i++)
  {
    fieldname=GetShortString(x+6);
    text="; "+fieldname+": ";
    ForceDword(x);MakeComm(x,"Field offset in class");
    AddClassEnum(ClassName,fieldname,Dword(x));
    DoEnum(x,"_cls_"+ClassName);
    x=x+4;
    ForceWord(x);MakeComm(x,"Field type index");
    text=text+GetTypeByIndex(typestbl,Word(x));
    x=x+2;
    ForceString(x);MakeComm(x,"Field name");
    MakeName(x,"");
    ExtLinA(x-6,0,text);
    x=x+Byte(x)+1;
  }
  Message("End of Field Table:%X\n",x);
  MakeName(start,"ft"+ClassName);
  checkAlign(x);
}

//parse Dynamic Methods Table
static DoDynaTable( x, ClassName )
{
  auto start,count,i;
  if (x==0) return;
  Message("Doing Dynamic Methods table at %X\n",x);
  start=x;
  ForceWord(x);MakeComm(x,"Dynamic metod count");
  OpDecimal(x,0);
  count=Word(x);
  x=x+2;
  for(i=0;i<count;i++)
  {
    ForceWord(x);x=x+2;
  }
  for(i=0;i<count;i++)
  {
    MakeMethod(x,form("Message %X",Word(start+2+i*2)));
    x=x+4;
  }
  Message("End of Dynamic Methods Table:%X\n",x);
  MakeName(start,"dt"+ClassName);
  checkAlign(x);
}

//parse Interface Table
static DoIntfTable( x, ClassName )
{
  auto start,count,i,text,y;
  if (x==0) return;
  Message("Doing Interface table at %X\n",x);
  start=x;
  ForceDword(x);MakeComm(x,"EntryCount: Integer;");
  OpDecimal(x,0);
  count=Dword(x);
  x=x+4;
  for(i=0;i<count;i++)
  {
    ForceDword(x); MakeComm(x,"Guid : TGUID;");
    text=GuidToString(x);
    x=x+4;ForceWord(x);ForceWord(x+2);MakeComm(x,text);
    x=x+4;Unknown(x,8);ForceByte(x);MakeArray(x,8);
    x=x+8;
    SoftOff(x);MakeComm(x,"VTable: Pointer;");
    y = Dword(x);
    while (y<start) {
      MakeMethod(y,"");
      y=y+4;
    }
    x=x+4;
    ForceDword(x); MakeComm(x,"IOffset: Integer;");
    AddClassEnum(ClassName,form("vmtIntf_%X",Dword(x)),Dword(x));
    x=x+4;
    if ((DELPHI_VER>=4)&&(!BCB4))
    {
      ForceDword(x); MakeComm(x,"ImplGetter: Integer;");
      x=x+4;
    }
  }
  MakeName(start,"it"+ClassName);
  checkAlign(x);
}

static DoAutoParams(x)
{
  auto text,j,res,count;
  ForceByte(x);MakeComm(x,"ResType: Byte;");
  res=Byte(x);
  x=x+1;
  ForceByte(x);MakeComm(x,"ParamCount: Byte;");
  count=Byte(x);
  text="";
  x=x+1;
  if (count) {
    Unknown(x,count);ForceByte(x);MakeArray(x,count);
    MakeComm(x,"ParamTypes: array[0..255] of Byte;");
    text="("+vtName(Byte(x));
    for (j=1;j<count;j++) text=", "+vtName(Byte(x));
    text=text+")";
  }
  if (res>0) text=text+":"+vtName(res);
  x=x+count;
  return text;
}

//parse Automation Table
static DoAutoTable( x, ClassName )
{
  auto start,count,i,text,flags,tmp;
  if (x==0) return;
  Message("Doing Automation table at %X\n",x);
  start=x;
  ForceDword(x);MakeComm(x,"EntryCount: Integer;");
  OpDecimal(x,0);
  count=Dword(x);
  x=x+4;
  text="";
  for(i=0;i<count;i++)
  {
    ForceDword(x);MakeComm(x,"DispId: Integer;");
    x=x+4;
    SoftOff(x);MakeComm(x,"Name: PShortString;");
    ForceString(Dword(x));
    MakeName(x,"");
    x=x+4;
    ForceDword(x);MakeComm(x,"Flags: Integer;");
    flags=Dword(x);
    text=GetShortString(Dword(x-4));
    if (flags&2) text="Get_"+text;
    if (flags&4) text="Set_"+text;
    if (!(flags&8))
    {
     Message("Doing MakeName(%X,%s);\n",Dword(x+8),"@"+ClassName+"@"+text);
     MakeName(Dword(x+8),"@"+ClassName+"@"+text);
     MakeMethod(x+8,"");
    }
    if (flags&2) text="function "+text;
            else text="procedure "+text;
    x=x+4;
    SoftOff(x);MakeComm(x,"Params: PParamList;");
    tmp=DoAutoParams(Dword(x));
    text="; "+text+tmp+";";
    ExtLinA(x-12,0,text);
    x=x+4;
    SoftOff(x);MakeComm(x,"Address: Pointer;");
    x=x+4;
  }
  MakeName(start,"at"+ClassName);
}

static DoIfNotAnalyzed(x)
{
  if (!Analyzed(x))
  if ((DELPHI_VER>=3) && (!isBCB))
    DoVMT( Dword(x) );
  else
    DoVMT( x );
}

//Have we analyzed this class yet?
static Analyzed (x) 
{
  if ((x==BADADDR)||(x==0)) return 1;
  if ((DELPHI_VER>=3) && (!isBCB))
    x=Dword(x);
  return ( GetShortString(Dword(x+vmtClassName))==Name(x) ); 
}

//set Vmt method at vmt+offset
//offset can be negative for special methods (e.g. Destroy)
//take a class name of most base class that contains this method
static MakeVmtMethod( vmt, offset, name, cmt)
{
  auto p,parent,last,x;
  x = vmt+offset;
  ForceDword( x );
  OpOff(x,0,0);
  MakeComm(x, cmt);
  p = Dword(x);
  if (!p)
   return;
  parent = vmt;
  while ((parent)&&(Dword(parent+offset)==p))
  {
   last = parent;
   parent = Dword(parent+vmtParent);
   if ((DELPHI_VER>=3) && (!isBCB))
     parent=Dword(parent);
  }
  MakeName(p,"@"+GetShortString(Dword(last+vmtClassName))+"@"+name);
  if (!MakeCode( p )) {
   MakeUnkn(p,0);
   MakeCode(p);
  }
  AutoMark( p, AU_PROC );
}

//parse a VMT (methods and tables at negative offsets too)
static DoVMT( x ) {
  auto parent, start,i,ClassName,minTblAddr,instSize,off_x;
  minTblAddr=0x7FFFFFFF;
  if (x==BADADDR) return;
  Message("Called DoVMT(%x)\n",x);
  start = x;
  instSize=Dword( start + vmtInstanceSize );
  //guardcheck against wrong parsing
  if ( (instSize>0x1000) || (instSize==0) ) 
  {
   if (AskYN(0,form("This class instance size is %X\nDo you wish to continue analysis?"
                     ,instSize))!=1 ) return;
  }
  //first analyze parent class if needed
  parent=Dword(start + vmtParent);
  DoIfNotAnalyzed(parent);

  //parse special class methods
  MakeVmtMethod( start, vmtDestroy, "Destroy", "destructor Destroy" );
  MakeVmtMethod( start, vmtFreeInstance, "FreeInstance" , "FreeInstance method");
  MakeVmtMethod( start, vmtNewInstance,"NewInstance"      , "NewInstance method");
  MakeVmtMethod( start , vmtDefaultHandler,"DefaultHandler"   , "DefaultHandler method");
  if ((DELPHI_VER>=3) && (!isBCB))
    MakeVmtMethod ( start, vmtSafeCallException, "SafeCallException", "SafeCallException  method" );
  if (DELPHI_VER>=4)
  {
    MakeVmtMethod ( start , vmtAfterConstruction, "AfterConstruction", "AfterConstruction  method" );
    MakeVmtMethod ( start , vmtBeforeDestruction,"BeforeDestruction", "BeforeDestruction method");
    MakeVmtMethod ( start , vmtDispatch         ,"Dispatch", "Dispatch method");
  }
  MakeVmtMethod ( start , vmtDefaultHandler, "DefaultHandler", "DefaultHandler method");
  x = start + vmtParent;
  SoftOff(x); MakeComm(x,"Pointer to parent class");
  x = start + vmtInstanceSize;
  MakeName(x,"");
  MakeComm(x,"Instance size");
  ForceDword(x);
  x = start + vmtClassName;
  MakeComm(x,"Class name pointer");
  off_x=SoftOff1(x);
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  x = off_x;
  ForceString(x);
  checkAlign(x+Byte(x)+1);
  ClassName = GetShortString(x);
  x = start + vmtDynamicTable;
  MakeComm(x,"Pointer to dynamic method table");
  off_x=SoftOff1(x); 
  DoDynaTable(off_x,ClassName);
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  x = start + vmtMethodTable;
  MakeComm(x,"Pointer to method definition table");
  off_x=SoftOff1(x); 
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  DoMethodTable(off_x, ClassName);
  x = start + vmtFieldTable;
  MakeComm(x,"Pointer to field definition table");
  off_x=SoftOff1(x); 
  DoFieldTable(off_x, ClassName);
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  x = start + vmtTypeInfo;
  MakeComm(x,"Pointer to type information table");
  off_x=SoftOff1(x);
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  DoTypeInfo(off_x);

  x = start + vmtInitTable;
  MakeComm(x,"Pointer to instance initialization table");
  off_x=SoftOff1(x); 
  DoInstanceInit(off_x, ClassName);
  if (off_x)
     minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
  x = start + vmtSelfPtr;
  SoftOff(x); MakeComm(x,"Pointer to self");

  if ((DELPHI_VER>=3) && (!isBCB))
  {
    MakeName(x,ClassName+"Class");
    x = start + vmtIntfTable;
    MakeComm(x,"Pointer to interface table");
    off_x=SoftOff1(x); 
    if (off_x)
       minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
    DoIntfTable(off_x, ClassName);
    x = start + vmtAutoTable;
    MakeComm(x,"Pointer to Automation initialization table");
    off_x=SoftOff1(x);
    if (off_x)
       minTblAddr=((off_x<minTblAddr)&&(off_x>=start))?off_x:minTblAddr;
    DoAutoTable(off_x, ClassName);
  }

  //minTblAddr determines the end of virtual methods table
  Message("minTblAddr=%X\n",minTblAddr);
  if ((minTblAddr!=MAXADDR)&&(minTblAddr!=0))
    for (x=start;x<minTblAddr;x=x+4)
    {
      off_x = x-start;
      if (off_x<0x10)
        i = form("0%X",off_x);
      else
        i = form("%X",off_x);
      //MakeMethod(x,form("Virtual method %X",x-start));
      MakeVmtMethod(start, off_x, "Virtual"+i, "Virtual method "+i);
    }
  MakeName(start, ClassName);
}

static main(void) {

 InitEnums();
 //SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);

// DoVMT(AskAddr(ScreenEA(),"Enter address of class VMT"));

 AddHotkey("Ctrl-Alt-F8","VMT");
 AddHotkey("Ctrl-Alt-D","DoDelphiStr");
 AddHotkey("Ctrl-F8","VMTPtr");
 AddHotkey("Ctrl-Alt-F9","TypeInfo");
 AddHotkey("Ctrl-Shift-F9","TypeInfoPtr");
 Message("Assuming Delphi version: %d\n",DELPHI_VER);
 Message("Use Ctrl-Alt-F8(Ctrl-F8) to parse a (pointer to) class VMT\n");
 Message("Use Ctrl-Alt-F9(Ctrl-Shift-F9) to parse a (pointer to) TypeInfo\n");
 Message("Use Ctrl-Alt-D to parse a Delphi string\n");
}                                             

static VMT(void)
{
 auto save_str;
 save_str = GetLongPrm(INF_STRTYPE);
 SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
 DoVMT(ScreenEA());
 SetLongPrm(INF_STRTYPE,save_str);
}

static VMTPtr(void)
{
 auto save_str;
 save_str = GetLongPrm(INF_STRTYPE);
 SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
 DoVMT(Dword(ScreenEA()));
 SetLongPrm(INF_STRTYPE,save_str);
}

static TypeInfo(void)
{
 auto save_str;
 save_str = GetLongPrm(INF_STRTYPE);
 SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
 DoTypeInfo(ScreenEA());
 SetLongPrm(INF_STRTYPE,save_str);
}

static TypeInfoPtr(void)
{
 auto save_str,x;
 save_str = GetLongPrm(INF_STRTYPE);
 SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
 x=ScreenEA();
 DoTypeInfo(Dword(x));
 SoftOff(x);MakeName(x,"p"+GetTrueName(Dword(x)));
 SetLongPrm(INF_STRTYPE,save_str);
}

static DoDelphiStr(void)
{
 auto save_str;
 save_str = GetLongPrm(INF_STRTYPE);
 SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
 MakeLStr(ScreenEA(),1);
 SetLongPrm(INF_STRTYPE,save_str);
}
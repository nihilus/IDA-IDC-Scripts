#include <idc.idc>
//////////////////////////////////////
// Unknown(long ea, long length)
//////////////////////////////////////
// Mark the ea as unknown for a length
// of length, but don't propagate.
static Unknown( ea, length )
{
  auto i;
//  Message("Unknown(%x,%d)\n",ea, length);
  for(i=0; i < length; i++)
     {
       MakeUnkn(ea+i,0);
     }
}

//////////////////////////////////////
// ProposeName(long ea, char* name)
//////////////////////////////////////
// Non destructive name a paerticular ea.
// If specified ea got no name, it takes
// the name, otherwise add a comment at
// ea to store the name.
static ProposeName( ea , name )
{
  auto cmt;
  cmt = RptCmt( ea );
  if ( strlen(cmt) != 0 ) cmt = cmt + "\n" + name;
  else cmt = name;
  cmt = cmt + "\nproposed name";

  if ( (GetFlags(ea) & FF_NAME) == 0)
     {
       if (MakeName(ea,name) == 1)
          {
             return;
          }
     }

  if (Name(ea) == name) return;
  MakeRptCmt(ea,cmt);
}

static checkAlign( x )  // check for Delphi 4-byte alignment and align if present
{
  if ((x%4)==0) return;
  if ((x%4)==1)
   if( (Word(x)==0x408D)&&(Byte(x+2)==0) )
   {
     MakeUnkn(x,0);
     MakeUnkn(x+1,0);
     MakeUnkn(x+2,0);
     MakeAlign(x,3,0);
   };
  if ((x%4)==2)
   if (Word(x)==0xC08B)
   {
     MakeUnkn(x,0);
     MakeUnkn(x+1,0);
     MakeAlign(x,2,0);
   };
  if ((x%4)==3)
   if (Byte(x)==0x90)
   {
     MakeUnkn(x,0);
     MakeAlign(x,1,0);
   };

}

static GetShortString( x ){   //Get pascal string at x
  auto len,i;
  auto res;
  res = "";
  len = Byte(x);
  for (i=1;i<=len;i++) res=form("%s%c",res,Byte(x+i));
  return res;
}

static ForceQword( x ) {  //Make dword, undefine as needed
 if (!MakeQword( x ))
 {
   Unknown(x,8);
   MakeQword(x);
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

static ForceString(x) { //Make short pascal string at x
//  Message("Doing string at %x, len=%d\n", x,Byte(x));
  Unknown(x,Byte(x)+1);
  MakeStr(x,x+Byte(x)+1);
//  MakeName(x,"");
}

//Make LStr at x
//if rec is set, then it tries to check for more strings after the current one
static MakeLStr( x , rec) 
{
  auto len,end;
  len=Dword(x-4);
  if (Dword(x-8)!=-1) return 0;
  if (Byte(x+len)) return 0;
  ForceDword(x-8);
  MakeComm(x-8, "Ref count");
  ForceDword(x-4);
  len=Dword(x-4);
  MakeComm(x-4, "String length");
  Unknown(x,(len+0x4)&(0xFFFFFFFC));
  SetLongPrm(INF_STRTYPE,STRTERM1(0));
  MakeStr(x,x+len+1);
  end=(x+len+4)&0xFFFFFFFC;
  MakeAlign(x+len+1,4-((len+1)%4),0);
  SetLongPrm(INF_STRTYPE,ASCSTR_PASCAL);
  if (rec)
   while (end=MakeLStr(end+8,0));
  return end;
}

static DoEnum(x,enum_name)
{
  auto enum_id;
  OpEnum(x,0,GetEnum(enum_name));
}

static SoftOff ( x ) { //Make offset if !=0
 ForceDword(x);
 if (Dword(x)>0 && Dword(x)<=MaxEA()) OpOff(x,0,0);
}

static SoftOff1 ( x ) { //Make offset if !=0,Return target
 if (DELPHI_VER==1)
 {
   ForceWord(x);
   if (Word(x)>0 && Word(x)<=SegEnd(x)) OpOff(x,SegStart(x)>>4,0);
   return (Word(x)>0)?SegStart(x)+Word(x):0;
 }
 else
 {
   ForceDword(x);
   if (Dword(x)>0 && Dword(x)<=MaxEA()) OpOff(x,0,0);
   return Dword(x);
 }
}

static MakeMethod( x, comment) {
  auto p;
  ForceDword( x );
  OpOff(x,0,0);
  MakeComm(x, comment);
  p = Dword(x);
  if (!MakeCode( p )) {
   MakeUnkn(p,0);
   MakeCode(p);
  }
  AutoMark( p, AU_PROC );
}

//get a name of type represented by typeinfo structure at ti
static GetTypeName( ti ) 
{
  auto name,last,pos,ch;
  //  Message("called GetTypeName ( %X );\n",ti );

  if ((DELPHI_VER>=3) && (!isBCB))
    if (SegName(ti)==".idata") //if class is imported from a package
    {
     ch=(DELPHI_VER==3)?'_':'@';
     name=Name(ti);
     pos=strstr(name,ch);
     while (pos!=-1)
     {
       last=pos;
       name=substr(name,last+1,-1);
       pos=strstr(name,ch);
     }
     return (name);
    }
  if ((DELPHI_VER>=3) && (!isBCB))
    return GetShortString(Dword(ti)+1);
  else
    return GetShortString(ti+1);
}

//get a name of type from a type index table
static GetTypeByIndex ( base, index )
{
  auto _class,name,last,pos,ch;
  //Message("called GetTypeByIndex ( %X,%d );\n",base, index );
  _class=Dword(base+2+index*4);

  if ((DELPHI_VER>=3) && (!isBCB))
    if (SegName(_class)==".idata") //if class is imported from a package
    {
     ch=(DELPHI_VER==3)?'_':'@';
     name=Name(_class);
     name=substr(name,0,strlen(name)-1);
     pos=strstr(name,ch);
     while (pos!=-1)
     {
       last=pos;
       name=substr(name,last+1,-1);
       pos=strstr(name,ch);
     }
     return (name);
    }
  if ((DELPHI_VER>=3) && (!isBCB))
    _class=Dword(_class);
  return GetShortString(Dword(_class+vmtTypeInfo)+1);
}

/*
static AddClassEnum(classname,constname,val)
{
  auto enum_ID,enum_name;
  enum_name=classname+"_members";
  if ((enum_ID=GetEnum(enum_name))==-1) // New enum
    if ((enum_ID=AddEnum(GetEnumQty() + 1, enum_name, FF_0NUMH))==-1)
    {
      Warning("Couldn't create enumeration '%s'!",enum_name);
      return;
    }
  return (AddConst(enum_ID,classname+"_"+constname,val));
}
*/

//Add a member to a class structure
//classname - name of class
//constname - member name
//val - offset of member
static AddClassEnum(classname,constname,val)
{
  auto enum_ID,enum_name;
  enum_name="_cls_"+classname;
  if ((enum_ID=GetStrucIdByName(enum_name))==-1) // New enum
    if ((enum_ID=AddStruc(GetStrucQty() + 1, enum_name))==-1)
    {
      Warning("Couldn't create structure '%s'!",enum_name);
      return;
    }
  return (AddStrucMember(enum_ID, constname, val, FF_DWRD, -1, 4));
}

//get a name of delphi enumeration member
static GetEnName( typeinfo, value )
{
  auto name;
  if ((DELPHI_VER>=3) && (!isBCB))
    typeinfo=Dword(typeinfo);

  if (Byte(typeinfo)!=tkEnumeration) 
    return (form("%d",value));

  if (value<0) 
  {
    Warning("value<0 in GetEnName!");
    return("");
  }
  name=typeinfo+1+Byte(typeinfo+1)+1+13;

  if (DELPHI_VER==2)
    if (Dword(name-4)!=typeinfo) 
    {
      typeinfo=Dword(name-4);
      name=typeinfo+1+Byte(typeinfo+1)+1+13;
    }
  else
    if (Dword(Dword(name-4))!=typeinfo)
    {
      typeinfo=Dword(Dword(name-4));
      name=typeinfo+1+Byte(typeinfo+1)+1+13;
    }
  while (value)
  {
    name=name+Byte(name)+1;
    value=value-1;
  }
  return(GetShortString(name));
}

//get Variant type name
static vtName( vt )
{
  if (vt==0) return "";
  if (vt==1) return "nil";
  if (vt==2) return "Smallint";
  if (vt==3) return "Integer";
  if (vt==4) return "Single";
  if (vt==5) return "Double";
  if (vt==6) return "Currency";
  if (vt==7) return "Date";
  if (vt==8) return "OleStr";
  if (vt==9) return "Dispatch";
  if (vt==10) return "Error";
  if (vt==11) return "Boolean";
  if (vt==12) return "Variant";
  if (vt==13) return "pUnknown";
  if (vt==17) return "Byte";
  return "??";
}

static GuidToString(x)
{
  auto text;

  text=form("; ['{%08X-%04X-%04X",Dword(x),Word(x+4),Word(x+6));
  text=text+form("-%02X%02X%02X%02X%02X%02X%02X%02X}']",
  Byte(x+8),Byte(x+9),Byte(x+10),Byte(x+11),Byte(x+12),Byte(x+13),Byte(x+14),Byte(x+15));
  return text;
}
#include <idc.idc>
//Microsoft C++ RTTI support for IDA
//Version 1.0 24.02.2003 Igor Skochinsky <skochinsky@mail.ru>

//check if Dword(vtbl-4) points to typeinfo record and extract the type name from it
static GetTypeName(vtbl)
{
  auto x, s, c;
  x = Dword(vtbl-4);
  if ((!x) || (x==BADADDR)) return "";
  if (Dword(x)||Dword(x+4)||Dword(x+8)) return "";
  x = Dword(x+12);
  if ((!x) || (x==BADADDR)) return "";
  s = "";
  x = x+8;
  while (c=Byte(x))
  {
    s = form("%s%c",s,c);
    x = x+1;
  }
  return s;
}

static main(void)
{
  auto a,i,s;
  a=ScreenEA();
  s=GetTypeName(a);
  if (substr(s,0,4)==".?AV")
  {
    s=substr(s,4,-1);
    MakeName(a,"??_7"+s+"6B@");
  }
}

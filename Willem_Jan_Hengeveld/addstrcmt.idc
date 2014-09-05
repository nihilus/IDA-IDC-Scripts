// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>

// this script adds the full referenced string in comments
// in and arm disassembly.
// it searches all 'LDR' instructions, and determines if the referenced address
// contains a string.

static isprintable(c)
{
 return (c>=" " && c<="~");
}
static escapedchar(c)
{
 if (c=="\r") return "\\r";
 if (c=="\t") return "\\t";
 if (c=="\n") return "\\n";
 if (c=="\0") return "\\0";
 return form("\\x%02x", ord(c)&0xff);
}
static printablewstring(ea) {
 auto seenprintable; 
 auto s;
 auto c;
 seenprintable= 0;
 s= "";
 while (Word(ea)) {
  c= char(Word(ea));
  if (isprintable(c)) {
   if (c=="\"") s = s + "\\\"";
   else if (c=="\\") s = s + "\\\\";
   else s= s + c;
   seenprintable= 1;
  }
  else {
   if (seenprintable) break;
   s= s + escapedchar(c);
  }
  ea= ea+2;
 }
 return "L\""+s+"\"";
}
static printableastring(ea) {
 auto seenprintable; 
 auto s;
 auto c;
 seenprintable= 0;
 s= "";
 while (Byte(ea)) {
  c= char(Byte(ea));
  if (isprintable(c)) {
   if (c=="\"") s = s + "\\\"";
   else if (c=="\\") s = s + "\\\\";
   else s= s + c;
   seenprintable= 1;
  }
  else {
   if (seenprintable) break;
   s= s + escapedchar(c);
  }
  ea= ea+1;
 }
 return "\""+s+"\"";
}
static addstrcmts() {
 auto ea;
 auto sea;
 ea= 0;
 while (BADADDR!=(ea= FindText(ea, SEARCH_DOWN+SEARCH_REGEX, 0, 0, " LDR[A-Z]* +[A-Z][A-Z0-9][0-9]*, +=[a-zA-Z_][a-zA-Z0-9_]+ *(;.*)?$"))) {
  if (substr(GetMnem(ea),0,3)=="LDR" && GetOpType(ea, 1)==2) {
   sea= Dword(GetOperandValue(ea, 1));
   if (isLoaded(sea) && isData(GetFlags(sea))) {

    if (SegName(sea)=="__cfstring") {
        sea= Dword(sea+8);
    }

    if (GetStringType(sea)==ASCSTR_UNICODE) {
     MakeComm(ea, printablewstring(sea));
     MakeTable(sea, NextHead(sea, BADADDR), "Al");
    }
    else if (GetStringType(sea)==ASCSTR_C) {
     MakeComm(ea, printableastring(sea));
     MakeTable(sea, NextHead(sea, BADADDR), "Al");
    }
    else
     Message("%08lx: -> %08lx: not a string - %s\n", ea, sea, Name(sea));
   }
  }
  ea= NextHead(ea, BADADDR);
 }
}
static main() {
    addstrcmts();
}

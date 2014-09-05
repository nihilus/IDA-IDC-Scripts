//
//      This example shows how to get list of functions.
//

#include <idc.idc>
#include "idascript.idc"

static main()
{
  auto ea, x;

  InitUtils();

  for ( ea=NextFunction(0); ea != BADADDR; ea=NextFunction(ea) )
  {
    Print(("Function at %08lX: %s", ea, GetFunctionName(ea)));
    x = GetFunctionFlags(ea);
    if ( x & FUNC_NORET )
      Print((" Noret"));
    if ( x & FUNC_FAR )
      Print((" Far"));
    Print(("\n"));
  }

  Quit(0);
}

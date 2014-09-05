/*
Sample hello world script.

(c) Hex-Rays
*/
#include <idc.idc>
#include "idascript.idc"

//--------------------------------------------------------------------------
static main()
{
  InitUtils();

  Print(("Hello world from IDC!\n"));

  Quit(0);
}
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

  auto i;
  for (i=1;i<ARGV.count;i++)
    Print(("ARG[%d]=%s\n", i, ARGV[i]));

  Quit(0);
}
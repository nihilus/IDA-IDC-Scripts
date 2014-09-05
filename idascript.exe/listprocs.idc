/*
Sample script that enumerates all processes

(c) Hex-Rays
*/
#include <idc.idc>
#include <idascript.idc>

static main()
{
  InitUtils();

  LoadDebugger("win32", 0);
  auto q = GetProcessQty(), i;

  for (i=0;i<q;i++)
    Print(("[%08X] %s\n", GetProcessPid(i), GetProcessName(i)));

  Quit(0);
}
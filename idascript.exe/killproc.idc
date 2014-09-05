/*
Sample script kill processes by name

(c) Hex-Rays
*/
#include <idc.idc>
#include "idascript.idc"
#include "procutil.idc"

static main()
{
  InitUtils();

  // Load the debugger
  LoadDebugger("win32", 0);

  // Get parameters
  if (ARGV.count < 1)
    QuitMsg(0, "Usage: killproc.idc ProcessName\n");

  auto procs = FindProcessByName(ARGV[1]), i;
  if (procs.count == 0)
    QuitMsg(-1, "No process(es) with name " + ARGV[1]);

  for (i=procs.count-1;i>=0;i--)
  {
    auto pid = procs[i];
    Print(("killing pid: %X\n", pid));
    KillProcess(pid);
  }

  Quit(0);
}
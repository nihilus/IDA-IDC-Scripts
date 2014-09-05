/*
Sample script kill processes by name

(c) Hex-Rays
*/
#include <idc.idc>
#include "idascript.idc"
#include "procutil.idc"

//--------------------------------------------------------------------------
static DumpProcessInfo()
{
  auto sep = "-----------------------------------------------------------------------------\n";
  Print((sep));

  // Retrieve command line via Appcall
  Print(("Command line: %s\n", GetProcessCommandLine()));

  // Enum modules
  Print(("Module list:\n------------\n"));

  auto x;
  for (x = GetFirstModule();x!=BADADDR;x=GetNextModule(x))
    Print(("Module [%08X] [%08X] %s\n", x, GetModuleSize(x), GetModuleName(x)));

  Print(("\nThread list:\n------------\n"));
  for (x=GetThreadQty()-1;x>=0;x--)
  {
    auto tid = GetThreadId(x);
    Print(("Thread [%x]\n", tid));
    SelectThread(tid);
    Print(("  EIP=%08X ESP=%08X EBP=%08X\n", Eip, Esp, Ebp));
  }
  Print((sep));
}

//--------------------------------------------------------------------------
static main()
{
  InitUtils();

  // Load the debugger
  LoadDebugger("win32", 0);

  // Get parameters
  if (ARGV.count < 2)
    QuitMsg(0, "Usage: killproc.idc ProcessName\n");

  auto procs = FindProcessByName(ARGV[1]), i;
  for (i=procs.count-1;i>=0;i--)
  {
    auto pid = procs[i];
    if (!AttachToProcess(pid))
    {
      Print(("Could not attach to pid=%x\n", pid));
      continue;
    }
    DumpProcessInfo();
    DetachFromProcess();
  }

  Quit(0);
}
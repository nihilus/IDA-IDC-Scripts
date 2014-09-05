/*
Process utility script

(c) Hex-Rays
*/
#include <idc.idc>

//--------------------------------------------------------------------------
static KillProcess(pid)
{
  if (!AttachToProcess(pid))
    return 0;

  StopDebugger();

  // Normally, we should get a PROCESS_EXIT event
  GetDebuggerEvent(WFNE_SUSP, -1);
}

//--------------------------------------------------------------------------
static GetProcessCommandLine()
{
  // Get address of the GetCommandLine API
  auto e, GetCmdLn = LocByName("kernel32_GetCommandLineA");

  if (GetCmdLn == BADADDR)
    return 0;

  // Set its prototype for Appcall
  SetType(GetCmdLn, "char * __stdcall x();");
  try
  {
    // Retrieve the command line using Appcall
    return GetCmdLn();
  }
  catch (e)
  {
    return 0;
  }
}

//--------------------------------------------------------------------------
static FindProcessByName(name)
{
  auto q = GetProcessQty();
  auto i, procs = object(), pcount=0;
  for (i=0;i<q;i++)
  {
    auto pname = GetProcessName(i);
    // No match?
    if (strstr(pname, name) == -1)
      continue;
    procs[pcount] = GetProcessPid(i);
    pcount++;
  }
  procs.count = pcount;
  return procs;
}

//--------------------------------------------------------------------------
static AttachToProcess(pid)
{
  auto code = AttachProcess(pid, -1);
  if (code != 1)
    return 0;

  // Normally, we should get a PROCESS_ATTACH event
  GetDebuggerEvent(WFNE_SUSP, -1);
  return 1;
}

//--------------------------------------------------------------------------
static DetachFromProcess()
{
  DetachProcess();
  // Normally, we should get a PROCESS_DETACH event
  GetDebuggerEvent(WFNE_SUSP, -1);
}
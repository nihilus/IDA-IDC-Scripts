/*
A utility script to read or write to process memory from or to a file.

Usage:
  runidc rwproc load notepad 10000 200 new_contents.bin
  ^^This will load the contents of 'new_contents.bin' into the process memory of notepad at address 0x10000 with size 200

  runidc rwproc save notepad 10000 200 contents.bin
  ^^This will write the contents of notepad process memory at address 0x10000 with size 200 into 'contents.bin'

(c) Hex-Rays
*/
#include <idc.idc>
#include "idascript.idc"
#include "procutil.idc"

static main()
{
  InitUtils();

  if (ARGV.count < 6)
  {
    Print(("Usage: rwproc.idc load|save processname addr_in_hex sz_in_hex to_file|from_file"));
    Quit(0);
  }

  LoadDebugger("win32", 0);

  auto PARAM_ACTION     = ARGV[1];
  auto PARAM_PROCNAME   = ARGV[2];
  auto PARAM_ADDR       = ARGV[3];
  auto PARAM_SZ         = ARGV[4];
  auto PARAM_FN         = ARGV[5];

  // Parse operation mode
  auto load;
  if (PARAM_ACTION == "load")
    load = 1;
  else if (PARAM_ACTION == "save")
    load = 0;
  else
    QuitMsg(-1, "Must pass either read or write; '"+PARAM_ACTION+"' passed.");

  // Find process by the given name
  auto procs = FindProcessByName(PARAM_PROCNAME), i;

  if (procs.count == 0)
    QuitMsg(-1, sprintf("No process by the name of %s was found!", PARAM_PROCNAME));

  auto addr = xtol(PARAM_ADDR);
  if (addr == 0)
    QuitMsg(-2, "Invalid address passed!");

  auto sz = xtol(PARAM_SZ);
  if (addr == 0)
    QuitMsg(-3, "Invalid size passed!");

  if (procs.count > 1)
    Print(("Found multiple processes with same name, will use the first one only!\n"));

  auto fp;
  if (load)
    fp = fopen(PARAM_FN, "rb");
  else
    fp = fopen(PARAM_FN, "wb");
  if (fp == 0)
    QuitMsg(-4, sprintf("Failed to open %s for reading or writing!", PARAM_FN));

  if (!AttachToProcess(procs[0]))
  {
    QuitMsg(-4, "Failed to attach!");
    fclose(fp);
  }

  if (load)
    loadfile(fp, 0, addr, sz);
  else
    savefile(fp, 0, addr, sz);

  DetachFromProcess();

  if (load)
    Print(("Loaded %d byte(s) from '%s' into process '%s' at %08X", sz, PARAM_FN, PARAM_PROCNAME, addr));
  else
    Print(("Saved %d byte(s) to '%s' from process '%s' at %08X", sz, PARAM_FN, PARAM_PROCNAME, addr));

  Quit(0);
}

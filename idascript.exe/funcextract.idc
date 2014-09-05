/*
Sample script illustrating how to extract the body of a function

(c) Hex-Rays
*/
#include <idc.idc>
#include "idascript.idc"

static main()
{
  InitUtils();

  if (ARGV.count < 2)
    QuitMsg(0, "Usage: funcextract.idc FuncName OutFile");

  // Resolve name
  auto ea = LocByName(ARGV[1]);
  if (ea == BADADDR)
    QuitMsg(0, sprintf("Function '%s' not found!", ARGV[1]));

  // Get function start
  ea = GetFunctionAttr(ea, FUNCATTR_START);
  if (ea == BADADDR)
    QuitMsg(0, "Could not determine function start!\n");

  // size = end - start
  auto sz = GetFunctionAttr(ea, FUNCATTR_END) - ea;

  auto fp = fopen(ARGV[2], "wb");
  if (fp == 0)
    QuitMsg(-1, "Failed to create output file\n");

  savefile(fp, 0, ea, sz);
  fclose(fp);

  Print(("Successfully extracted %d byte(s) from '%s'", sz, ARGV[1]));
  Quit(0);
}

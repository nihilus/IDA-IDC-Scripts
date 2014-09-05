/*
IDC utility functions.

(c) Hex-Rays
*/
#include <idc.idc>

#define Print(x) LogWrite(sprintf x)

//--------------------------------------------------------------------------
extern g_idcutil_oldopt;

//--------------------------------------------------------------------------
extern g_idcutil_logfile;
static LogInit()
{
  g_idcutil_logfile = fopen("idaout.txt", "w");
  if (g_idcutil_logfile == 0)
    return 0;
  return 1;
}

//--------------------------------------------------------------------------
static LogWrite(str)
{
  if (g_idcutil_logfile != 0)
    return fprintf(g_idcutil_logfile, "%s", str);
  return -1;
}

//--------------------------------------------------------------------------
static QuitMsg(code, s)
{
  LogWrite(s);
  Quit(code);
}

//--------------------------------------------------------------------------
static LogTerm()
{
  if (g_idcutil_logfile == 0)
    return;
  fclose(g_idcutil_logfile);
  g_idcutil_logfile = 0;
}

//--------------------------------------------------------------------------
static InitUtils()
{
  // We mark as snapshot so that we can load the debuggers
  SetCharPrm(INF_LFLAGS, GetCharPrm(INF_LFLAGS) | LFLG_SNAPSHOT);

  // Disable all debugger output
  g_idcutil_oldopt = SetDebuggerOptions(0);

  return LogInit();
}

//--------------------------------------------------------------------------
static Quit(code)
{
  TermUtils();
  Exit(code);
}

//--------------------------------------------------------------------------
static TermUtils()
{
  // Restore debugger options
  SetDebuggerOptions(g_idcutil_oldopt);

  LogTerm();
}

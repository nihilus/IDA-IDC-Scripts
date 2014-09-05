//--------------------------------------------------------------------------
extern g_idcutil_logfile;
static LogInit()
{
  g_idcutil_logfile = fopen("idaout.txt", "w");
  if (g_idcutil_logfile == 0)
    return 0;
  return 1;
}

static LogWrite(str)
{
  if (g_idcutil_logfile != 0)
    return fprintf(g_idcutil_logfile, "%s", str);
  return -1;
}

static LogTerm()
{
  if (g_idcutil_logfile == 0)
    return;
  fclose(g_idcutil_logfile);
  g_idcutil_logfile = 0;
}

//--------------------------------------------------------------------------
static main()
{
  LogInit(); // Open log file
  LogWrite("Hello world from IDC!\n"); // Write to log file
  LogTerm(); // Close log file

  Exit(0); // Exit IDA Pro
}
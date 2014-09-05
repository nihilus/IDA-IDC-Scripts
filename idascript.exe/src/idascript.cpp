/*-------------------------------------------------------------------------
IDAScript - 1.0 (c) Hex-Rays

A frontend utility for the -S and -t switches.
This utility allows you to run IDC scripts (or other registered scripts) from
the command line.
-------------------------------------------------------------------------*/
#include <stdio.h>
#include <windows.h>
#include <string>
#include <conio.h>

//-------------------------------------------------------------------------
#define IDA_EXE "idag.exe"
#define IDA_OUT "idaout.txt"

//-------------------------------------------------------------------------
bool launch_program(
  const char *prog,
  const char *args)
{
  PROCESS_INFORMATION pi;
  STARTUPINFO si = {sizeof(si)};

  char *cargs = strdup(args);
  bool ok = CreateProcess(prog, cargs, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == TRUE;
  if ( ok )
  {
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
  free(cargs);
  return ok;
}

//-------------------------------------------------------------------------
void show_usage()
{
  static const char help[] =
    "IDAScript 1.0 (c) Hex-Rays - A tool to run IDA Pro scripts from the command line\n"
    "\n"
    "It can be used in two modes:\n"
    "\n"
    "a) With a database:\n"
    "\n"
    "\tidascript database.idb script.(idc|py|...) [arg1 [arg2 [arg3 [...]]]]\n"
    "\n"

    "b) With a temporary database:\n"
    "\n"
    "\tidascript script.(idc|py|...) [arg1 [arg2 [arg3 [...]]]]\n"
    "\n";

  printf("%s", help);
}

//-------------------------------------------------------------------------
// Opens a file and retrieves the last write time.
// This function can be used to test if a file exists by passing 'ft = NULL'
bool get_file_modified_date(const char *file, FILETIME *ft = NULL)
{
  HANDLE h = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if ( h == INVALID_HANDLE_VALUE )
  {
    memset(ft, 0, sizeof(FILETIME));
    return false;
  }
  if ( ft != NULL )
    GetFileTime(h, NULL, NULL, ft);

  CloseHandle(h);
  return true;
}

//-------------------------------------------------------------------------
// atexit handler that will pause and wait for a keypress
static void pause()
{
  printf("Press any key to continue...");
  _getch();
}

//-------------------------------------------------------------------------
// Checks if the program was executed from an existing console or a new console
// From: http://www.codeguru.com/cpp/misc/misc/consoleapps/article.php/c15893
void install_pause_at_exit()
{
  CONSOLE_SCREEN_BUFFER_INFO csbi = {0};
  HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  if ( !GetConsoleScreenBufferInfo(hStdOutput, &csbi) )
    return;

  // Check whether the cursor position is (0,0)
  if ( csbi.dwCursorPosition.X == 0 && csbi.dwCursorPosition.Y == 0 )
  {
    // By using atexit, the pause() function will be called
    // automatically when the program exits.
    atexit(pause);
  }
}

//-------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  install_pause_at_exit();

  if ( argc < 2 )
  {
    show_usage();
    return -1;
  }

  int argi = 1;
  FILETIME out_ft_before, out_ft_after;

  // Take first argument
  const char *p;
  const char *script_file;
  const char *db_file;

  // If file has no extension then we assume it is a script file
  p = strrchr(argv[argi], '.');
  if ( p == NULL )
  {
    printf("Error: Scripts must have an extension in order to determine extlang!\n");
    return -1;
  }

  // idb file?
  ++p;
  if ( strncmp(p, "idc", 3) != 0 && strnicmp(p, "id", 2) == 0 )
  {
    if ( argc < 3 )
    {
      show_usage();
      return -1;
    }
    db_file = argv[argi++];
    script_file = argv[argi];
  }
  else
  {
    db_file = "-t";
    script_file = argv[argi];
  }

  // Check if script file exists
  if ( !get_file_modified_date(script_file) )
  {
    printf("Error: script file '%s' not found!\n", script_file);
    return -2;
  }

  // Tell IDA to skip UI related updates
  putenv("TVHEADLESS=1");

  // Get output file time before executing the script
  get_file_modified_date(IDA_OUT, &out_ft_before);

  std::string cmdln = IDA_EXE " -A -S\"";
  for ( int i=argi; i<argc; i++ )
  {
    if ( strchr(argv[i], ' ') == NULL )
    {
      cmdln += argv[i];
    }
    else
    {
      cmdln += "\\\"";
      cmdln += argv[i];
      cmdln += "\\\"";
    }
    if ( i+1 < argc )
      cmdln.push_back(' ');
  }
  cmdln += "\" ";
  cmdln += db_file;
  if ( !launch_program(NULL, cmdln.c_str()) )
  {
    printf("Failed to run IDA with: %s\n", cmdln.c_str());
    return -2;
  }

  // Log file exists and has been modified?
  if ( get_file_modified_date(IDA_OUT, &out_ft_after) && memcmp(&out_ft_after, &out_ft_before, sizeof(FILETIME)) != 0 )
  {
    FILE *fp = fopen(IDA_OUT, "r");

    char line[4096];
    while ( fgets(line, sizeof(line), fp) != NULL )
      printf("%s", line);

    fclose(fp);
  }
	return 0;
}

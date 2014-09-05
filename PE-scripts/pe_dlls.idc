#include <idc.idc>

#define NO_MAIN

#include <utils.idc>
#include <pe_sections.idc>

/*
// File:
//   pe_dlls.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   Loads DLL's, associated with a particular PE executable, into the database.
//
// Note:
//   This script requires the PE_SECTIONS.IDC script.
//
//   If the script doesn't find the HEADER section then it automatically runs the PE_SECTIONS.IDC script
//   (with out asking the user).
//
//   Otherwise the script asks the user if it should run the PE_SECTIONS.IDC script.
//
// Usage:
//   Just run the script :)
//
// Fixes/additions
//   amg - ??-06-1999 - 1st version
//   amg - 18-12-2000 - Blew the dust of this old script and made the following modifications:
//                      - cleaned it up
//                      - removed large portions of it and made it use PE_SECTIONS.IDC instead.
//   amg - 18-12-2000 - added a new [custom] FirstNamedSeg(in_name)
//   amg - 15-01-2001 - the script now supports loading of DLLs specified by the user (ex. dynamically
//                      loaded DLLs).
//   amg - 28-02-2001 - bugfix: the script now correctly hooks imported functions to the import table.
//   amg - 01-03-2001 - the script can (and will) now load DLLs of DLLs, relocs are still not supported though.
//   amg - 12-03-2002 - minor structural change: doPEtables is now handled with in the LoadSections function
//
//                      Note: even though relocs are currently unsupported this is not a disadvantage when
//                            disassembling apps that use system DLLs, they usually have unique base addresses
//                            anyway (because of optimization issues and the desire not to create a copy of the
//                            DLL in the systems swap file).
//
//   amg - 13-07-2002 - interface: clarified one user message.
//   amg - 13-07-2002 - bugfix:
//                        - we now correctly recognize if a DLL has already been loaded.
//                        - we now correctly patch imports in multiple DLLs, which import the same DLL.
//                        - we now correctly patch imports in a DLL if it imports from the loaded base image.
//                        - removed reduntant call to the PE table parsing function (see pe_sections.idc:12-03-2002).
//   amg - 13-07-2002 - enhancement (actually in pe_sections.idc):
//                        - we now apply fixups to all relocated DLLs (most common relocs are supported).
//   amg - 12-08-2002 - bugfix:
//                        - better detection for end of import table
//   amg - 01-09-2002 - bugfix:
//                        - AskFile() now displays an open button instead of a save button
//   amg - 02-09-2002 - enhancement
//                        - moved utility function into utils.idc
//                            
*/

static main()
{
  auto imageBase, PEoffset, loadEXE;
  auto ask_user;
  auto fhandle;

  Message("-------------------------------------------------------------------------------\n\n");
  Message("  The DLL loader script for PE files.\n  created by Atli Gudmundsson <agudmundsson@symantec.com>\n");
  Message("\n");

  ask_user = AskYN(0, "Do you want to specify DLL(s) to load?");

  if(ask_user != 0)
  {
    auto DLL_name;

    if(ask_user == -1)
    {
      return -1;
    }

    do
    {
      DLL_name = AskStr("KERNEL32.DLL", "What is the name of the DLL (don't type in the full path)?");

      if(DLL_name == 0)
      {
        break;
      }

      imageBase = LoadSingleDLL(DLL_name);
      if(imageBase == -1)
      {
        break;
      }

      if(imageBase != 0)
      {
        if(LoadDLLs(imageBase) < 0)
        {
          break;
        }
      }

      ask_user = AskYN(1, "Do you want to load another DLL?");
    }
    while(ask_user == 1);

    return 0;
  }

  imageBase = FirstSeg();

  if((imageBase != BADADDR) && (SegName(imageBase) == PE_HEADER_SECTION_NAME))
  {
    ask_user = AskYN(0, "HEADER section found, do you want me to run the PE_SECTION.IDC script?");

    //  1 - Yes
    //  0 - No
    // -1 - Cancel

    if(ask_user == -1)
    {
      return -1;
    }
    else if(ask_user == 1)
    {
      loadEXE = 1;
    }
    else
    {
      loadEXE = 0;
    }
  }
  else
  {
    loadEXE = 1;
  }

  if(loadEXE)
  {
    imageBase = EXEload();

    if(imageBase == BADADDR)
    {
      return -1;
    }
  }

  LoadDLLs(imageBase);

  Message("\n-------------------------------------------------------------------------------\n\n");

  return 0;
}

static LoadDLLs(imageBase)
{
  auto PEoffset;
  auto importTable;
  auto BaseArray;

  auto ask_user, loadDLL;
  auto index;

  loadDLL = 1;
  ask_user = AskYN(1, "Load all DLLs associated with this one?");

  //  1 - Yes
  //  0 - No
  // -1 - Cancel

  if(ask_user < 0)
  {
    return 0;
  }

  BaseArray = CreateArray("BaseArray for DLLs");

  if(BaseArray == -1)
  {
    BaseArray = GetArrayId("BaseArray for DLLs");
    if(BaseArray == -1)
    {
      WarningMessage("ERROR:can't initialize the BaseArray");
      return -1;
    }

    DeleteArray(BaseArray); // clear all elements out of the array
  }

  index = 0;

  SetArrayLong(BaseArray, 0, imageBase);

  while(1)
  {
    imageBase = GetArrayElement(AR_LONG, BaseArray, index);
    PEoffset  = LEDword(imageBase + 0x3c);

    if(LEDword(imageBase + PEoffset) != 0x4550)
    {
      WarningMessage("ERROR:A non-PE file was specified as a DLL!");
      return -1; // unexpected
    }

    importTable = LEDword(imageBase + PEoffset + 0x80);

    if(importTable)
    {
      importTable = importTable + imageBase;

      if(SegStart(importTable) == BADADDR)
      {
        WarningMessage("  import table is not in any section (run the PE_SECTIONS.IDC script)!");
        return 0;
      }

      while(1)
      {
        auto ilt, tds, fc, name, iat;
        auto imports;
        auto DLL_name;

        ilt     = LEDword(importTable);
        tds     = LEDword(importTable + 0x04);
        fc      = LEDword(importTable + 0x08);
        name    = LEDword(importTable + 0x0c);
        iat     = LEDword(importTable + 0x10);

        if(!name || !iat)
        {
          break;
        }

        if(ilt)
        {
          imports = ilt;
        }
        else
        {
          imports = iat;
        }

        name    = name + imageBase;
        imports = imports + imageBase;
        iat     = iat + imageBase;

        DLL_name = Str(name);

        if(!ask_user)
        {
          loadDLL = AskYN(1, "Do you want me to load " + DLL_name + "?");

          //  1 - Yes
          //  0 - No
          // -1 - Cancel

          if(loadDLL < 0)
          {
            return -1;
          }
        }

        if(loadDLL)
        {
          auto DLLBase;

          DLLBase = LoadSingleDLL(DLL_name);

          // Add

          if(DLLBase == -1)
          {
            if(ask_user)
            {
              ask_user = AskYN(1, "Some error occured, do you still want to load all DLLs?");

              //  1 - Yes
              //  0 - No
              // -1 - Cancel

              if(ask_user < 0)
              {
                return;
              }
            }

            DLLBase = 0;
          }

          if(DLLBase != 0)
          {
            auto travel, last;

            travel = 0;
            last = GetLastIndex(AR_LONG, BaseArray);

            while(travel <= last)
            {
              if(GetArrayElement(AR_LONG, BaseArray, travel) == DLLBase)
              {
                break;
              }

              travel++;
            }

            if(travel > last)
            {
              // no match was found, so add it for later parsing

              SetArrayLong(BaseArray, GetLastIndex(AR_LONG, BaseArray) + 1, DLLBase);
            }
          }

          if(DLLBase != 0)
          {
            auto importAddress;
            auto FuncName;

            // fix the import table of the current DLL.

            importAddress = LEDword(imports);

            if(importAddress)
            {
              do
              {
                if(importAddress < 0)
                {
                  // import by ordinal

                  importAddress = importAddress & 0x7fffffff;
                  importAddress = GetProcAddress(DLLBase, "", importAddress);
                }
                else
                {
                  // import by name

                  importAddress = importAddress + imageBase + 2;

                  FuncName = Str(importAddress);

                  importAddress = GetProcAddress(DLLBase, FuncName, 0);
                }

                if(importAddress != 0)
                {
                  PatchDword(iat, importAddress);
                  OpOff(iat, 0, 0);
//                  MakeCode(importAddress); // already taken care of by the doExportTable
                }
                // else // silently ignore this case... the most likely cause for this is that the import
                // {    // table has already been patched (the script is being re-executed)...
                //  MakeComm(iat, "Can't resolve to this address!");
                // }

                iat     = iat + 4;
                imports = imports + 4;

                importAddress = LEDword(imports);
              }
              while(importAddress);
            }
          }
        }

        importTable = importTable + 0x14;
      }
    }

    if(GetLastIndex(AR_LONG, BaseArray) == index++)
    {
      break;
    }
  }

  DeleteArray(BaseArray);
}

static GetProcAddress(DLLBase, ProcName, ordinal)
{
  auto PEoffset;
  auto exportTable;

  auto ord_base, num_at, num_np, at, np, ot;

  auto retval;

  PEoffset = LEDword(DLLBase + 0x3c) + DLLBase;

  exportTable = LEDword(PEoffset + 0x78) + DLLBase;

  if(SegStart(exportTable) == BADADDR)
  {
    WarningMessage("  export table is not in any section (run the PE_SECTIONS.IDC script on this DLL)!\n");
    return 0;
  }

  ord_base  = LEDword(exportTable + 0x10);
  num_at    = LEDword(exportTable + 0x14);
  num_np    = LEDword(exportTable + 0x18);
  at        = LEDword(exportTable + 0x1c) + DLLBase;
  np        = LEDword(exportTable + 0x20) + DLLBase;
  ot        = LEDword(exportTable + 0x24) + DLLBase;

  if(ProcName != "")
  {
    auto at_proc_name;
    auto pStr;

    // we must find the ordinal number for the requested proc name

    while(num_np)
    {
      pStr = LEDword(np) + DLLBase;

      at_proc_name = Str(pStr);

      if(ProcName == at_proc_name)
      {
        ordinal = LEWord(ot) + ord_base;
        break;
      }

      np = np + 4;
      ot = ot + 2;

      num_np--;
    }

    if(!num_np)
    {
      return 0;
    }
  }

  if(ordinal < ord_base)
  {
    return 0;
  }

  ordinal = ordinal - ord_base;

  if(ordinal >= num_at)
  {
    return 0;
  }

  retval = LEDword(at + ordinal*4) + DLLBase;

  // for later: do forwarder chain parsing...

  return retval;
}

static CleanDLLName(DLL_name)
{
  auto retval;

  retval = "";

  if(DLL_name != "")
  {
    auto i, str_len;

    str_len = strlen(DLL_name);
    i = 0;

    do
    {
      auto letter, sub_str;

      sub_str = substr(DLL_name, i, i+1);

      if((sub_str != ".") && ((sub_str < "0") || ((sub_str > "9") && (sub_str < "A") || (sub_str > "Z") && ((sub_str < "a") || (sub_str > "z")))))
      {
        sub_str = "_";
      }
      else if((sub_str >= "a") && (sub_str <= "z"))
      {
        sub_str = toupper(sub_str);
      }

      retval = retval + sub_str;

      i++;
    }
    while(i != str_len);
  }

#if defined(DEBUG_THIS)
  WarningMessage(form("CleanDLLName: %s --> %s\n", DLL_name, retval));
#endif

  return retval;
}

static LoadSingleDLL(DLL_name)
{
  auto DLLBase, PEoffset, MZ_signature, PE_signature;
  auto fhandle;
  auto current;

  DLL_name = CleanDLLName(DLL_name);
  DLLBase = FirstNamedSeg(DLL_name + DLL_SEPERATOR + PE_HEADER_SECTION_NAME);

  if((DLLBase == BADADDR) && (DLL_name == GetInputFile()))
  {
    DLLBase = FirstNamedSeg(PE_HEADER_SECTION_NAME);
  }

  if(DLLBase != BADADDR)
  {
    // DLL already loaded...
    Message("  " + DLL_name + form(" already loaded at address %.8x\n", DLLBase));
    return DLLBase; // must return the DLL image base
  }

  fhandle = fopen(DLL_name, "rb");
  current = DLL_name;

  while(fhandle == 0)
  {
    current = AskFile(0, current, "Please find " + DLL_name + " for me.");

    if(current == 0)
    {
      Message("  User didn't find " + DLL_name + "\n");
      return -1;
    }

    fhandle = fopen(current, "rb");
  }

  // fhandle contains a valid handle to an open file.

  if(MySeek(fhandle, 0, 0) != 0)
  {
    return -1;
  }

  Message("  " + DLL_name + " load information\n\n");

  MZ_signature = readshort(fhandle, 0);

  if((MZ_signature != 0x4d5a) && (MZ_signature != 0x5a4d))
  {
    WarningMessage("This is not an MZ executable!");
    return -1;
  }

  MySeek(fhandle, 0x3c, 0);
  PEoffset = readlong(fhandle, 0);

  MySeek(fhandle, PEoffset, 0);
  PE_signature = readlong(fhandle, 0);

  if(PE_signature == 0x4550)
  {
    DLLBase = LoadSections(fhandle, PEoffset, DLL_name);
  }
  else
  {
    WarningMessage("This is not a PE executable!");
    return -1;
  }

  fclose(fhandle);
  return DLLBase;
}

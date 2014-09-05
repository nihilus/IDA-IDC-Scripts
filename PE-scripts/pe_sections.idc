#include <idc.idc>

/*
// File:
//   pe_sections.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   parses the input file and if it is a PE executable does the following:
//   - Loads and creates a HEADER section that corresponds to the PE file header.
//   - Creates the MZ and PE header structures at the correct place in the header.
//     - All fields in the structures, that contain a non zero offset, are resolved.
//   - Creates the PE section structures at the correct place in the header.
//   - Loads and creates all possible sections.
//   - Creates table data structures.  Those currently recognizes are:
//
//     - the export table.
//     - the import table.
//     - the resource table (bare format).
//     - the debug table.
//     - the relocs table.
//     - the tls table.
//     - the bound import table
//
// Note:
//   Be sure to uncheck the 'Make imports section' option, when loading the file for the first time.
//   Otherwise most of the data in the import section will be invisible.
//
//   Can be unchecked by default from IDA.CFG by specifying PE_MAKE_IDATA = NO.
//
// Usage:
//   Just run the script ;).
//
// Fixes/additions
//   amg - ??-06-1999 - 1st version.
//   amg - 06-03-2000 - a total rewrite, merging two scripts (pe_header.idc --> pe_section.idc),
//                      also added some comments.
//   amg - 07-03-2000 - added xrefs in to the structures (see above) so that you can now travel
//                      from one structure to the next (e.g. from the MZ header to the PE header)
//                      This doesn't work for versions less than or equal to v4.02, but it
//                      won't cause any errors either...
//   amg - 01-08-2000 - added an #ifdef because of function incompatability between new and old 
//                      versions of IDA.
//   amg - 01-08-2000 - a major rewrite.  The script now loads all sections possible.
//   amg - 06-08-2000 - added some information messages.
//   amg - 06-08-2000 - the script now recognizes when a previously loaded section is interfering
//                      with the loading of another section and tries to fix that.
//   amg - 21-08-2000 - added information about the entry (what it is and in which section)
//   amg - 21-08-2000 - added more information messages.
//   amg - 29-08-2000 - some bug fixes.
//   amg - 30-08-2000 - added support for parsing the header tables.
//   amg - 18-09-2000 - resource table added (bare format).
//   amg - 18-09-2000 - some bug fixes.
//   amg - 21-09-2000 - fixed a minor overside when I was optimizing the script last time ;)
//                      I forgot to enforce the loading of the HEADER section, silly me :)
//                      anyway, fixed.
//   amg - 21-09-2000 - added a coooool banner that is displayed in the message output.
//   amg - 25-09-2000 - we now force the creation of all structures, overstepping some problems
//                      where IDA has already declared a data element in the middle of the structure.
//   amg - 25-09-2000 - the TimeStamp function ULDateToStr() now supports times stamps with the high bit set.
//   amg - 25-09-2000 - the script now recognizes when there is no entrypoint in the file.
//   amg - 26-09-2000 - the script now parses the relocs tables correctly, even though some of the
//                      page entries look broken.
//   amg - 09-10-2000 - if the header physical size is too small then we just use the virtual size instead.
//   amg - 09-10-2000 - names are now created correctly, when requested (overlapping datastructures are destroyed).
//   amg - 17-10-2000 - we can now see where each section ends in the file.
//   amg - 02-11-2000 - export ordinal comments are now correct (base added)
//   amg - 03-11-2000 - we now create all structures, always.  Helps debugging apps.
//   amg - 03-11-2000 - tls table added.
//   amg - 05-11-2000 - minor fixes:
//                       - to the date function (ULDateToStr()).
//                       - to the export handling.
//   amg - 06-11-2000 - minor enhancement:
//                       - to the import handling (zero terminated entries).
//   amg - 09-11-2000 - added some minor comments to the section flags.
//   amg - 10-11-2000 - the script now:
//                       - skips a particular table if the user presses No.
//                       - stops parsing tables if the user presses Esc/Cancel.
//   amg - 10-11-2000 - fixed the TLS parsing code, we no longer assume we have a callbacks array pointer.
//   amg - 10-11-2000 - added better support for user termination requests, when parsing individual tables.
//   amg - 14-11-2000 - the script now handles correctly invalid reloc tables, in regard to when finding empty entries in the table.
//   amg - 15-11-2000 - the script now displays a message when ever it detects extra data after the image.
//   amg - 21-11-2000 - the script now uses a custom Dword() function (LEDword()) since the old one returns 0xff in
//                      those bytes which would reference into undefined segment memory.
//   amg - 21-11-2000 - we now display a warning if the TLS contains callbacks.
//   amg - 28-11-2000 - fixed the physical size, when loading sections, it is now adjusted to the file alignment.
//   amg - 14-12-2000 - we now use GetInputFilePath() instead of GetInputFile(), to get the location of the original file.
//   amg - 18-12-2000 - major modifications (to support the PE_DLLS.IDC script):
//                      - added a NO_MAIN ifdef so that the script can be called from another script.
//                      - added a prefix variable (called DLL_name) to all functions.
//   amg - 15-01-2001 - added some error checking, regarding section creation. (more is needed though)
//   amg - 28-02-2001 - fixed some bugs
//                      - a most embarrassing bug... forgot a return in the LEWord() function.
//                      - the above fix exposed another bug in the doResourceTable() function... fixed.
//   amg - 28-02-2001 - the script now creates a function and a name on all exports which have no name,
//                      this allows the script to work better with the PE_DLLS.IDC script.
//   amg - 01-03-2001 - the script no longer gives the user the option of selecting which tables to load,
//                      all tables are loaded by default.
//   amg - 06-03-2001 - the script no longer tries to make forwarder entries in the export table into functions,
//                      instead it makes them into strings.
//   amg - 25-04-2001 - the script now supports 'strange' section values, such as when the first section in the
//                      section table is realy the last section in the file.
//   amg - 25-04-2001 - IDA may occasionaly change the default string type from ASCII to something else (such as
//                      PASCAL), this would play havoc with the strings created by the script.  The script now
//                      bypasses this behaviour, with out affecting IDA.
//   amg - 01-05-2001 - re-enabled the asking of whether to load all tables (see change at 01-03-2001), but this time it is
//                      #ifdefed (Should help when analyzing weird script errors)
//   amg - 01-05-2001 - adjusted the import parsing code so that it would actualy terminate the import directory correctly.
//   amg - 02-05-2001 - the script is no longer fooled by sections which have a very high RVA (2G+), when determining the
//                      header virtual size.
//   amg - 02-05-2001 - the script now conforms to IDAs way of things when creating section names (replacing spaces with '_')
//   amg - 22-05-2001 - the script now behaves correctly when creating sections with ":" in the name, leaving them in there.
//                      note: this bug would not allow the pe_dlls.idc script to recognize already loaded DLLs (sections)
//   amg - 28-05-2001 - bugfix: if all sections vSizes were zero then the HEADER size would be 0x7fffffff.
//   amg - 14-06-2001 - bugfix: if phyAddr was 0 and phySize was not then the section was loaded with the header data.
//                              - windows actualy takes phyAddr == 0 to mean that phySize is also 0
//                              - additional research revealed that windows truncates phyAddr to a 200h boundary.
//                                this means that if (0 < phyAddr < 200h) and (phySize != 0) then the section will be
//                                loaded with the header data.
//   amg - 14-06-2001 - interface: minor adjustments to the output of the script (made it more understandable (hopefully ;))
//   amg - 22-07-2001 - bound import table now included.
//   amg - 04-08-2001 - PE2 format now supported (PE32+ if you will :).
//                      note: due to IDA limitations the image base is handled as a 32-bit value (high 32-bits are ignored)
//   amg - 04-08-2001 - debug directory now supported.
//   amg - 07-08-2001 - bugfix: bound import table seems to be constructed of {DWORD, WORD, WORD} nibbles
//   amg - 19-08-2001 - bugfix: Native subsystem now behaves correctly in regards to non-sector aligned sections
//   amg - 28-08-2001 - bugfix: some runtime packers pack the export table.  This would cause the script to go into a very long loop.
//   amg - 02-09-2001 - bugfix: the script now asks the user what it should do when it encounters files with weird section offsets.
//   amg - 02-09-2001 - interface: image flags will now be different for multivalue flags (reversing all bits when cleared)
//   amg - 12-10-2001 - interface: image flags will now be of the following form: mask - bits - info
//   amg - 14-10-2001 - interface: if the script encounters a HEADER section it will ask the user if he wants to refresh the section data.
//   amg - 14-10-2001 - interface: the script now detects if there is a .reloc section but no relocs and asks if it should try to parse
//                      it for relocs.
//   amg - 14-10-2001 - bugfix: the script is now fully PE2 compliant (any future bugs aside ;)
//   amg - 28-10-2001 - bugfix: in Windows 00000000 as an EP is valid, but only if the image is a non-DLL
//   amg - 28-10-2001 - interface: image flags will now be of the following form: mask - bit state - info
//                        you can see I'm having trouble with this one (what do you think is the best one so far ? :)
//   amg - 26-11-2001 - bugfix: Windows does not care about the size field of the resource table
//   amg - 26-11-2001 - bugfix: TLS code now correctly displays the TLS directory (instead of most of the time leaving it undefined)
//   amg - 28-11-2001 - bugfix: offset values are now taken into account when adjusting section sizes to alignment values
//   amg - 04-02-2002 - interface: we now add the correct name of an export as a comment (in the export table) if needed.
//   amg - 12-03-2002 - minor structural change: doPEtables is now handled with in the LoadSections function
//   amg - 12-03-2002 - bugfix: the header structures (MZ, PE) are now created after everything else is done.
//                              otherwise some tables might actually 'destroy' them...
//   amg - 05-04-2002 - enhancement: changed name of ULDToStr() to ULDateToStr()
//                                   created ULDosDateToStr()
//   amg - 05-04-2002 - enhancement: we now display Borlands [DOS] time along with Microsoft time for the timestamp field in the pe header.
//   amg - 17-05-2002 - enhancement: loading of the image is now in a seperate function (i.e. EXEload()), to better support secondary scripts
//                                   that want to use this one (e.g. the pe_dlls.idc script).
//   amg - 13-07-2002 - bugfix:
//                        - introduced a define for the DLL name seperator (used in pe_dlls.idc as well).
//                        - we now display the VA for the entry point correctly in PE2 images.
//                        - we now, correctly, recognize an EP==0 in the HEADER section.
//                        - better reporting of strangely terminated relocs
//   amg - 13-07-2002 - enhancement:
//                        - we now resolve DLL address collisions (when called from pe_dlls.idc),
//                          loading the second DLL at a different (free) location.
//                        - we now apply fixups to all relocated DLLs (most common relocs are supported).
//   amg - 15-07-2002 - bugfix:
//                        - IDA prefixes sections names with an underscore '_' if it starts with a number, section creation now recognizes this.
//                        - we now recognize a corrupted section count field (too high a value).
//   amg - 15-07-2002 - bugfix:
//                        - addition of image base to 64-bit relocations is now applied correctly (detecting any carry).
//   amg - 12-08-2002 - bugfix:
//                        - ILT code nolonger overwrites first entry of IAT if there is no ILT.
//                        - better detection for end of import table
//                      enhancement:
//                        - Imported names are now applied to individual import table entries,
//                          but only if there is no name there already and if it isn't an ordinal import.
//   amg - 01-09-2002 - bugfix:
//                        - AskFile() now displays an open button instead of a save button
//                        - doImportTable now correctly adds the name of loaded DLL to the import names, if being called from within pe_dlls.idc
//                        - replaced all MakeFunction() calls with MakeCode(), since MakeFunction() fails to create code if the destionation is
//                          already within a function boundary
//                        - we now better resolve name collitions in DLLs that import from the same DLL
//                      enhancement:
//                        - some minor optimizations, mostly moving memory reads and arithmetics outside of loops
//                        - we now name any function that is exported via ordinal only, in secondary DLLs
//                        - we now create code at the EP for secondary DLLs being loaded from within pe_dlls.idc
//   amg - 02-09-2002 - enhancement
//                        - moved utility functions into utils.idc
//   amg - 04-09-2002 - enhancement
//                        - we now set the default segment selector of segment registers in created segments to zero,
//                          this will allow offsets to be used automatically
//   amg - 23-10-2002 - bugfix:
//                        - we no longer try to parse corrupted import tables forever
//                        - we also report to the user if we find such a case
//   amg - 14-11-2002 - bugfix:
//                        - we now use the function AddEntryPoint() instead of MakeCode()
//                          - this will create the name, code and function in one go
//                        - we now define the [start] entry point if it doesn't exist already
//                        - TLS callbacks table is now correctly filled with offsets
//   amg - 14-11-2002 - enhancement:
//                        - when parsing and creating the TLS we now use the same names as IDA does
//
*/

// Uncomment the following line to allow the user to choose which tables to parse (good for script debugging).
// #define DEBUG_ASK_TABLES

#define MZ_HEADER_STRUCTURE_NAME  "S_MZ_HEADER"
#define PE_HEADER_STRUCTURE_NAME  "S_PE_HEADER"
#define PE_SECTION_STRUCTURE_NAME "S_PE_SECTION"

#define PE_HEADER_SECTION_NAME    "HEADER"
#define DLL_SEPERATOR             "_"

// The following define is no longer supported:
//
//#define IDA_IS_OLD
//
//   comment the above line if you are using v3.85+
// uncomment the above line if you are using pre v3.85

#include <utils.idc>

#ifndef NO_MAIN

static main(void)
{
  return EXEload();
}

#endif

static EXEload(void)
{
  auto fhandle;
  auto MZ_signature, PE_signature;
  auto current;
  auto PEoffset, imageBase;

  auto error;

  error = 0;

  Message("-------------------------------------------------------------------------------\n\n");
  Message("  The PE header parser script.\n  Created by Atli Gudmundsson <agudmundsson@symantec.com>\n");
  Message("\n");

  current = GetInputFilePath();
  fhandle = fopen(current, "rb");

  while(fhandle == 0)
  {
#ifdef IDA_IS_OLD
    current = AskFile(current, "Please find the file for me");
#else
    current = AskFile(0, current, "Please find the file for me");
#endif
    if(current == 0)
    {
      error = -1;
      break;
    }

    fhandle = fopen(current, "rb");
  }

  // fhandle contains a valid handle to an open file.

  while(!error)
  {
    if(MySeek(fhandle, 0, 0) != 0)
    {
      error = -1;
      break;
    }

    MZ_signature = readshort(fhandle, 0);

    if((MZ_signature != 0x4d5a) && (MZ_signature != 0x5a4d))
    {
      WarningMessage("This is not an MZ executable!");
      error = -1;
      break;
    }

    MySeek(fhandle, 0x3c, 0);
    PEoffset = readlong(fhandle, 0);

    MySeek(fhandle, PEoffset, 0);
    PE_signature = readlong(fhandle, 0);

    if(PE_signature == 0x4550)
    {
      imageBase = LoadSections(fhandle, PEoffset, "");
      if(imageBase == -1)
      {
        error = -1;
      }

      break;
    }
    else
    {
      WarningMessage("This is not a PE executable!");
      error = -1;
      break;
    }
  }

  fclose(fhandle);

  if(!error)
  {
    return imageBase;
  }
  else
  {
    return BADADDR;
  }
}

static CleanSectName(sect_name)
{
  auto retval;

  retval = "";

  if(sect_name != "")
  {
    auto i, str_len;

    str_len = strlen(sect_name);
    i = 0;

    do
    {
      auto letter, sub_str;

      sub_str = substr(sect_name, i, i+1);

      if((sub_str != ":") && (sub_str != ".") && ((sub_str < "0") || ((sub_str > "9") && (sub_str < "A") || (sub_str > "Z") && ((sub_str < "a") || (sub_str > "z")))))
      {
        sub_str = "_";
      }

      retval = retval + sub_str;

      i++;
    }
    while(i != str_len);
  }

  return retval;
}

/*
// Function:
//   CreateSection
// Purpose:
//   Creates a virtual section, expanding or adjusting already existing sections
//   as needed.
// Input:
//   SectionName
//   SectionStart  - VA of the start of the section
//   vSize         - the requested virtual size of the section
//   phyAddr       - offset of this sections physical block, in the file
//   phySize       - size of this sections physical block, in the file
//   loadData      - specifies wether the function should actually read the data from the file.
// Returns:
//   nothing
// Notes:
//   The function also prints messages that tell the user if anything unusual happend.
*/
static CreateSection(fhandle, SectionName, SectionStart, vSize, phyAddr, phySize, loadData)
{
  auto SectionBase;
  auto question, answer;

  SectionName = CleanSectName(SectionName);

#if defined(DEBUG_THIS)
  Message(form("%s: [%08X, %08X] --> [%08X, %08X]\n", SectionName, phyAddr, phySize, SectionStart, vSize));
#endif

  SectionBase = SectionStart;

  if(vSize != 0)
  {
    auto SectionEnd;

    SectionEnd = SectionStart + vSize;

    while(SectionStart < SectionEnd)
    {
      if(SegStart(SectionStart) != BADADDR)
      {
        // A section, at the specified address, already exists.

        if((SegName(SectionStart) == SectionName) || (SegName(SectionStart) == "_" + SectionName)) // if name starts with a number then IDA prefixes it with an '_'
        {
          // A section with the given name already exists at this address.

          if(SegEnd(SectionStart) >= SectionEnd)
          {
            // cool, nothing more needed

            Message("  %s (%.8X - %.8X) section already exists.\n", SegName(SectionStart), SegStart(SectionStart), SegEnd(SectionStart));

            if((SegStart(SectionStart) != SectionStart) || (SegEnd(SectionStart) != SectionEnd))
            {
              Message("  and already spans the addresses (%.8X - %.8X).\n", SectionStart, SectionEnd);
            }

            SectionStart = SectionEnd;
            break;
          }
          else
          {
            // must expand the section upwards.

            SegBounds(SectionStart, SegStart(SectionStart), SectionEnd, 1);
            SegRename(SectionStart, SectionName);

            Message("  %s section found at %.8X, expanded to (%.8X - %.8X).\n", SectionName, SectionStart, SegStart(SectionStart), SegEnd(SectionStart));
          }
        }
        else
        {
          // An unknown section, at the specified address, already exists.
          Message("  %s (%.8X - %.8X) section already spans the address %.8X.\n", SegName(SectionStart), SegStart(SectionStart), SegEnd(SectionStart), SectionStart);
          Message("  %s created at the next available address.\n", SectionName);

          SectionStart = SegEnd(SectionStart);
          continue;
        }
      }
      else
      {
        // no section has this start address in itself.

        SegCreate(SectionStart, SectionEnd, 0, 1, saRelPara, scPub);
        SegRename(SectionStart, SectionName);

        SegDefReg(SectionStart, "es", 0);
        SegDefReg(SectionStart, "ds", 0);
        SegDefReg(SectionStart, "ss", 0);
        SegDefReg(SectionStart, "fs", 0);
        SegDefReg(SectionStart, "gs", 0);
      }

      // SectionStart is always inside a section at this point
      // SegEnd(SectionStart) == SectionEnd OR SegEnd(SectionStart) is inside a section

      if(SegEnd(SectionStart) < SectionEnd)
      {
        auto temp;

        // hmmm, unable to do the entire segment
        // must have another segment interfering

        temp = SegEnd(SectionStart);

        if(SegName(temp) == SectionName)
        {
          // they have the same names, so let's merge them

          SegDelete(SectionStart, 0);
          Message("  %s section found at %.8X, expanding down to (%.8X - %.8X).\n", SectionName, temp, SectionStart, SegEnd(temp));

          SegBounds(temp, SectionStart, SegEnd(temp), 1);
          SegRename(SectionStart, SectionName);

          // next iteration will take care of the upper boundary.
        }
        else
        {
          // a different name, let's skip it (note: must preserve what ever is already there)

          Message("  error: %s section (%.8X - %.8X) is interfering.\n", SegName(temp), temp, SegEnd(temp));

          if(SegEnd(temp) < SectionEnd)
          {
            Message("\n  splitting %s up, will try to create a new block at (%.8X - %.8X).\n", SectionName, SegEnd(temp), SectionEnd);
            SectionStart = SegEnd(temp);
          }
          else
          {
            // we are done
            SectionStart = SectionEnd;
            break;
          }
        }
      }
      else
      {
        // cool, nothing more needed
        SectionStart = SectionEnd;
        break;
      }
    }
  }
  else
  {
    Message("  WARNING: Sections virtual size is zero, can't create");
  }

  if(phySize != 0)
  {
    if(vSize < phySize)
    {
      phySize = vSize;
    }

    if(loadData)
    {
      loadfile(fhandle, phyAddr, SectionBase, phySize);
    }
  }
}

static LoadSections(fhandle, PEoffset, DLL_name)
{
  auto i, k, flags;
  auto comment, commentTimeStamp, findString;
  auto headerPSize, headerVSize, imageBase, imageBase2;
  auto numberSections, NTheaderSize, PEsections;
  auto fileSize;
  auto PEentry;
  auto SectionAlignment, FileAlignment;
  auto LargestPhysical;
  auto PEtype;
  auto subsystem;
  auto strange_alignment;
  auto load_section_data;
  auto tables_error;
  auto TimeStamp;
  auto already_loaded;
  auto actualImageSize;
  auto DLLflags;
  auto imageDelta;

  strange_alignment = 0;
  load_section_data = 1;
  already_loaded    = 1;

  if(DLL_name != "")
  {
    DLL_name = DLL_name + DLL_SEPERATOR;
    already_loaded = 0;
  }

  if(FirstNamedSeg(DLL_name + PE_HEADER_SECTION_NAME) != BADADDR)
  {
    load_section_data = AskYN(0, "Do you want me to reload the section data?");

    // -1 - we return from this function.
    //  0 - we don't reload any section data, but we still apply the script in any other way.
    //  1 - we reload all section data.

    if(load_section_data < 0)
    {
      return -1;
    }

    already_loaded = 1;
  }

  LargestPhysical = 0;

  Message("-------------------------------------------------------------------------------\n\n");

  MySeek(fhandle, PEoffset + 0x18, 0);
  PEtype = readshort(fhandle, 0);

  fseek(fhandle, PEoffset + 0x54, 0);
  headerPSize = readlong(fhandle, 0);

  if(PEtype != 0x20b)
  {
    Message("Found PE header of size %.8X at file offset %.8X:\n\n", headerPSize, PEoffset);
  }
  else
  {
    Message("Found PE2 header of size %.8X at file offset %.8X:\n\n", headerPSize, PEoffset);
  }

  fileSize = filelength(fhandle);
  if(fileSize == -1)
  {
    WarningMessage("Unable to get the file size!");
  }

  Message("- file size:                %.8X (%d bytes)\n\n", fileSize, fileSize);
  
  MySeek(fhandle, PEoffset + 0x4, 0);
  i = readshort(fhandle,0);

  if(i == 0)
  {
    comment = "applicable to all cpu's";
  }
  else
  {
    k = i & 0xff;
    i = i >> 8;

    if(k == 0x84)
    {
      comment = "Alpha AXP";

      if(i == 2)
      {
        comment = comment + " 64-bit";
      }
    }
    else if((k == 0) || (k == 0x4c))
    {
      comment = "intel " + ((k == 0) ? "IA64" : "386+");
    }
    else 
    {
      // to lasy to do the rest, since I rarely encounter them... :)

      comment = "unrecognized";
    }
  }

  Message("- required cpu type:        " + comment + "\n");

  MySeek(fhandle, PEoffset + 0x5c, 0);
  subsystem = readshort(fhandle,0);

  if(subsystem == 1)
  {
    comment = "Native (doesn't require a subsystem)";
  }
  else if(subsystem == 2)
  {
    comment = "Windows GUI";
  }
  else if(subsystem == 3)
  {
    comment = "Windows character";
  }
  else if(subsystem == 7)
  {
    comment = "POSIX character";
  }
  else if(subsystem == 9)
  {
    comment = "Windows CE";
  }
  else if(subsystem == 10)
  {
    comment = "EFI application";
  }
  else if(subsystem == 11)
  {
    comment = "EFI boot service driver";
  }
  else if(subsystem == 12)
  {
    comment = "EFI runtime service driver";
  }
  else
  {
    comment = "unknown";
  }

  Message("- required subsystem:       " + comment + "\n");

  MySeek(fhandle, PEoffset + 0x8, 0);
  TimeStamp = readlong(fhandle, 0);

  commentTimeStamp = "Microsoft(" + ULDateToStr(TimeStamp) + "), Borland(" + ULDosDateToStr(TimeStamp) + ")";
  Message("- time stamp:               " + commentTimeStamp + "\n");
  commentTimeStamp = "time stamp: " + commentTimeStamp;

  fseek(fhandle, PEoffset + 0x30, 0);

  imageBase   = readlong(fhandle, 0);
  imageBase2  = readlong(fhandle, 0);

  Message("- image base:               ");

  if(PEtype != 0x20b)
  {
    imageBase   = imageBase2;
    imageBase2  = 0;

    Message("%.8X\n", imageBase);
  }
  else
  {
    Message("%.8X%.8X\n", imageBase2, imageBase);
  }

  fseek(fhandle, PEoffset + 0x38, 0);
  SectionAlignment = readlong(fhandle, 0);

  Message("- Section alignment:        %.8X\n", SectionAlignment);

  if(SectionAlignment != (SectionAlignment & ~(SectionAlignment - 1)))
  {
    Message("  * WARNING: SectionAlignment is strange\n");
  }

  if(SectionAlignment > 0x100000)
  {
    Message("  * ERROR: SectionAlignment is 1M+, using 200h instead.\n");

    SectionAlignment = 0x200;
  }

  fseek(fhandle, PEoffset + 0x3C, 0);
  FileAlignment = readlong(fhandle, 0);

  if(!SectionAlignment)
  {
    if(FileAlignment)
    {
      SectionAlignment = FileAlignment;
      Message("  using file alignment instead (%.8X)\n", FileAlignment);
    }
    else
    {
      Message("  file alignment is also zero, using default value of 0x200.\n");
      SectionAlignment = 0x200; // Mustn't divide by zero.
    }
  }

  Message("- File alignment:           %.8X\n", FileAlignment);

  if(!FileAlignment)
  {
    Message("  file alignment is zero, using section alignment instead.\n");
    FileAlignment = SectionAlignment;
  }

  if(FileAlignment != (FileAlignment & ~(FileAlignment - 1)))
  {
    Message("  * WARNING: FileAlignment is strange\n");
  }

  if(FileAlignment > 0x100000)
  {
    Message("  * ERROR: FileAlignment is 1M+, using 512 instead.\n");

    FileAlignment = 512;
  }

  MySeek(fhandle, PEoffset + 0x28, 0);
  PEentry = readlong(fhandle,0);

  MySeek(fhandle, PEoffset + 0x6, 0);
  numberSections = readshort(fhandle, 0);

  MySeek(fhandle, PEoffset + 0x14, 0);
  NTheaderSize = readshort(fhandle, 0);

  PEsections = PEoffset + NTheaderSize + 0x18;

  MySeek(fhandle, PEoffset + 0x16, 0);
  flags = readshort(fhandle, 0);

  Message("- entry point:              ");

  if(PEentry || !(flags & 0x2000))
  {
    if(PEtype != 0x20b)
    {
      Message("%.8X (%.8X)\n", PEentry, PEentry + imageBase);
    }
    else
    {
      auto temp_lower, temp_higher;

      temp_higher = imageBase2;
      temp_lower  = PEentry + imageBase;

      if(temp_lower < PEentry)
      {
        temp_higher = temp_higher + 1;
      }

      Message("%.8X (%.8X%.8X)\n", PEentry, temp_higher, temp_lower);
    }
  }
  else
  {
    Message("not present\n");
  }

  Message("\n- image flags (%.4X):\n", flags);

  comment = "";

  if(flags & 0x0001)
  {
    comment = comment + "\n    0x0001 - 1 - relocs stripped";
  }

  comment = comment + "\n    0x0002 - " + ((flags & 0x0002) ? "1 - executable" : "0 - invalid") + " image";

  if(flags & 0x0004)
  {
    comment = comment + "\n    0x0004 - 1 - COFF line numbers stripped";
  }

  if(flags & 0x0008)
  {
    comment = comment + "\n    0x0008 - 1 - COFF symbols stripped";
  }

  if(flags & 0x0010)
  {
    comment = comment + "\n    0x0010 - 1 - OS is supposed to aggressively trim working set";
  }

  if(flags & 0x0020)
  {
    comment = comment + "\n    0x0020 - 1 - Application can handle 2GB+ addresses";
  }

  if(flags & 0x0040)
  {
    comment = comment + "\n    0x0040 - 1 - 16-bit word architecture (reserved)";
  }

  comment = comment + "\n    0x0080 - " + ((flags & 0x0080) ? "1 - big" : "0 - little") + " endian byte order";

  if(flags & 0x0100)
  {
    comment = comment + "\n    0x0100 - 1 - 32-bit word architecture";
  }

  if(flags & 0x0200)
  {
    comment = comment + "\n    0x0200 - 1 - debug information stripped";
  }

  if(flags & 0x0400)
  {
    comment = comment + "\n    0x0400 - 1 - copy and run image from swap file (if on removable media)";
  }

  if(flags & 0x0800)
  {
    comment = comment + "\n    0x0800 - 1 - copy and run image from swap file (if remote)";
  }

  if(flags & 0x1000)
  {
    comment = comment + "\n    0x1000 - 1 - system file";
  }

  comment = comment + "\n    0x2000 - " + ((flags & 0x2000) ? "1 - Dynamic Link Library (DLL)" : "0 - Executable (EXE)");

  if(flags & 0x4000)
  {
    comment = comment + "\n    0x4000 - 1 - run only on uniprocessor machines";
  }

  comment = comment + "\n    0x8000 - " + ((flags & 0x8000) ? "1 - big" : "0 - little") + " endian word order";

  Message(comment + "\n\n");

  MySeek(fhandle, PEoffset + 0x5e, 0);
  DLLflags = readshort(fhandle, 0);

  if(DLLflags != 0)
  {
    Message("- DLL flags (loader requirements) (%.4X):\n", DLLflags);

    comment = "";

    if(DLLflags & 0x0001)
    {
      comment = comment + "\n    0x0001 - per-process library initialization (reserved)";
    }
    if(DLLflags & 0x0002)
    {
      comment = comment + "\n    0x0002 - per-process library termination (reserved)";
    }
    if(DLLflags & 0x0004)
    {
      comment = comment + "\n    0x0004 - per-thread library initialization (reserved)";
    }
    if(DLLflags & 0x0008)
    {
      comment = comment + "\n    0x0008 - per-thread library termination (reserved)";
    }
    if(DLLflags & 0x0800)
    {
      comment = comment + "\n    0x0800 - do not bind image";
    }
    if(DLLflags & 0x2000)
    {
      comment = comment + "\n    0x2000 - driver is a WDM driver";
    }
    if(DLLflags & 0x8000)
    {
      comment = comment + "\n    0x8000 - image is terminal server aware";
    }

    Message(comment + "\n\n");
  }

  Message("- %d sections (excluding header) found at file offset %.8X:\n\n", numberSections, PEsections);

  headerVSize = 0x7fffffff; // largest long (just below the 2G limit)

  actualImageSize = 0;

  for(i = 0; i < numberSections; i++)
  {
    auto valid, baseRVA;

    MySeek(fhandle, PEsections + 0x28*i + 8, 0); // the vSize field of the section

    valid   = readlong(fhandle, 0);
    baseRVA = readlong(fhandle, 0);

    if(!valid)
    {
      // vSize is zero.  Windows just uses pSize instead and so will we.
      valid = readlong(fhandle, 0); // the pSize field of the section
    }

    if(!baseRVA)
    {
      auto phyOffset;
      // zero RVA lets check the 

      phyOffset = readlong(fhandle, 0);

      if(!phyOffset)
      {
        numberSections = i;
        valid = 0;

        Message("* Invalid section count detected, adjusted to %i\n\n", numberSections);
      }
    }

    if(valid)
    {
      if(actualImageSize < (baseRVA + valid))
      {
        actualImageSize = (baseRVA + valid);
      }

      if((baseRVA >= 0) && (baseRVA < headerVSize))
      {
        headerVSize = baseRVA;
      }
    }
  }

  if(headerPSize < (PEoffset + NTheaderSize + 0x18 + numberSections*0x28))
  {
    // The physical size is too small.
    // Windows NT/2000 won't load this file... (but we will ;)

    comment = form("header physical size is too small (%.8X), ", headerPSize);

    headerPSize = PEoffset + NTheaderSize + 0x18 + numberSections*0x28;

    comment = comment + form("adjusted to (%.8X)", headerPSize);

    Message("  * " + comment + "\n\n");

    comment = "\n" + comment;
  }
  else
  {
    comment = "";
  }

  LargestPhysical = headerPSize;

  imageDelta = 0;

  if(!already_loaded)
  {
    auto next_seg;

    next_seg = NextSeg(imageBase);

    if((SegStart(imageBase) != BADADDR) || ((next_seg != BADADDR) && (actualImageSize > (next_seg - imageBase))))
    {
      auto newBase;

      if(flags & 0x0001) // relocs stripped
      {
        already_loaded = AskYN(0, "image does not have relocations, relocate anyway?");

        // -1 - we return from this function.
        //  0 - we return from this function.
        //  1 - we reload all section data.

        if(already_loaded <= 0)
        {
          return already_loaded;
        }

        already_loaded = 0;
      }

      // we must relocate the image

      newBase = 0x10000000; // we will start searching for a free block from the 1st GB

      while((SegStart(newBase) != BADADDR) || ((next_seg != BADADDR) && (actualImageSize > (next_seg - newBase))))
      {
        next_seg = NextSeg(newBase);

        if(SegStart(newBase) != BADADDR)
        {
          newBase = SegEnd(newBase);
        }
      }

      imageDelta  = newBase - imageBase;

      Message("- Address collision detected at %08X-%08X\n", imageBase, imageBase + actualImageSize - 1);
      Message("  - Relocating image to %08X-%08X (delta:%08X)\n\n", newBase, newBase + actualImageSize - 1, imageDelta);

      imageBase   = newBase;
    }
    else
    {
      already_loaded = 1;
    }
  }

  CreateSection(fhandle, DLL_name + PE_HEADER_SECTION_NAME, imageBase, headerVSize, 0, headerPSize, load_section_data);

  MakeComm(imageBase + PEoffset, commentTimeStamp + comment);

  Message("\n    name:                     %s\n", PE_HEADER_SECTION_NAME);
  Message("    file offset:              00000000\n");
  Message("    file size:                %.8X (ends at %.8X)\n", headerPSize, headerPSize);
  Message("    relative virtual address: --------\n");
  Message("    virtual size:             %.8X\n", headerVSize);
  Message("    flags:                    --------\n\n");

  if((PEentry || !(flags & 0x2000)) && (PEentry < headerVSize))
  {
    Message("  * The entry point is in the " + PE_HEADER_SECTION_NAME + " section\n");

    if(PEentry > headerPSize)
    {
      Message("  * WARNING: no physical data to backup the entry point\n\n");
    }

    Message("\n");
  }

  if(CreateMZStruct(imageBase, DLL_name) == -1)
    return -1;
  if(CreatePEStruct(imageBase, PEoffset, DLL_name) == -1)
    return -1;
  if(CreatePESStruct(imageBase, DLL_name) == -1)
    return -1;

  ForceName(imageBase + PEsections, DLL_name + "pe_section_table");

  for(i = 0; i < numberSections; i++)
  {
    auto vSize, RVA, phySize, phyAddr;
    auto l, printPhySize, printVSize;
    auto flagsComment, warningComment;
    auto vExtra;
    auto printPhyAddr;
    auto tmpStr;
    auto sectionflags;

    MySeek(fhandle, PEsections + i*0x28, 0);

    findString = fgetStr(fhandle, 8);

    vSize   = readlong(fhandle, 0);
    RVA     = readlong(fhandle, 0);
    phySize = readlong(fhandle, 0);
    phyAddr = readlong(fhandle, 0);

    printPhyAddr = phyAddr;
    printPhySize = phySize;
    printVSize   = vSize;

    MySeek(fhandle, 0x0c, 1);

    sectionflags = readlong(fhandle, 0);

    warningComment = "";
    comment = "(";

    comment = comment + ((sectionflags & 0x40000000) ? "r" : "-");
    comment = comment + ((sectionflags & 0x80000000) ? "w" : "-");
    comment = comment + ((sectionflags & 0x20000000) ? "x" : "-");
    comment = comment + ((sectionflags & 0x00000020) ? "c" : "-");
    comment = comment + ((sectionflags & 0x00000040) ? "i" : "-");
    comment = comment + ((sectionflags & 0x00000080) ? "u" : "-");

    comment = comment + ")";

    if(sectionflags & 0x10000000)
    {
      comment = comment + " shared";
    }

    if(sectionflags & 0x01000000)
    {
      comment = comment + " ext relocs";
    }

    if(sectionflags & 0x02000000)
    {
      comment = comment + " discardable";
    }

    if(sectionflags & 0x04000000)
    {
      comment = comment + " don't cache";
    }

    if(sectionflags & 0x08000000)
    {
      comment = comment + " don't page";
    }

    flagsComment = comment;

    comment = "flags" + comment;

    if((vSize == 0) && (phySize != 0))
    {
      // Win9x specific (NT will refuse to load the application)

      vSize = phySize;

      tmpStr = "virtual size is zero --> using physical size instead";
      comment = comment + "\n" + tmpStr;
      warningComment = warningComment + "  * " + tmpStr + "\n\n";
    }

    if(phyAddr == 0)
    {
      phySize = 0;

      tmpStr = "file offset is zero --> using zero for the physical size";
      comment = comment + "\n" + tmpStr;
      warningComment = warningComment + "  * " + tmpStr + "\n\n";
    }

    // adjusting phyAddr to valid values

    if((phyAddr & 0x1ff) && (subsystem != 1) && (strange_alignment >= 0))
    {
      // Windows adjusts the physical offset to a 200h boundary (sector size?)
      // Note:
      //   This check is done AFTER the zero check.
      //   and is not done for programs running under native subsystem.
      //   apparently pre Win95 SP2 did not adjust the offset like this.

      if(strange_alignment == 0)
      {
        strange_alignment = AskYN(1, form("Strange section alignment (%08X), adjust to 200h?", phyAddr));
        if(strange_alignment < 0)
        {
          return -1;
        }

        if(strange_alignment == 0)
        {
          strange_alignment = -1;
        }
      }

      if(strange_alignment > 0)
      {
        phyAddr = phyAddr & 0xfffffe00;

        tmpStr = form("file offset is not on a 200h boundary --> adjusted to %08X", phyAddr);

        comment = comment + "\n" + tmpStr;
        warningComment = warningComment + "  * " + tmpStr + "\n\n";
      }
    }

    // adjusting sizes to alignment values

    vExtra = (phyAddr + phySize) % FileAlignment;
    if(vExtra != 0)
    {
      vExtra = FileAlignment - vExtra;
      phySize = phySize + vExtra;
    }

    vExtra = (RVA + vSize) % SectionAlignment;
    if(vExtra != 0)
    {
      vExtra = SectionAlignment - vExtra;
      vSize = vSize + vExtra;
    }

    // making sure that we don't try to read data that isn't there.

    if(vSize < phySize)
    {
      phySize = vSize;
    }

    if(phySize != 0)
    {
      if(fileSize > phyAddr)
      {
        if(fileSize < (phyAddr + phySize))
        {
          phySize = fileSize - phyAddr;
        }

        if(fileSize < (phyAddr + printPhySize))
        {
          Warning(findString + " section ends outside of the file, part of the physical data is missing!");
          warningComment = warningComment + "  * " + findString + " section ends outside of the file\n  * part of its physical data is missing!\n\n";
          comment = comment + "\nSection ends outside of the file\npart of the physical data is missing!";
        }
      }
      else
      {
        phySize = 0;

        if(printPhySize != 0)
        {
          Warning(findString + " section starts outside of the file!  No physical data available!");
          warningComment = warningComment + "  * " + findString + " section starts outside of the file\n  * no physical data is available for it\n\n";
          comment = comment + "\nSection starts outside of the file\nNo physical data available";
        }
      }
    }

    if(LargestPhysical < (phyAddr + phySize))
    {
      LargestPhysical = phyAddr + phySize;
    }

    CreateSection(fhandle, DLL_name + findString, imageBase + RVA, vSize, phyAddr, phySize, load_section_data);

    Message("\n    name:                     %s\n", findString);
    Message("    file offset:              %.8X\n", printPhyAddr);
    Message("    file size:                %.8X (ends at %.8X)\n", printPhySize, phyAddr + printPhySize);
    Message("    relative virtual address: %.8X\n", RVA);
    Message("    virtual size:             %.8X\n", printVSize);
    Message("    flags:                    %.8X ", sectionflags);
    Message(flagsComment + "\n\n");

    Message(warningComment);

    if(PEentry && (RVA <= PEentry) && (PEentry < (RVA + vSize)))
    {
      Message("  * The entry point is in the " + DLL_name + findString + " section\n\n");
      comment = comment + "\n* The entry point is in this section.";

      if((RVA + phySize) <= PEentry)
      {
        Message("  * WARNING: no physical data to backup the entry point\n\n");
      }
    }

    l = imageBase + PEsections + i*0x28;

    ForceStruct(l, DLL_name + PE_SECTION_STRUCTURE_NAME);
    MakeComm(l, comment);
  }

  if(LargestPhysical < fileSize)
  {
    Message(form("  * extra data after image at %.8X (size is %.8X)\n\n", LargestPhysical, fileSize - LargestPhysical));
  }

  if(imageDelta)
  {
    auto reloc_rva;

    if(PEtype != 0x20b)
    {
      reloc_rva = imageBase + PEoffset + 0xa0;
    }
    else
    {
      reloc_rva = imageBase + PEoffset + 0xb0;
    }

    ApplyRelocs(imageBase, LEDword(reloc_rva), imageDelta);
  }

  Message("-------------------------------------------------------------------------------\n\n");

  tables_error = doPETables(PEoffset, imageBase, DLL_name);

  ForceStruct(imageBase, DLL_name + MZ_HEADER_STRUCTURE_NAME);
  ForceStruct(imageBase + PEoffset, DLL_name + PE_HEADER_STRUCTURE_NAME);

  ForceName(imageBase, DLL_name + "image_base");
  ForceName(imageBase + PEoffset, DLL_name + "pe_header");

  if(tables_error != -1)
  {
    if(PEentry || !(flags & 0x2000))
    {
      // this block must be here since here we are guarantied that we have the section data available

      AddEntryPoint(PEentry + imageBase, PEentry + imageBase, DLL_name + "start", 1);
    }

    return imageBase;
  }
  else
  {
    return -1;
  }
}

static CreateMZStruct(imageBase, DLL_name)
{
  auto sHandle;
  auto error;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + MZ_HEADER_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, DLL_name + MZ_HEADER_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + MZ_HEADER_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + MZ_HEADER_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "MZ_signature",        0x00, FF_ASCI, -1, 2);
  AddStrucMember(sHandle, "bytes_in_last",       0x02, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "total_pages",         0x04, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "num_relocs",          0x06, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "header_size",         0x08, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "min_mem",             0x0a, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "max_mem",             0x0c, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "init_SS",             0x0e, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "init_SP",             0x10, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "CRC",                 0x12, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "init_IP",             0x14, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "init_CS",             0x16, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "relocs_offset",       0x18, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "overlay_number",      0x1a, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "reserved",            0x1c, FF_BYTE, -1, 32); 
  AddStrucMember(sHandle, "new_hdr_offset",      0x3c, FF_DWRD | FF_0OFF, imageBase, 4);
}

static CreatePEStruct(imageBase, PEoffset, DLL_name)
{
  auto sHandle;
  auto numInterested;

  auto PEtype;
  auto delta;

  PEtype = LEWord(imageBase + PEoffset + 0x18);

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_HEADER_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_HEADER_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_HEADER_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_HEADER_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle,   "PE_signature",        0x00, FF_ASCI, -1, 4);
  AddStrucMember(sHandle,   "CPU_Type",            0x04, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "number_of_Sections",  0x06, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "time_date_stamp",     0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "symbol_table_file_offset", 0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "symbol_table_size",   0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "opt_header_size",     0x14, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "flags",               0x16, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "COFF_magic",          0x18, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "Linker_version",      0x1a, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "size_of_code",        0x1c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_init_data",   0x20, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_uninit_data", 0x24, FF_DWRD, -1, 4);
  AddNZOffset(sHandle,      "entry_point_RVA",     0x28, imageBase, PEoffset);
  AddNZOffset(sHandle,      "base_of_code",        0x2c, imageBase, PEoffset);

  if(PEtype != 0x20b)
  {
    AddNZOffset(sHandle,    "base_of_data",        0x30, imageBase, PEoffset);
    AddStrucMember(sHandle, "base_of_image",       0x34, FF_DWRD, -1, 4);
  }
  else
  {
    AddStrucMember(sHandle, "base_of_image",       0x30, FF_QWRD, -1, 8);
  }

  AddStrucMember(sHandle,   "image_alignment",     0x38, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "file_alignment",      0x3c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "OS_version_major",    0x40, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "OS_version_minor",    0x42, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "User_version_major",  0x44, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "User_version_minor",  0x46, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "SubSys_version_major",0x48, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "SubSys_version_minor",0x4a, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "Reserved2",           0x4c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_image",       0x50, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_header",      0x54, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "file_CRC",            0x58, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Sub_System",          0x5c, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "DLL_flags",           0x5e, FF_WORD, -1, 2);

  if(PEtype != 0x20b)
  {
    AddStrucMember(sHandle, "stack_reserve",       0x60, FF_DWRD, -1, 4);
    AddStrucMember(sHandle, "stack_commit",        0x64, FF_DWRD, -1, 4);
    AddStrucMember(sHandle, "heap_reserve",        0x68, FF_DWRD, -1, 4);
    AddStrucMember(sHandle, "heap_commit",         0x6c, FF_DWRD, -1, 4);

    delta = 0;
  }
  else
  {
    AddStrucMember(sHandle, "stack_reserve",       0x60, FF_QWRD, -1, 8);
    AddStrucMember(sHandle, "stack_commit",        0x68, FF_QWRD, -1, 8);
    AddStrucMember(sHandle, "heap_reserve",        0x70, FF_QWRD, -1, 8);
    AddStrucMember(sHandle, "heap_commit",         0x78, FF_QWRD, -1, 8);

    delta = 0x10;
  }

  AddStrucMember(sHandle,   "loader_flags",        0x70 + delta, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "interesting_pairs",   0x74 + delta, FF_DWRD, -1, 4);

  numInterested = LEDword(imageBase + PEoffset + 0x74 + delta);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "export_table_RVA",    0x78 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "export_table_size",   0x7c + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "import_table_RVA",    0x80 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "import_table_size",   0x84 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "resource_table_RVA",  0x88 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "resource_table_size", 0x8c + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "exception_table_RVA", 0x90 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "exception_table_size", 0x94 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "security_table_RVA",  0x98 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "security_table_size", 0x9c + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "reloc_table_RVA",     0xa0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "reloc_table_size",    0xa4 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "debug_table_RVA",     0xa8 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "debug_table_size",    0xac + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "image_desc_table_RVA", 0xb0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "image_desc_table_size", 0xb4 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "machine_spec_table_RVA", 0xb8 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "machine_spec_table_size", 0xbc + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "thread_local_storage_table_RVA", 0xc0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "thread_local_storage_table_size", 0xc4 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "load_config_table_RVA", 0xc8 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "load_config_table_size", 0xcc + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "bound_import_table_RVA", 0xd0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "bound_import_table_size", 0xd4 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "IAT_table_RVA",       0xd8 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "IAT_table_size",      0xdc + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "delay_import_desc_table_RVA", 0xe0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "delay_import_desc_table_size", 0xe4 + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "Reserved0_table_RVA", 0xe8 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "Reserved0_table_size", 0xec + delta, FF_DWRD, -1, 4);

  if(!numInterested--)
    return 0;

  AddNZOffset(sHandle,      "Reserved1_table_RVA", 0xf0 + delta, imageBase, PEoffset);
  AddStrucMember(sHandle,   "Reserved1_table_size", 0xf4 + delta, FF_DWRD, -1, 4);
}

static CreatePESStruct(imageBase, DLL_name)
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_SECTION_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_SECTION_STRUCTURE_NAME, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_SECTION_STRUCTURE_NAME);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_SECTION_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "name",                           0x00, FF_ASCI, -1, 8); 
  AddStrucMember(sHandle, "virtual_size",                   0x08, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "relative_virtual_address",       0x0c, FF_DWRD | FF_0OFF, imageBase, 4); 
  AddStrucMember(sHandle, "size_in_file",                   0x10, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "offset_in_file",                 0x14, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "file_offset_to_relocs",          0x18, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "file_offset_to_line_numbers",    0x1c, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "number_of_relocs",               0x20, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "number_of_line_numbers",         0x22, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "flags",                          0x24, FF_DWRD, -1, 4); 
}

static doPETables(PEoffset, imageBase, DLL_name)
{
  auto ask_user, user_quit;
  auto number_of_tables;

  auto current;
  auto table_start, table_size;

  auto PEtype;

  PEtype = LEWord(imageBase + PEoffset + 0x18);

  if(PEtype != 0x20b)
  {
    number_of_tables  = LEDword(imageBase + PEoffset + 0x74);
    current           = imageBase + PEoffset + 0x78;
  }
  else
  {
    number_of_tables  = LEDword(imageBase + PEoffset + 0x84);
    current           = imageBase + PEoffset + 0x88;
  }

  ///////////////////////////////////////////////////
  // Various Structures

  if(ExportStructs(imageBase, DLL_name) < 0)
  {
    return -1;
  }

  if(ImportStructs(imageBase, DLL_name) < 0)
  {
    return -1;
  }

  if(DebugStructs(imageBase, DLL_name) < 0)
  {
    return -1;
  }

  if(ResourceStructs(imageBase, DLL_name) < 0)
  {
    return -1;
  }

  if(TLSStructs(imageBase, DLL_name) < 0)
  {
    return -1;
  }

  ///////////////////////////////////////////////////
  // And now the tables

  user_quit = 0; // just in case there are no tables.

  while(1)
  {

    if(!number_of_tables--)
    {
      break;
    }

#if !defined(DEBUG_ASK_TABLES)
    ask_user = 1;
#else
    ask_user = AskYN(1, "Do you want me to parse all the PE tables?");
#endif

    // -1 - we return from this function.
    //  0 - we ask the user which tables he wants.
    //  1 - we do all the tables, with out anoying the user.

    if(ask_user < 0)
    {
      break;
    }

    ///////////////////////////////////////////////////
    // exports

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doExportTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // imports

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doImportTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // resources

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doResourceTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // exceptions

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = 0; // doExceptionTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // security

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = 0; // doSecurityTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // relocations

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doRelocTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // debug

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doDebugTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // architecture

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = 0; // doArchitectureTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // Global Pointer

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4); // should be zero

    current       = current + 8;
    user_quit     = 0; // doGlobalPtrTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // TLS

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doTLSTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // Load Config

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = 0; // doLoadConfigTable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    ///////////////////////////////////////////////////
    // Bound Import

    table_start   = LEDword(current);
    table_size    = LEDword(current + 4);

    current       = current + 8;
    user_quit     = doBoundITable(ask_user, imageBase, table_start, table_size, DLL_name);

    if((user_quit < 0) || (!number_of_tables--))
    {
      break;
    }

    break; // to get out of the while
  }

  if(ask_user < 0)
  {
    Message("  user skipped table parsing.\n\n");
  }
  else
  {
    if(user_quit < 0)
    {
      Message("  user terminated table parsing.\n\n");
    }
    else
    {
      Message("  no more tables.\n\n");
    }
  }

  Message("-------------------------------------------------------------------------------\n\n");

  return 0;
}

#define PE_EXPORT_DIRECTORY_STRUCT  "EXPORT_DIR_ENTRY"

static ExportStructs(imageBase, DLL_name)
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_EXPORT_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_EXPORT_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_EXPORT_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_EXPORT_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "export_flags",           0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "time_date_samp",         0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "version"                 0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name",                   0x0c, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "ordinal_base",           0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "address_table_count",    0x14, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name_pointers_count",    0x18, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "address_table",          0x1c, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "name_pointers",          0x20, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "ordinal_table",          0x24, FF_DWRD | FF_0OFF, imageBase, 4);

  return 0;
}

static doExportTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start && table_size)
  {
    auto do_table;
    auto tds, ver, name, num_at, num_np, at, np, ot, ord_base;
    auto comment;

    auto exp_addr;
    auto SectionStart;

    auto PEtype;
    auto address_table;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the export table?");

      if(do_table <= 0)
      {
        Message("  user skipped export table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  export table is not in any section!\n");
      return 0;
    }

    Message("  export table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    tds       = LEDword(table_start + 0x04);
    name      = LEDword(table_start + 0x0c) + imageBase;
    ord_base  = LEDword(table_start + 0x10);
    num_at    = LEDword(table_start + 0x14);
    num_np    = LEDword(table_start + 0x18);
    at        = LEDword(table_start + 0x1c) + imageBase;
    np        = LEDword(table_start + 0x20) + imageBase;
    ot        = LEDword(table_start + 0x24) + imageBase;

    if(!hasValue(GetFlags(ot)) || !hasValue(GetFlags(np)) || !hasValue(GetFlags(at)) || !hasValue(GetFlags(name)))
    {
      Message("    export table appears to contain garbage (packed?)\n");
      return 0;
    }

    PEtype = LEDword(imageBase + 0x3c);
    PEtype = LEWord(imageBase + PEtype + 0x18);

    ForceName(ot, DLL_name + "export_ordinal_table");
    ForceName(np, DLL_name + "export_name_pointer_table");
    ForceName(at, DLL_name + "export_address_table");
    ForceName(name, DLL_name + "export_name");

    ForceName(table_start, DLL_name + "export_directory");

    comment = "time stamp: " + ULDateToStr(tds);

    if(LEDword(table_start + 0x08) != 0)
    {
      ver     = form("\nVersion: %i.%i", LEWord(table_start + 0x08), LEWord(table_start + 0x0a));
      comment = comment + ver;
    }

    ForceStruct(table_start, DLL_name + PE_EXPORT_DIRECTORY_STRUCT);
    MakeComm(table_start, comment);

    table_start = table_start - imageBase;

    ForceStr(name, BADADDR);

    address_table = at;

    while(num_np--)
    {
      auto ordinal;
      auto at_entry;

      exp_addr = LEDword(np);

      MakeDword(np);
      MakeWord(ot);

      ordinal = LEWord(ot) + ord_base;

      comment = form("ordinal: %i (%Xh)", ordinal, ordinal);
      MakeComm(np, comment);

      comment = DLL_name + Str(exp_addr + imageBase);
      MakeComm(ot, comment);

      ordinal = ordinal - ord_base;

      at = address_table + ordinal*4;
      at_entry = at;

      at = LEDword(at);

      if(at)
      {
        // if (exportTable <= retval < exportTable + exportTableSize) then it's a forwarder entry

        // since IDA uses signed longs for everything we have to make a clutch to detect this correctly
        // in addresses above 0x7fffffff.

        // clutch: previously subtract the image base from the table address (hopefully no file to analyze will be larger than 2G).

        if((at < table_start) || (at >= (table_start + table_size)))
        {
          if(PEtype != 0x20b)
          {
            AddEntryPoint(at + imageBase, at + imageBase, comment, 1);
          }
          else
          {
            // PE2 export address table does not reference directly to a function, rather into a pointer to the function
            AddEntryPoint(LEDword(at + imageBase), LEDword(at + imageBase), comment, 1);
          }
        }
        else
        {
          AddEntryPoint(at + imageBase, at + imageBase, comment, 0);
          ForceStr(at + imageBase, BADADDR);
        }

        at = at + imageBase;

        if(Name(at) != comment)
        {
          MakeComm(at_entry, comment);
        }
      }

      OpOff(np, 0, imageBase);

      np = np + 4;
      ot = ot + 2;
    }

    at = address_table;

    while(num_at--)
    {
      exp_addr = LEDword(at);

      MakeDword(at);

      if(exp_addr)
      {
        OpOff(at, 0, imageBase);

        exp_addr = exp_addr + imageBase;
        if((GetFlags(exp_addr) & FF_NAME) == 0)
        {
          ForceName(exp_addr, form("%s%04x", DLL_name + "ord" + DLL_SEPERATOR, (ord_base + (at - address_table)/4)));
        }
      }

      at = at + 4;
    }

    return 1;
  }
  else
  {
    Message("  no export table available.\n");

    return 0;
  }
}

#define PE_IMPORT_DIRECTORY_STRUCT  "IMPORT_DIR_ENTRY"

static ImportStructs(imageBase, DLL_name)
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_IMPORT_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_IMPORT_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_IMPORT_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_IMPORT_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "import_lookup_table",    0x00, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "time_date_stamp",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "forwarder_chain",        0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name",                   0x0c, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "import_address_table",   0x10, FF_DWRD | FF_0OFF, imageBase, 4);

  return 0;
}

static doImportTable(ask_user, imageBase, table_start, table_size, in_DLL_name)
{
  if(table_start && table_size)
  {
    auto do_table;
    auto SectionStart;
    auto counter;

    auto PEtype;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the import table?");

      if(do_table <= 0)
      {
        Message("  user skipped import table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  import table is not in any section!\n");
      return 0;
    }

    Message("  import table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    PEtype = LEDword(imageBase + 0x3c);
    PEtype = LEWord(imageBase + PEtype + 0x18);

    counter = 0;

    ForceName(table_start, in_DLL_name + "import_directory");

    while(1)
    {
      auto ilt, tds, fc, name, iat;
      auto DLL_name;
      auto comment;

      auto temp;

      ilt     = LEDword(table_start);
      tds     = LEDword(table_start + 0x04);
      fc      = LEDword(table_start + 0x08);
      name    = LEDword(table_start + 0x0c);
      iat     = LEDword(table_start + 0x10);

      ForceStruct(table_start, in_DLL_name + PE_IMPORT_DIRECTORY_STRUCT);

      if(!name || !iat)
      {
        ForceName(table_start, in_DLL_name + "import_directory_terminator");
        break;
      }

      if(!isLoaded(name + imageBase))
      {
        Message("    ");
        WarningMessage("import table: corruption detected.");
        break;
      }

      ForceStr(name + imageBase, BADADDR);

      DLL_name = Str(name + imageBase);
      comment = DLL_name + "\ntime stamp: " + ULDateToStr(tds);
      DLL_name = DLL_name + DLL_SEPERATOR;

      MakeComm(table_start, comment);

      iat = iat + imageBase;

      if(!ilt)
      {
        ilt = iat;
      }
      else
      {
        ilt = ilt + imageBase;
        ForceName(ilt, in_DLL_name + DLL_name + "ilt");
      }

      if(!isLoaded(iat) || !isLoaded(ilt))
      {
        Message("    ");
        WarningMessage("import table: corruption detected.");
        break;
      }

      temp = LEDword(ilt);

      while(temp != 0)
      {
        if((PEtype == 0x20b) && (LEDword(ilt + 4) < 0))
        {
          temp = -1; // clutch to get the desired behaviour
        }

        if(temp < 0)
        {
          if(PEtype != 0x20b)
          {
            temp = temp & 0x7fffffff;
            MakeDword(ilt);
          }
          else
          {
            temp = Dword(ilt);
            MakeQword(ilt);
          }

          comment = "(import by ordinal)";

          if((GetFlags(iat) & FF_NAME) == 0)
          {
            ForceName(iat, form("%s%04X", in_DLL_name + DLL_name + "ord" + DLL_SEPERATOR, temp));
          }
        }
        else
        {
          auto address, func_name;

          if(PEtype != 0x20b)
          {
            address = (temp & 0x7fffffff) + imageBase;
          }
          else
          {
            address = temp + imageBase;
          }

          ForceWord(address);
          ForceStr(address + 2, BADADDR);

          func_name = Str(address + 2);

          if(in_DLL_name == "")
          {
            comment = func_name + " (import by name)";
          }
          else
          {
            comment = DLL_name + func_name + " (import by name)";
          }

          OpOff(ilt, 0, imageBase);

          if((GetFlags(iat) & FF_NAME) == 0)
          {
            if(in_DLL_name == "")
            {
              ForceName(iat, func_name);
            }
            else
            {
              ForceName(iat, in_DLL_name + DLL_name + func_name);
            }
          }
        }

        MakeComm(ilt, comment);
                
        if(PEtype != 0x20b)
        {
          MakeDword(iat);

          iat = iat + 4;
          ilt = ilt + 4;
        }
        else
        {
          MakeQword(iat);

          iat = iat + 8;
          ilt = ilt + 8;
        }

        temp = LEDword(ilt);
      }

      if(PEtype != 0x20b)
      {
        MakeDword(ilt);
        MakeDword(iat);
      }
      else
      {
        MakeQword(ilt);
        MakeQword(iat);
      }

      table_start = table_start + 0x14;
      ForceName(table_start, form(in_DLL_name + "import_dir_%.2x", ++counter));
    }

    return 1;
  }
  else
  {
    Message("  no import table available.\n");
    return 0;
  }
}

static ApplyRelocs(imageBase, reloc_rva, imageDelta)
{
  auto table_size, table_start;
  auto page, size;
  auto untested_mask;

  Message("- Applying relocation information");

  if(!reloc_rva)
  {
    Message(" (no reloc table)\n\n");
    return 0;
  }

  table_start = reloc_rva + imageBase;

  if(SegStart(table_start) == BADADDR)
  {
    Message(" (reloc table not in any section)\n\n");
    return 0;
  }

  table_size = SegEnd(table_start) - table_start;

  untested_mask = 0;

  while(table_size > 0)
  {
    page = LEDword(table_start);
    size = LEDword(table_start + 4);

    if((page == 0) && (size == 0))
    {
      break;
    }

    if(size < 8)
    {
      size = 8;
    }

    if(table_size < 8)
    {
      table_size = 8;
    }

    if(size > table_size)
    {
      size = table_size;
    }

    table_size  = table_size - size;
    table_start = table_start + 8;
    size        = size - 8;

    if(size & 1)
    {
      size = size & ~1;
    }

    while(size > 0)
    {
      auto fixup_type, fixup_offset, untested;

      fixup_offset = LEWord(table_start);

      fixup_type   = fixup_offset >> 12;
      fixup_offset = (fixup_offset & 0x0fff) + page + imageBase;

      untested = 0;

      if(fixup_type == 0) // IMAGE_REL_BASED_ABSOLUTE (filler)
      {
        // ignore this one
      }
      else if(fixup_type == 1) // IMAGE_REL_BASED_HIGH
      {
        PatchWord(fixup_offset, LEWord(fixup_offset) + ((imageDelta >> 16) & 0xffff));
        untested = 1;
      }
      else if(fixup_type == 2) // IMAGE_REL_BASED_LOW
      {
        PatchWord(fixup_offset, LEWord(fixup_offset) + (imageDelta && 0xffff));
        untested = 1;
      }
      else if(fixup_type == 3) // IMAGE_REL_BASED_HIGHLOW
      {
        PatchDword(fixup_offset, LEDword(fixup_offset) + imageDelta);
      }
      else if(fixup_type == 4) // IMAGE_REL_BASED_HIGHADJ
      {
        untested = 1;
      }
      else if(fixup_type == 5) // IMAGE_REL_BASED_MIPS_JMPADDR
      {
        untested = 1;
      }
      else if(fixup_type == 6) // IMAGE_REL_BASED_SECTION (reserved)
      {
        untested = 1;
      }
      else if(fixup_type == 7) // IMAGE_REL_BASED_REL32 (reserved)
      {
        untested = 1;
      }
      else if(fixup_type == 8) // ???
      {
        untested = 1;
      }
      else if(fixup_type == 9) // IMAGE_REL_BASED_MIPS_JMPADDR16
      {
        untested = 1;
      }
      else if(fixup_type == 10) // IMAGE_REL_BASED_DIR64
      {
        PatchDword(fixup_offset, LEDword(fixup_offset) + imageDelta);

        if(LEDword(fixup_offset) < imageDelta)
        {
          PatchDword(fixup_offset + 4, LEDword(fixup_offset + 4) + 1);
        }

        untested = 1; // only the low 32-bits (for now)
      }
      else if(fixup_type == 11) // IMAGE_REL_BASED_HIGH3ADJ
      {
        untested = 1;
      }
      else // ???
      {
        untested = 1;
      }

      if(untested && !(untested_mask & (1 << fixup_type)))
      {
        untested_mask = untested_mask | (1 << fixup_type);
        Message(form("\n(untested reloc:%i, %08X:%04X @ %08X)", fixup_type, page, fixup_offset, table_start));
      }

      table_start = table_start + 2;
      size        = size - 2;
    }
  }

  Message(" (done)\n\n");

  return 0;
}

static doRelocTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  auto do_table;

  if(!table_start)
  {
    table_start = FirstNamedSeg(DLL_name + ".reloc");

    if(table_start != BADADDR)
    {
      do_table = AskYN(1, "No relocs, but there is a .reloc section.  Shall I try to parse it?");

      if(do_table <= 0)
      {
        Message("  user skipped [possible] relocs table.\n");
        return do_table;
      }

      table_size  = SegEnd(table_start) - table_start;
      table_start = table_start - imageBase;
    }
    else
    {
      table_start = 0;
    }
  }

  if(table_start && table_size)
  {
    auto SectionStart;

    auto page, size, number;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the relocs table?");

      if(do_table <= 0)
      {
        Message("  user skipped relocs table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  relocs table is not in any section!\n");
      return 0;
    }

    Message("  relocs table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    number = 1;

    while(table_size > 0)
    {
      page = LEDword(table_start);
      size = LEDword(table_start + 4);

      MakeDword(table_start);
      MakeDword(table_start + 4);

      ForceName(table_start, form(DLL_name + "relocs_%.4X_page", number));
      ForceName(table_start + 4, form(DLL_name + "relocs_%.4X_size", number));

      if((page == 0) && (size == 0))
      {
        MakeComm(table_start, "unexpected end of reloc table");
        break;
      }

      if(size < 8)
      {
        MakeComm(table_start + 4, "invalid relocs table size");
        size = 8;
      }

      if(table_size < 8)
      {
        MakeComm(table_start + 4, "invalid relocs table size");
        table_size = 8;
      }

      if(size > table_size)
      {
        MakeComm(table_start + 4, "invalid relocs table size");
        size = table_size;
      }

      if(size & 1)
      {
        Message(form("    (weird reloc block size detected @ %08X)\n", table_start));
      }

      MakeWord(table_start + 8);
      MakeArray(table_start + 8, (size - 8) >> 1);
      ForceName(table_start + 8, form(DLL_name + "relocs_%.4X_toff", number));

      number++;

      table_start = table_start + size;
      table_size  = table_size - size;
    }

    return 1;
  }
  else
  {
    Message("  no relocs table available.\n");
    return 0;
  }
}

#define PE_RESOURCE_DIRECTORY_STRUCT  "RESOURCE_DIR_ENTRY"
#define PE_RESOURCE_ENTRY_STRUCT      "RESOURCE_DATA_ENTRY"

static ResourceStructs(imageBase, DLL_name)
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_RESOURCE_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_RESOURCE_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_RESOURCE_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_RESOURCE_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "characteristics",        0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "time_date_stamp",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "linker_version_major",   0x08, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "linker_version_minor",   0x0a, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "number_of_names",        0x0c, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "number_of_ids",          0x0e, FF_WORD, -1, 2);

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + PE_RESOURCE_ENTRY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + PE_RESOURCE_ENTRY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + PE_RESOURCE_ENTRY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + PE_RESOURCE_ENTRY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "data_RVA",               0x00, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "data_size",              0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "code_page",              0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "reserved",               0x0c, FF_DWRD, -1, 4);

  return 0;
}

static doResourceDir(imageBase, rootDirStart, DLL_name)
{
  auto fifo;
  auto dirStart;
  auto dir_current, dir_next;
  auto tds;
  auto names, ids;
  auto comment;
  auto entry;
  auto leaf;

  fifo = CreateArray("Resource_Directories");
  leaf = 0;

  if(fifo == -1)
  {
    return -1;
  }

  dir_current = 0;
  dir_next = 1;

  if(SetArrayLong(fifo, dir_current, rootDirStart) == 0)
  {
    return -1;
  }

  while(dir_current != dir_next)
  {
    dirStart = GetArrayElement(AR_LONG, fifo, dir_current);

    if(dir_current)
    {
      ForceName(dirStart, form(DLL_name + "resource_dir_%.4X", dir_current));
    }
    else
    {
      ForceName(dirStart, DLL_name + "resource_directory");
    }

    dir_current++;

    tds   = LEDword(dirStart + 0x04);
    names = LEWord(dirStart + 0x0c);
    ids   = LEWord(dirStart + 0x0e);

    comment = "time stamp: " + ULDateToStr(tds);

    ForceStruct(dirStart, DLL_name + PE_RESOURCE_DIRECTORY_STRUCT);
    MakeComm(dirStart, comment);

    entry = dirStart + 0x10;

    while(names || ids)
    {
      auto RVA;

      if(names)
      {
        OpOffEx(entry, 0, REF_OFF32, -1, rootDirStart, 0x80000000);
        MakeComm(entry, "name");

        --names;
      }
      else
      {
        MakeDword(entry);
        MakeComm(entry, "ID");

        --ids;
      }

      entry = entry + 0x04;
      RVA = LEDword(entry);

      if(RVA & 0x80000000)
      {
        MakeDword(entry);
        MakeComm(entry, "subdir");

        OpOffEx(entry, 0, REF_OFF32, -1, rootDirStart, 0x80000000);

        if(SetArrayLong(fifo, dir_next++, (RVA & 0x7fffffff) + rootDirStart) == 0)
        {
          return -1;
        }
      }
      else
      {
        auto data_struct, data_RVA, data_size;

        MakeDword(entry);
        MakeComm(entry, "resource data entry (leaf)");
        data_struct = LEDword(entry);

        OpOff(entry, 0, rootDirStart);

        if(data_struct)
        {
          data_struct = data_struct + rootDirStart;

          ForceName(data_struct, form(DLL_name + "resource_leaf_%.4X", leaf));
          ForceStruct(data_struct, DLL_name + PE_RESOURCE_ENTRY_STRUCT);

          data_RVA  = LEDword(data_struct);
          data_size = LEDword(data_struct + 4);

          if(data_RVA && data_size)
          {
            ForceName(data_RVA + imageBase, form(DLL_name + "resource_data_%.4X", leaf));
            MakeByte(data_RVA + imageBase);
            MakeArray(data_RVA + imageBase, data_size);
          }

          ++leaf;
        }
      }

      entry = entry + 0x04;
    }
  }

  DeleteArray(fifo);

  return 0;
}

static doResourceTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start) // && table_size) // size ignored by Windows
  {
    auto do_table;
    auto SectionStart;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the resource table?");

      if(do_table <= 0)
      {
        Message("  user skipped resource table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  resource table is not in any section!\n");
      return 0;
    }

    Message("  resource table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    ///////////////////////////////////////////////////
    // table handling code comes here

    if(doResourceDir(imageBase, table_start, DLL_name) < 0)
    {
      return -1;
    }
    else
    {
      return 1;
    }
  }
  else
  {
    Message("  no resource table available.\n");
    return 0;
  }
}

#define DEBUG_DIRECTORY_STRUCT  "DEBUG_DIRECTORY"

static DebugStructs(imageBase, DLL_name)
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + DEBUG_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + DEBUG_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + DEBUG_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + DEBUG_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "characteristics",        0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "time_date_stamp",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "major_version",          0x08, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "minor_version",          0x0a, FF_WORD, -1, 2);
  AddStrucMember(sHandle, "type",                   0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "raw_data_size",          0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "raw_data_rva",           0x14, FF_DWRD | FF_0OFF, imageBase, 4);
  AddStrucMember(sHandle, "raw_data_file_pointer",  0x18, FF_DWRD, -1, 4);

  return 0;
}

static doDebugTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start && table_size)
  {
    auto do_table;
    auto SectionStart;

    auto table_offset;

    auto comment;
    auto ver;
    auto type;
    auto number;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the debug table?");

      if(do_table <= 0)
      {
        Message("  user skipped debug table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  debug table is not in any section!\n");
      return 0;
    }

    Message("  debug table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    ///////////////////////////////////////////////////
    // table handling code comes here

    table_offset  = table_start;
    number        = 0;

    while(table_offset < (table_start + table_size))
    {
      ForceStruct(table_offset, DLL_name + DEBUG_DIRECTORY_STRUCT);
      ForceName(table_offset, form(DLL_name + "debug_entry_%.4X", number++));

      comment = "time stamp: " + ULDateToStr(LEDword(table_start + 0x04));

      type = LEDword(table_offset + 0x0c);

      comment = comment + "\ntype: ";

      if(type == 0)
      {
        comment = comment + "unknown";
      }
      else if(type == 1)
      {
        comment = comment + "COFF";
      }
      else if(type == 2)
      {
        comment = comment + "CodeView";
      }
      else if(type == 3)
      {
        comment = comment + "Frame Pointer Omission";
      }
      else if(type == 4)
      {
        comment = comment + "misc";
      }
      else if(type == 5)
      {
        comment = comment + "exception";
      }
      else if(type == 6)
      {
        comment = comment + "fixup";
      }
      else if(type == 7)
      {
        comment = comment + "omap to source";
      }
      else if(type == 8)
      {
        comment = comment + "omap from source";
      }
      else if(type == 9)
      {
        comment = comment + "Borland";
      }

      ver = LEDword(table_offset + 0x08);

      if(ver != 0)
      {
        comment = comment + form("\nVersion: %i.%i", ver & 0xffff, (ver >> 16) & 0xffff);
      }

      MakeComm(table_offset, comment);

      table_offset = table_offset + 0x1c;
    }

    return 1;
  }
  else
  {
    Message("  no debug table available.\n");
    return 0;
  }
}

#define TLS_DIRECTORY_STRUCT  "TLS_DIR_ENTRY"

static TLSStructs(imageBase, DLL_name)
{
  auto sHandle;
  auto PEtype;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, DLL_name + TLS_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, DLL_name + TLS_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(DLL_name + TLS_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + DLL_name + TLS_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  PEtype = LEDword(imageBase + 0x3c);
  PEtype = LEWord(imageBase + PEtype + 0x18);

  if(PEtype != 0x20b)
  {
    AddStrucMember(sHandle, "raw_data_VA",            0x00, FF_DWRD | FF_0OFF, 0, 4);
    AddStrucMember(sHandle, "raw_data_end_VA",        0x04, FF_DWRD | FF_0OFF, 0, 4);
    AddStrucMember(sHandle, "index_VA",               0x08, FF_DWRD | FF_0OFF, 0, 4);
    AddStrucMember(sHandle, "callbacks_VA",           0x0c, FF_DWRD | FF_0OFF, 0, 4);
    AddStrucMember(sHandle, "zero_fill_size",         0x10, FF_DWRD, -1, 4);
    AddStrucMember(sHandle, "characteristics",        0x14, FF_DWRD, -1, 4);
  }
  else
  {
    AddStrucMember(sHandle, "raw_data_VA",            0x00, FF_QWRD | FF_0OFF, 0, 8);
    AddStrucMember(sHandle, "raw_data_end_VA",        0x08, FF_QWRD | FF_0OFF, 0, 8);
    AddStrucMember(sHandle, "index_VA",               0x10, FF_QWRD | FF_0OFF, 0, 8);
    AddStrucMember(sHandle, "callbacks_VA",           0x18, FF_QWRD | FF_0OFF, 0, 8);
    AddStrucMember(sHandle, "zero_fill_size",         0x20, FF_DWRD, -1, 4);
    AddStrucMember(sHandle, "characteristics",        0x24, FF_DWRD, -1, 4);
  }

  return 0;
}

static doTLSTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start)
  {
    auto do_table;
    auto SectionStart;

    auto PEtype;

    auto raw_start, raw_end, index, callbacks, zero_fill, characteristics;
    auto number, func;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the TLS table?");

      if(do_table <= 0)
      {
        Message("  user skipped TLS table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  TLS table is not in any section!\n");
      return 0;
    }

    Message("  TLS table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    ///////////////////////////////////////////////////
    // table handling code comes here

    PEtype = LEDword(imageBase + 0x3c);
    PEtype = LEWord(imageBase + PEtype + 0x18);

    if(PEtype != 0x20b)
    {
      raw_start       = LEDword(table_start);
      raw_end         = LEDword(table_start + 0x04);
      index           = LEDword(table_start + 0x08);
      callbacks       = LEDword(table_start + 0x0c);
      zero_fill       = LEDword(table_start + 0x10);
      characteristics = LEDword(table_start + 0x14);
    }
    else
    {
      raw_start       = LEDword(table_start);
      raw_end         = LEDword(table_start + 0x08);
      index           = LEDword(table_start + 0x10);
      callbacks       = LEDword(table_start + 0x18);
      zero_fill       = LEDword(table_start + 0x20);
      characteristics = LEDword(table_start + 0x24);
    }

    if(raw_start)
    {
      ForceName(raw_start,  DLL_name + "TlsRawStart");
    }

    if(raw_end)
    {
      ForceName(raw_end,    DLL_name + "TlsRawEnd");
    }

    if(index)
    {
      ForceName(index,      DLL_name + "TlsIndex");
      ForceDword(index);
    }

    if(callbacks)
    {
      ForceName(callbacks,  DLL_name + "TlsCallbacks");

      func = LEDword(callbacks);

      if(func)
      {
        number = 0;

        while(func)
        {
          AddEntryPoint(func, func, form(DLL_name + "TlsCallback_%d", number++), 1);
          OpOff(callbacks, 0, 0);

          if(PEtype != 0x20b)
          {
            callbacks = callbacks + 4;
          }
          else
          {
            callbacks = callbacks + 8;
          }

          func = LEDword(callbacks);
        }

        ForceName(callbacks, DLL_name + "TlsCallbacksEnd");
        Message("Forcing Dword\n");
        ForceDword(callbacks);

        Message(form("\n  * %d TLS callbacks detected\n\n", number));
      }
    }

    // The following lines should be last so that none of the above lines will destroy the tls directory

    ForceName(table_start, DLL_name + "TlsDirectory");
    ForceStruct(table_start, DLL_name + TLS_DIRECTORY_STRUCT);

    return 1;
  }
  else
  {
    Message("  no TLS table available.\n");
    return 0;
  }
}

static doBoundITable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start && table_size)
  {
    auto do_table;
    auto SectionStart;
    auto index;
    auto corrupted;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the Bound Import table?");

      if(do_table <= 0)
      {
        Message("  user skipped Bound Import table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  Bound Import table is not in any section!\n");
      return 0;
    }

    Message("  Bound Import table found in %s section, at %.8X (%.8X bytes).", SegName(table_start), table_start, table_size);

    ///////////////////////////////////////////////////
    // table handling code comes here

    ForceName(table_start, DLL_name + "bound_import_directory");

    index     = 0;
    corrupted = 0;

    while(1)
    {
      auto stamp, delta, offset;
      auto bound_DLL_offset;

      offset = table_start + index;

      stamp   = LEDword(offset);
      delta   = LEWord(offset + 0x04);

      MakeDword(offset);

      if(!stamp || !delta || (index > table_size))
      {
        if(stamp || delta || (index > table_size))
        {
          corrupted = 1;
        }

        ForceName(table_start + index, DLL_name + "bound_import_directory_terminator");
        MakeWord(offset + 0x04);
        MakeWord(offset + 0x06);

        break;
      }

      MakeComm(offset, ULDateToStr(stamp));
      bound_DLL_offset = LEWord(offset + 0x04);

      if(bound_DLL_offset && (SegStart(bound_DLL_offset + table_start) != BADADDR))
      {
        auto bound_DLL_name;

        bound_DLL_offset = bound_DLL_offset + table_start;

        MakeWord(offset + 0x04);
        MakeWord(offset + 0x06);

        OpOff(offset + 0x04, 0, table_start);

        ForceStr(bound_DLL_offset, BADADDR);

        bound_DLL_name = Str(bound_DLL_offset);
        ForceName(bound_DLL_offset, DLL_name + "bound_" + bound_DLL_name);
      }
      else
      {
        corrupted = 1;
        break;
      }

      index = index + 8;
    }

    if(corrupted)
    {
      Message(" (corrupted)");
    }

    Message("\n");
    return 1;
  }
  else
  {
    Message("  no Bound Import table available.\n");
    return 0;
  }
}

static doTemplateTable(ask_user, imageBase, table_start, table_size, DLL_name)
{
  if(table_start && table_size)
  {
    auto do_table;
    auto SectionStart;

    table_start = imageBase + table_start;

    if(ask_user == 0)
    {
      do_table = AskYN(1, "Do you want me to parse the XXXX table?");

      if(do_table <= 0)
      {
        Message("  user skipped XXXX table.\n");
        return do_table;
      }
    }

    SectionStart = SegStart(table_start);

    if(SectionStart == BADADDR)
    {
      Message("  XXXX table is not in any section!\n");
      return 0;
    }

    Message("  XXXX table found in %s section, at %.8X (%.8X bytes).\n", SegName(table_start), table_start, table_size);

    ///////////////////////////////////////////////////
    // table handling code comes here

    Message("  XXXX table not supported.\n");

    return 1;
  }
  else
  {
    Message("  no XXXX table available.\n");
    return 0;
  }
}

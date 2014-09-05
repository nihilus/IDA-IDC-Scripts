#include <idc.idc>

/*
// File:
//   pe_write.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//
//   Take a PE image and dump it to a file, as a PE executable.
//
// Warning:
//   This is the first version of this script so there might be some unexpected behaviours
//
// Note:
//   Be sure to uncheck the 'Make imports section' option, when loading the file for the first time.
//   Also, this script should be used with pe_sections.idc script (which should be run first)
//
//   This first version does not adjust the sections physical data size if the extra virtual region
//   actually contains data.  Nor does it save overlays, after the original file, to the new file.
//
//   I will add the above two things next...
//
// Usage:
//   Just run the script ;).
//
// Fixes/additions
//   amg - 01-12-2000 - 1st version.
//   amg - 28-04-2001 - bugfix: the script can now handle a 'strange' section table.
//
*/

#define PE_HEADER_SECTION_NAME    "HEADER"

static main(void)
{
  auto current;
  auto fhandle;
  auto signature;

  auto offset;
  auto num_sections;
  auto iBase, phyOffset, phySize, vOffset;

  Message("-------------------------------------------------------------------------------\n\n");
  Message("  The PE write script.\n  created by Atli Gudmundsson <agudmundsson@symantec.com>\n");
  Message("\n");

  current = GetInputFile();
  current = AskFile(-1, current, "What should I write the image to?");
  if(current == 0)
  {
    return -1;
  }

  // is this a PE image?

  iBase = FirstSeg();
  if(SegName(iBase) != PE_HEADER_SECTION_NAME)
  {
    Message("The " + PE_HEADER_SECTION_NAME + " section is not the first section\n");
    return -1;
  }

  signature = Word(iBase);

  if(signature != 0x5a4d)
  {
    // Note: the 'ZM' signature is not valid in a PE file.
    Message("  No MZ signature\n");
    return -1;
  }

  offset = Dword(iBase + 0x3c) + iBase;
  signature = Dword(offset);
  if(signature != 0x4550)
  {
    Message("  No PE signature\n");
    return -1;
  }

  // here we know that the image looks like a PE image.

  fhandle = fopen(current, "wb");
  if(fhandle == 0)
  {
    return -1;
  }


  phyOffset     = 0;
  phySize       = Dword(offset + 0x54);
  vOffset       = iBase;

  num_sections  = Word(offset + 0x6) + 1;
  offset        = Word(offset + 0x14) + offset + 0x18;

  Message("  Sections written out:\n\n");

  do
  {
    Message(form("    %8.8s : [%08X] --> [%08X, %08X]\n", SegName(vOffset), vOffset, phyOffset, phySize));

    savefile(fhandle, phyOffset, vOffset, phySize);

    vOffset   = Dword(offset + 0x0c) + iBase;
    phySize   = Dword(offset + 0x10);
    phyOffset = Dword(offset + 0x14);

    offset = offset + 0x28;
  }
  while(--num_sections);

  fclose(fhandle);

  Message("\n  The file has been written out\n");
  Message("-------------------------------------------------------------------------------\n\n");

  return 0;
}
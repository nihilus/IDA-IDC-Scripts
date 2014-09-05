/*
// File:
//   phytorva.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   Convert a physical address to a relative virtal address, based on the PE image
//   being analyzed.
//
//   Also display conversion information.
//
// Usage:
//   Just run the script ;).
//
// Fixes/additions
//   amg - 17-05-2002 - 1st version.
//
*/

#include <idc.idc>

#define NO_MAIN

#include <pe_sections.idc>

static main()
{
  auto loadEXE;
  auto imageBase;
  auto PEoffset, sections, section_count;
  auto signature;
  auto phy;

//  Message("-------------------------------------------------------------------------------\n\n");
//  Message("  The rva to phy conversion script\n  Created by Atli Gudmundsson <agudmundsson@symantec.com>\n\n");
//  Message("-------------------------------------------------------------------------------\n\n");

  imageBase = FirstNamedSeg(PE_HEADER_SECTION_NAME);

  loadEXE = 0;

  if(imageBase == BADADDR)
  {
    auto ask_user;
    ask_user = AskYN(0, "Missing HEADER, do you want me to run the PE_SECTION.IDC script?");

    //  1 - Yes
    //  0 - No
    // -1 - Cancel

    if((ask_user == -1) || (ask_user == 0))
    {
      return -1;
    }

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

  signature = Word(imageBase);

  if((signature != 0x4d5a) && (signature != 0x5a4d))
  {
    WarningMessage("This is not an MZ executable!");
    return -1;
  }

  PEoffset  = Dword(imageBase + 0x3c) + imageBase;
  signature = Dword(PEoffset);

  if(signature != 0x4550)
  {
    WarningMessage("This is not a PE executable!");
    return -1;
  }

  section_count = Word(PEoffset + 0x6);
  sections      = PEoffset + 0x18 + Word(PEoffset + 0x14);

  phy = AskAddr(-1, "Please enter the PHY to convert\n(hex numbers terminated with an h)");

  while(section_count)
  {
    auto section_rva, section_phy, section_vsize, section_psize;

    section_vsize = Dword(sections + 0x08);
    section_rva   = Dword(sections + 0x0c);
    section_psize = Dword(sections + 0x10);
    section_phy   = Dword(sections + 0x14);

    if(!section_vsize)
    {
      section_vsize = section_psize;
    }

    if((section_phy <= phy) && (phy < (section_phy + section_psize)) && (phy < (section_phy + section_vsize)))
    {
      auto out_string;

#if defined(DEBUG_THIS)
      Message("rva:   %08x\n", section_rva);
      Message("vsize: %08x\n", section_vsize);
      Message("phy:   %08x\n", section_phy);
      Message("psize: %08x\n", section_psize);
#endif

      out_string = form("    % 13s: %.8x (rva) <- %.8x (phy)\n", SegName(phy - section_phy + section_rva + imageBase), phy - section_phy + section_rva, phy);

      WarningMessage(out_string);

      Jump(phy - section_phy + section_rva + imageBase);

      break;
    }

    section_count--;
    sections = sections + 0x28;
  }

  if(!section_count)
  {
    // must be an address in the header, lets print that

    WarningMessage(form("    % 13s: %.8x (rva) <- %.8x (phy)\n", SegName(imageBase), phy, phy));
    Jump(phy + imageBase);
  }

//  Message("\n-------------------------------------------------------------------------------\n\n");

  return 0;
}
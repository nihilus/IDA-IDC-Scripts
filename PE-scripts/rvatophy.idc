/*
// File:
//   rvatophy.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   Convert a relative virtal address to a physical address, based on the PE image
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
  auto rva;

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

  rva = AskAddr(here - imageBase, "Please enter the RVA to convert");

  if(SegStart(rva + imageBase) == BADADDR)
  {
    WarningMessage("No physical data backs up this address");
    return -1;
  }

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

    if((section_rva <= rva) && (rva < (section_rva + section_vsize)))
    {
      auto out_string;

#if defined(DEBUG_THIS)
      Message("rva:   %08x\n", section_rva);
      Message("vsize: %08x\n", section_vsize);
      Message("phy:   %08x\n", section_phy);
      Message("psize: %08x\n", section_psize);
#endif

      out_string = "";

      if((section_rva + section_psize) <= rva)
      {
        out_string = "          WARNING: no physical data behind this address\n";
      }

      out_string = out_string + form("    % 13s: %.8x (rva) -> %.8x (phy)\n", SegName(rva + imageBase), rva, rva - section_rva + section_phy);

      WarningMessage(out_string);

      break;
    }

    section_count--;
    sections = sections + 0x28;
  }

  if(!section_count)
  {
    // must be an address in the header, lets print that

    WarningMessage(form("    % 13s: %.8x (rva) -> %.8x (phy)\n", SegName(imageBase), rva, rva));
  }

//  Message("\n-------------------------------------------------------------------------------\n\n");

  return 0;
}
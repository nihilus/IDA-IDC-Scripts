#include <idc.idc>

/*
// File:
//   pe_structs.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   Load needed PE header structures for analyzes
//
// Usage:
//   Just run the script ;).
//
// Fixes/additions
//   amg - 09-05-2001 - 1st version.
//   amg - 20-05-2002 - bugfix: IDA seems to have a namespace confligt between .idc files.
//                        i.e. if two .idc files have a function with the same name, but with
//                        different parameters then, when the second one is executed, IDA will
//                        come up with an error message complaining about the parameters being
//                        incorrect (this happened if you were analysing a non-executable but
//                        accidentaly executed pe_sections.idc before this file).
*/

#define PE_HEADER_SECTION_NAME        "HEADER"

#define MZ_HEADER_STRUCTURE_NAME      "S_MZ_HEADER"
#define PE_HEADER_STRUCTURE_NAME      "S_PE_HEADER"
#define PE_SECTION_STRUCTURE_NAME     "S_PE_SECTION"

#define COFF_STANDARD_STRUCTURE_NAME  "S_COFF_STANDARD"
#define PE_OPTIONAL_STRUCTURE_NAME    "S_PE_OPTIONAL"

#define PE_EXPORT_DIRECTORY_STRUCT    "EXPORT_DIR_ENTRY"
#define PE_IMPORT_DIRECTORY_STRUCT    "IMPORT_DIR_ENTRY"
#define PE_RESOURCE_DIRECTORY_STRUCT  "RESOURCE_DIR_ENTRY"
#define PE_RESOURCE_ENTRY_STRUCT      "RESOURCE_DATA_ENTRY"
#define TLS_DIRECTORY_STRUCT          "TLS_DIR_ENTRY"

//#define IDA_IS_OLD
//
//   comment the above line if you are using v3.85+
// uncomment the above line if you are using pre v3.85

#ifndef NO_MAIN

static main(void)
{
  return LStructs();
}

#endif

static LStructs()
{
  if(LMZStruct() < 0)
  {
    return -1;
  }

  if(LPEStruct() < 0)
  {
    return -1;
  }

  if(LCOFFStd() < 0)
  {
    return -1;
  }

  if(LPEOpt() < 0)
  {
    return -1;
  }

  if(LPESStruct() < 0)
  {
    return -1;
  }

  if(LExportStructs() < 0)
  {
    return -1;
  }

  if(LImportStructs() < 0)
  {
    return -1;
  }

  if(LResourceStructs() < 0)
  {
    return -1;
  }

  if(LTLSStructs() < 0)
  {
    return -1;
  }
}

static WarningMessage(outString)
{
  Message(outString + "\n");
  Warning(outString);
}

static LMZStruct()
{
  auto sHandle;
  auto error;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, MZ_HEADER_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, MZ_HEADER_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(MZ_HEADER_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + MZ_HEADER_STRUCTURE_NAME + " structure!\n");
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
  AddStrucMember(sHandle, "new_hdr_offset",      0x3c, FF_DWRD, -1, 4);
}

static LPEStruct()
{
  auto sHandle;
  auto numInterested;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_HEADER_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, PE_HEADER_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_HEADER_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_HEADER_STRUCTURE_NAME + " structure!\n");
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
  AddStrucMember(sHandle,   "entry_point_RVA",     0x28, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_code",        0x2c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_data",        0x30, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_image",       0x34, FF_DWRD, -1, 4);
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
  AddStrucMember(sHandle,   "stack_reserve",       0x60, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "stack_commit",        0x64, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "heap_reserve",        0x68, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "heap_commit",         0x6c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "loader_flags",        0x70, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "interesting_pairs",   0x74, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "export_table_RVA",    0x78, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "export_table_size",   0x7c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "import_table_RVA",    0x80, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "import_table_size",   0x84, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "resource_table_RVA"   0x88, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "resource_table_size", 0x8c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "exception_table_RVA", 0x90, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "exception_table_size", 0x94, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "security_table_RVA",  0x98, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "security_table_size", 0x9c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "reloc_table_RVA",     0xa0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "reloc_table_size",    0xa4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "debug_table_RVA",     0xa8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "debug_table_size",    0xac, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "image_desc_table_RVA", 0xb0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "image_desc_table_size", 0xb4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "machine_spec_table_RVA",  0xb8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "machine_spec_table_size", 0xbc, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "thread_local_storage_table_RVA", 0xc0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "thread_local_storage_table_size", 0xc4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "load_config_table_RVA",  0xc8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "load_config_table_size", 0xcc, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "bound_import_table_RVA", 0xd0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "bound_import_table_size",0xd4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "IAT_table_RVA",       0xd8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "IAT_table_size",      0xdc, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "delay_import_desc_table_RVA", 0xe0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "delay_import_desc_table_size", 0xe4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "Reserved0_table_RVA", 0xe8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Reserved0_table_size",0xec, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "Reserved1_table_RVA", 0xf0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Reserved1_table_size",0xf4, FF_DWRD, -1, 4);
}

static LCOFFStd()
{
  auto sHandle;
  auto numInterested;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, COFF_STANDARD_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, COFF_STANDARD_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(COFF_STANDARD_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + COFF_STANDARD_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle,   "CPU_Type",            0x00, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "number_of_Sections",  0x02, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "time_date_stamp",     0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "symbol_table_file_offset", 0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "symbol_table_size",   0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "opt_header_size",     0x10, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "flags",               0x12, FF_WORD, -1, 2);
}

static LPEOpt()
{
  auto sHandle;
  auto numInterested;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_OPTIONAL_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, PE_OPTIONAL_STRUCTURE_NAME, 0);
#endif

  if(sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_OPTIONAL_STRUCTURE_NAME);

    if(sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_OPTIONAL_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle,   "COFF_magic",          0x00, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "Linker_version",      0x02, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "size_of_code",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_init_data",   0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_uninit_data", 0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "entry_point_RVA",     0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_code",        0x14, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_data",        0x18, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "base_of_image",       0x1c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "image_alignment",     0x20, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "file_alignment",      0x24, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "OS_version_major",    0x28, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "OS_version_minor",    0x2a, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "User_version_major",  0x2c, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "User_version_minor",  0x2e, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "SubSys_version_major",0x30, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "SubSys_version_minor",0x32, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "Reserved2",           0x34, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_image",       0x38, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "size_of_header",      0x3c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "file_CRC",            0x40, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Sub_System",          0x44, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "DLL_flags",           0x46, FF_WORD, -1, 2);
  AddStrucMember(sHandle,   "stack_reserve",       0x48, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "stack_commit",        0x4c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "heap_reserve",        0x50, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "heap_commit",         0x54, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "loader_flags",        0x58, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "interesting_pairs",   0x5c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "export_table_RVA",    0x60, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "export_table_size",   0x64, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "import_table_RVA",    0x68, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "import_table_size",   0x6c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "resource_table_RVA"   0x70, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "resource_table_size", 0x74, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "exception_table_RVA", 0x78, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "exception_table_size", 0x7c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "security_table_RVA",  0x80, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "security_table_size", 0x84, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "reloc_table_RVA",     0x88, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "reloc_table_size",    0x8c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "debug_table_RVA",     0x90, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "debug_table_size",    0x94, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "image_desc_table_RVA", 0x98, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "image_desc_table_size", 0x9c, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "machine_spec_table_RVA",  0xa0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "machine_spec_table_size", 0xa4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "thread_local_storage_table_RVA", 0xa8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "thread_local_storage_table_size", 0xac, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "load_config_table_RVA",  0xb0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "load_config_table_size", 0xb4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "bound_import_table_RVA", 0xb8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "bound_import_table_size",0xbc, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "IAT_table_RVA",       0xc0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "IAT_table_size",      0xc4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "delay_import_desc_table_RVA", 0xc8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "delay_import_desc_table_size", 0xcc, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "Reserved0_table_RVA", 0xd0, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Reserved0_table_size",0xd4, FF_DWRD, -1, 4);

  AddStrucMember(sHandle,   "Reserved1_table_RVA", 0xd8, FF_DWRD, -1, 4);
  AddStrucMember(sHandle,   "Reserved1_table_size",0xdc, FF_DWRD, -1, 4);
}

static LPESStruct()
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_SECTION_STRUCTURE_NAME);
#else
  sHandle = AddStrucEx(-1, PE_SECTION_STRUCTURE_NAME, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_SECTION_STRUCTURE_NAME);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_SECTION_STRUCTURE_NAME + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "name",                           0x00, FF_ASCI, -1, 8); 
  AddStrucMember(sHandle, "virtual_size",                   0x08, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "relative_virtual_address",       0x0c, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "size_in_file",                   0x10, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "offset_in_file",                 0x14, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "file_offset_to_relocs",          0x18, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "file_offset_to_line_numbers",    0x1c, FF_DWRD, -1, 4); 
  AddStrucMember(sHandle, "number_of_relocs",               0x20, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "number_of_line_numbers",         0x22, FF_WORD, -1, 2); 
  AddStrucMember(sHandle, "flags",                          0x24, FF_DWRD, -1, 4); 
}

static LExportStructs()
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_EXPORT_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, PE_EXPORT_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_EXPORT_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_EXPORT_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "export_flags",           0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "time_date_samp",         0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "version"                 0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name",                   0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "ordinal_base",           0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "address_table_count",    0x14, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name_pointers_count",    0x18, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "address_table",          0x1c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name_pointers",          0x20, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "ordinal_table",          0x24, FF_DWRD, -1, 4);

  return 0;
}

static LImportStructs()
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_IMPORT_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, PE_IMPORT_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_IMPORT_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_IMPORT_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "import_lookup_table",    0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "time_date_stamp",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "forwarder_chain",        0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "name",                   0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "import_address_table",   0x10, FF_DWRD, -1, 4);

  return 0;
}

static LResourceStructs()
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, PE_RESOURCE_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, PE_RESOURCE_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_RESOURCE_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_RESOURCE_DIRECTORY_STRUCT + " structure!\n");
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
  sHandle = AddStruc(-1, PE_RESOURCE_ENTRY_STRUCT);
#else
  sHandle = AddStrucEx(-1, PE_RESOURCE_ENTRY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(PE_RESOURCE_ENTRY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + PE_RESOURCE_ENTRY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "data_RVA",               0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "data_size",              0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "code_page",              0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "reserved",               0x0c, FF_DWRD, -1, 4);

  return 0;
}

static LTLSStructs()
{
  auto sHandle;

#ifdef IDA_IS_OLD
  sHandle = AddStruc(-1, TLS_DIRECTORY_STRUCT);
#else
  sHandle = AddStrucEx(-1, TLS_DIRECTORY_STRUCT, 0);
#endif

  if (sHandle == -1)
  {
    sHandle = GetStrucIdByName(TLS_DIRECTORY_STRUCT);

    if (sHandle == -1)
    {
      WarningMessage("Unable to create the " + TLS_DIRECTORY_STRUCT + " structure!\n");
      return -1;
    }

    return 0;
  }

  AddStrucMember(sHandle, "raw_data_VA",            0x00, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "raw_data_end_VA",        0x04, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "index_VA",               0x08, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "callbacks_VA",           0x0c, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "zero_fill_size",         0x10, FF_DWRD, -1, 4);
  AddStrucMember(sHandle, "characteristics",        0x14, FF_DWRD, -1, 4);

  return 0;
}


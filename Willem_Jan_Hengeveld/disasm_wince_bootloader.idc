// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>

// this script processes a windows ce bootloader image,
// creates the ram segment, processes the romhdr, e32, o32 structs.

// before use, the bootloader needs to be loaded at the correct segment

// todo: automatically find the base address, and move it to that address.
// todo: automatically identify clib functions often used in bootloaders.

static round_up(x)
{
    return (x&3) ? (x|3)+1 : x;
}
static process_bl(base, wm2005)
{
    auto romhdr, cpent, tocent, e32, o32, pdata, its;
    its= wm2005 ? 4 : 0;
    if (Dword(base+0x40)!=0x43454345) {
        Message("no ECEC at %08lx\n", base+0x40);
        return;
    }
    romhdr= Dword(base+0x44);
    if (wm2005) {
        MakeTable(base+0x40, base+0x4c, "a4od");
    }
    else {
        MakeTable(base+0x40, base+0x48, "a4o");
    }

    MakeName(romhdr, "romhdr");
    MakeStructEx(romhdr, 0x54, "struc_romhdr");

// ulRAMStart, ulRAMFree
    SegCreate(Dword(romhdr+0x14), Dword(romhdr+0x18), 0, 1, 4, 0);

    cpent= Dword(romhdr+0x24);  // ulCopyOffset
    MakeName(cpent, "copyentry");
    MakeStructEx(cpent, 0x10, "struc_CopyEntry");

    memcpy(Dword(cpent+4), Dword(cpent), round_up(Dword(cpent+8)));
    MakeName(Dword(cpent), "copydata");
    MakeByte(Dword(cpent));
    MakeArray(Dword(cpent), round_up(Dword(cpent+8)));

    tocent= romhdr+0x54;
    MakeName(tocent, "tocentry");
    MakeStructEx(tocent, 0x20, "struc_TocEntry");

    e32= Dword(tocent+0x14);    // ulE32Offset
    MakeName(e32, "e32entry");
    MakeStructEx(e32, 0x6C+its, "struc_e32rom");

    o32= Dword(tocent+0x18);    // ulO32Offset
    MakeName(o32, "o32list");
    MakeStructEx(o32, 0x18, "struc_o32rom");
    MakeArray(o32, Word(e32));

    pdata= base+Dword(e32+0x38+its);    // unit_EXC.rva
    ParsePdata(pdata, pdata+Dword(e32+0x3C+its));   // unit_EXC.size
    MakeName(pdata, "pdata");
    MakeDword(pdata);
    OpNumber(pdata, 0);
    MakeArray(pdata, Dword(e32+0x3C+its)/4);
}
static find_rvabase() {
    return FirstSeg();
}
static has_wm2005_e32struct(rvabase) {
    auto romhdr; romhdr= Dword(rvabase+0x44);

// 54: sizeof(romhdr)
// 14: TOCentry.ulE32Offset
// 18: TOCentry.ulO32Offset
// todo: sometimes e32 and o32 are not sequentially in memory.
// -> test other romhdr and toc fields too for proximity to e32.

    return (Dword(romhdr+0x54+0x18)-Dword(romhdr+0x54+0x14)) > 0x6c;
}
static main() {
    auto rvabase;
    auto id;
    auto its;
    rvabase= find_rvabase();
    its= has_wm2005_e32struct(rvabase) ? 4 : 0;

	id = AddStrucEx(-1,"struc_FILETIME",0);
	AddStrucMember(id,"ftLow",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"ftHigh",	0X4,	0x20000400,	-1,	4);
	
	id = AddStrucEx(-1,"struc_rvainfo",0);
	AddStrucMember(id,"rva",	0X0,	0x20500400,	rvabase,	4);
	AddStrucMember(id,"size",	0X4,	0x20000400,	-1,	4);

	id = AddStrucEx(-1,"struc_romhdr",0);
	AddStrucMember(id,"dllFirst",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"dllLast",	0X4,	0x20000400,	-1,	4);
	AddStrucMember(id,"physStart",	0X8,	0x20500400,	0X0,	4);
	AddStrucMember(id,"physLast",	0XC,	0x20500400,	0X0,	4);
	AddStrucMember(id,"nummods",	0X10,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulRAMStart",	0X14,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulRAMFree",	0X18,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulRAMEnd",	0X1C,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulCopyEntries",	0X20,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulCopyOffset",	0X24,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulProfileLe",	0X28,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulProfileOffset",	0X2C,	0x20000400,	-1,	4);
	AddStrucMember(id,"numfiles",	0X30,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulKernelFlags",	0X34,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulFSRamPercent",	0X38,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulDrivglobStart",	0X3C,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulDrivglobLen",	0X40,	0x20000400,	-1,	4);
	AddStrucMember(id,"usCPUType",	0X44,	0x10000400,	-1,	2);
	AddStrucMember(id,"usMiscFlags",	0X46,	0x10000400,	-1,	2);
	AddStrucMember(id,"pExtensions",	0X48,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulTrackingStart",	0X4C,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulTrackingLen",	0X50,	0x20000400,	-1,	4);
	
	id = AddStrucEx(-1,"struc_CopyEntry",0);
	AddStrucMember(id,"ulSource",	0X0,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulDest",	0X4,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulCopyLen",	0X8,	0x20000400,	-1,	4);
	AddStrucMember(id,"ulDestLen",	0XC,	0x20000400,	-1,	4);
	
	id = AddStrucEx(-1,"struc_TocEntry",0);
	AddStrucMember(id,"dwFileAttributes",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"ftTime",	0X4,	0x60000400,	GetStrucIdByName("struc_FILETIME"),	8);
	AddStrucMember(id,"nFileSize",	0XC,	0x20000400,	-1,	4);
	AddStrucMember(id,"lpszFileName",	0X10,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulE32Offset",	0X14,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulO32Offset",	0X18,	0x20500400,	0X0,	4);
	AddStrucMember(id,"ulLoadOffset",	0X1C,	0x20500400,	0X0,	4);
	
	id = AddStrucEx(-1,"struc_e32rom",0);
	AddStrucMember(id,"e32_objcnt",	0X0,	0x10000400,	-1,	2);
	AddStrucMember(id,"e32_imageflags",	0X2,	0x10000400,	-1,	2);
	AddStrucMember(id,"e32_entryrva",	0X4,	0x20000400,	-1,	4);
	AddStrucMember(id,"e32_vbase",	0X8,	0x20000400,	-1,	4);
	AddStrucMember(id,"e32_subsysmajor",	0XC,	0x10000400,	-1,	2);
	AddStrucMember(id,"e32_subsysminor",	0XE,	0x10000400,	-1,	2);
	AddStrucMember(id,"e32_stackmax",	0X10,	0x20000400,	-1,	4);
	AddStrucMember(id,"e32_vsize",	0X14,	0x20000400,	-1,	4);
	AddStrucMember(id,"e32_sect14rva",	0X18,	0x20500400,	rvabase,	4);
	AddStrucMember(id,"e32_sect14size",	0X1C,	0x20000400,	-1,	4);
    if (its) {
        AddStrucMember(id,"e32_timestamp",	0X20,	0x20000400,	-1,	4);
    }
	AddStrucMember(id,"unit_EXP",	0X20+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_IMP",	0X28+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_RES",	0X30+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_EXC",	0X38+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_SEC",	0X40+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_FIX",	0X48+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_DEB",	0X50+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_IMD",	0X58+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"unit_MSP",	0X60+its,	0x60000400,	GetStrucIdByName("struc_rvainfo"),	8);
	AddStrucMember(id,"e32_subsys",	0X68+its,	0x20000400,	-1,	4);
	
	id = AddStrucEx(-1,"struc_o32rom",0);
	AddStrucMember(id,"o32_vsize",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"o32_rva",	0X4,	0x20500400,	rvabase,	4);
	AddStrucMember(id,"o32_psize",	0X8,	0x20000400,	-1,	4);
	AddStrucMember(id,"o32_dataptr",	0XC,	0x20500400,	0X0,	4);
	AddStrucMember(id,"o32_realaddr",	0X10,	0x20500400,	0X0,	4);
	AddStrucMember(id,"o32_flags",	0X14,	0x20000400,	-1,	4);
	
	id = AddStrucEx(-1,"struc_debugdirectory",0);
	AddStrucMember(id,"Characteristics",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"TimeDateStamp",	0X4,	0x20000400,	-1,	4);
	AddStrucMember(id,"MajorVersion",	0X8,	0x10000400,	-1,	2);
	AddStrucMember(id,"MinorVersion",	0XA,	0x10000400,	-1,	2);
	AddStrucMember(id,"Type",	0XC,	0x20000400,	-1,	4);
	AddStrucMember(id,"SizeOfData",	0X10,	0x20000400,	-1,	4);
	AddStrucMember(id,"AddressOfRawData",	0X14,	0x20000400,	-1,	4);
	AddStrucMember(id,"PointerToRawData",	0X18,	0x20000400,	-1,	4);


	id = AddStrucEx(-1,"struc_bdkstruct",0);
	AddStrucMember(id,"newsign",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"oldsign",	0X4,	0x20000400,	-1,	4);
	AddStrucMember(id,"signoffset",	0X8,	0x20000400,	-1,	4);
	AddStrucMember(id,"startingblock",	0XC,	0x20000400,	-1,	4);
	AddStrucMember(id,"length",	0X10,	0x20000400,	-1,	4);
	AddStrucMember(id,"flags",	0X14,	0x20000400,	-1,	4);
	AddStrucMember(id,"pBuffer",	0X18,	0x20000400,	-1,	4);

	id = GetStrucIdByName("struc_doc_command");
	AddStrucMember(id,"partitionnr",	0X0,	0x20000400,	-1,	4);
	AddStrucMember(id,"field_4",	0X4,	0x20000400,	-1,	4);
	AddStrucMember(id,"field_8",	0X8,	0x20000400,	-1,	4);
	AddStrucMember(id,"pBuf",	0XC,	0x20000400,	-1,	4);
	AddStrucMember(id,"sectornr",	0X10,	0x20000400,	-1,	4);
	AddStrucMember(id,"sectorcount",	0X14,	0x20000400,	-1,	4);
	
    process_bl(rvabase, its);
}


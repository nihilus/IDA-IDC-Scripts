// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>

// THIS SCRIPT IS NOT FINISHED

// attempt to automatically parse resources.
//



//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;

	id = AddStrucEx(-1,"struc_resource_directory",0);
	id = AddStrucEx(-1,"struc_resource_directory_entry",0);
	id = AddStrucEx(-1,"struc_resource_data_entry",0);
	
	id = GetStrucIdByName("struc_resource_directory");
	AddStrucMember(id,"characteristics",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"timedatestamp",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"majorversion",	0x8,	0x10000400,	-1,	2);
	AddStrucMember(id,"minorversion",	0xa,	0x10000400,	-1,	2);
	AddStrucMember(id,"NumberOfNamedEntries",	0xc,	0x10000400,	-1,	2);
	AddStrucMember(id,"NumberOfIdEntries",	0xe,	0x10000400,	-1,	2);
	
	id = GetStrucIdByName("struc_resource_directory_entry");
	AddStrucMember(id,"name",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"offsetToData",	0x4,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("struc_resource_data_entry");
	AddStrucMember(id,"offsetToData",	0x0,	0x20000400,	-1,	4);
	AddStrucMember(id,"size",	0x4,	0x20000400,	-1,	4);
	AddStrucMember(id,"codepage",	0x8,	0x20000400,	-1,	4);
	AddStrucMember(id,"reserved",	0xc,	0x20000400,	-1,	4);
}

// root is a rva, ea is an offset relative to the root.
// first call should be ParseResources(..., 0)
// levels:
//    0 = root : contains type entries
//    1 = names: contains id entries
//    2 = lang : contains language entries
//    3 = data : contains data
static ParseResources(root, ea, level) {
    auto i;
    auto nrNamed;
    auto nrId;
    auto ofs;
    nrNamed= Word(root+ea+0xc);
    nrId= Word(root+ea+0xe);

    ofs= ea+0x10;
    for (i=0 ; i<nrNamed ; i++)
    {
        ParseNamedResource(root, ofs);
        ofs= ofs+8;
    }
    for (i=0 ; i<nrId ; i++)
    {
        ParseIdResource(root, ofs);
        ofs= ofs+8;
    }
}
static ParseNamedResource(root, ea)
{
    auto name;
    auto data;

    name= Dword(root+ea);
    data= Dword(root+ea+4);

}
static ParseIdResource(root, ea)
{
    auto id;
    auto data;

    id= Dword(root+ea);
    data= Dword(root+ea+4);
    if (data&0x80000000) {
        Message("resource directory %d\n", id);
        ParseResources(root, data&0x7fffffff, 0);
    }
}
// End of file.

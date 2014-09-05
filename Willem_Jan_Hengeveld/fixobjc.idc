// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>

// this script processes the objective C typeinfo tables,
// and names functions accordingly.
// greatly improving the disassembly of objective C programs

// todo: set function type: int objc_msgSend(_DWORD, _DWORD, ...)

static create_mthnames(ea0, ea1, name, type)
{
    auto ea;
    for (ea=ea0 ; ea<ea1 ; ea=ea+12)
    {
        MakeName(Dword(ea+8), name+"::"+type+String(Dword(ea)));
	// todo: use typeinfo encoded in String(Dword(ea+4))
    }
}
static fix__objc_binary()
{
    auto rea, ea,segea,name, i, origc,cmt,n,id,type,ofs,size;
    segea=SegByBase(SegByName("__class"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__class_struct") {
            name=String(Dword(ea+8));
            Message("%08lx %s\n", ea, name);
            MakeName(ea, form("class_%s", name));
            MakeName(Dword(ea+0x18), form("ivars_%s", name));	// instance vars
            MakeName(Dword(ea+0x1c), form("methods_%s", name));	// methods
            create_mthnames(Dword(ea+0x1c)+8, Dword(ea+0x1c)+8+12*Dword(Dword(ea+0x1c)+4), name, "");
	    // todo: create meta_class_methods ( Dword(ea+0x24)
        }
    }
    segea=SegByBase(SegByName("__meta_class"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__class_struct") {
            name=String(Dword(ea+8));
            Message("%08lx %s\n", ea, name);
            MakeName(ea, form("metaclass_%s", name));
            if (Dword(ea+0x18)) {	// instance vars
                MakeName(Dword(ea+0x18), form("metaivars_%s", name));
            }
            if (Dword(ea+0x1c)) {	// methods
                MakeName(Dword(ea+0x1c), form("metamethods_%s", name));
                create_mthnames(Dword(ea+0x1c)+8, Dword(ea+0x1c)+8+12*Dword(Dword(ea+0x1c)+4), name, "static_");
            }
	    // todo: meta_class_methods ( Dword(ea+0x24)
        }
    }
    segea=SegByBase(SegByName("__protocol"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__protocol_struct") {
            name=String(Dword(ea+4));
            Message("%08lx %s\n", ea, name);
            if (MakeName(ea, form("protocol_%s", name))) {
                if (Dword(ea+0xc)) {	// instance methods
                    MakeName(Dword(ea+0xc), form("protomth_%s", name));
                }
            }
	    // todo: better handling of name collisions
            else if (MakeName(ea, form("protocol_%s_1", name))) {
                if (Dword(ea+0xc)) {	// instance methods
                    MakeName(Dword(ea+0xc), form("protomth_%s_1", name));
                }
            }
	    // todo: class_methods : Dword(ea+0x10)
        }
    }
    segea=SegByBase(SegByName("__category"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__category_struct") {
            name=String(Dword(ea+4))+"_"+String(Dword(ea));	// class _ category
            Message("%08lx %s\n", ea, name);
            MakeName(ea, form("category_%s", name));
            if (Dword(ea+0x8)) {	// methods -> seg __cat_inst_meth
                MakeName(Dword(ea+0x8), form("catmths_%s", name));
                create_mthnames(Dword(ea+0x8)+8, Dword(ea+0x8)+8+12*Dword(Dword(ea+0x8)+4), name, "cat_");
            }
	    // todo: class methods -> __cat_cls_meth
        }
    }
    segea=SegByBase(SegByName("__module_info"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__module_info_struct") {
            MakeName(Dword(ea+0xC), form("symtab_%X", Dword(ea+0xC)));
        }
    }
    segea=SegByBase(SegByName("__cfstring"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__cfstring_struct") {
            if (!MakeName(ea, "cfs_"+Name(Dword(ea+8))))
            {
                i=0;
                while (!MakeName(ea, form("cfs_%s_%d",Name(Dword(ea+8)),i)))
                    i++;
            }
            for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
            {
                MakeComm(rea, String(Dword(ea+8)));
            }
        }
    }
    segea=SegByBase(SegByName("__message_refs"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (!MakeName(ea, "msg_"+Name(Dword(ea))))
        {
            i=0;
            while (!MakeName(ea, form("msg_%s_%d",Name(Dword(ea)),i)))
                i++;
        }
        for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
        {
            MakeComm(rea, "message "+String(Dword(ea)));
        }
    }
    segea=SegByBase(SegByName("__cls_refs"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (!MakeName(ea, "cls_"+Name(Dword(ea))))
        {
            i=0;
            while (!MakeName(ea, form("cls_%s_%d",Name(Dword(ea)),i)))
                i++;
        }
        for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
        {
            MakeComm(rea, "class "+String(Dword(ea)));
        }
    }

    segea=SegByBase(SegByName("__instance_vars"));
    for (ea= SegStart(segea) ; ea<SegEnd(segea) ; )
    {
        n=Dword(ea);
        if (n==0) {
            ea=ea+4;
        }
        else {
            id=AddStruc(-1, Name(ea)+"_struct");
            ea=ea+4;
            while (n--) {
                type=String(Dword(ea+4));
                ofs=Dword(ea+8);
                name=String(Dword(ea));
                if (type=="c") { size=1; }
                else if (type=="i") { size=4; }
                else if (type=="I") { size=4; }
                else if (type=="l") { size=4; }
                else if (type=="S") { size=4; }
                else if (type=="q") { size=8; }
                else if (type=="Q") { size=8; }
                else if (type=="B") { size=4; }
                else if (type=="f") { size=4; }
                else if (type=="d") { size=8; }
                else if (substr(type,0,1)=="[") {
                    if (strstr(type,"@")!=-1) {
                        size=4*atol(substr(type,1,-1));
                    }
                    else {
                        Message("%08lx: unrecognized type: %s\n", ea, type);
                        size=4*atol(substr(type,1,-1));
                        if (size==0)
                            size=4;
                    }
                }
                else if (substr(type,0,1)=="@") {
                    size=4;
                }
                else {
                    Message("%08lx: unrecognized type: %s\n", ea, type);
                    size=4;
                }
                AddStrucMember(id, name, ofs, FF_DWRD, -1, size);

                ea=ea+0xc;
            }
        }
    }
    // todo: analyse 'objc_msgSend' calls, and add code refs
    // todo: create class_<name>  and vtbl_<name>  from ivars+methods
    // todo: create __cfstring_struct in seg
    // todo: create align 40h  between __class items and __meta_class item  s
    // todo: create align 20h  between __cls_meth, __inst_meth, __instance_vars, __symbols
    // todo: create dword arrays for __eh_frame
    // todo: const_coal contains obj defs + ptr to vtables too
    // todo: rename __pointers -> { __data -> __cstring ptrs, __data -> __cfstring, ... }
}
static main()
{
    fix__objc_binary();
}

//vim:ft=cpp:

// nameinfo:
//   vtbl_typeinfo  <-- ea
//   0
//   namechars

// ... exceptioninfo also contains ptrs to nameinfo of exception classes
//
// classinfo:
//   0
//   0
//   0
//   nameinfo_ptr  <-- tea
//   inheritanceinfo_ptr

// inheritanceinfo:  <-- ttea
//   0
//   0
//   n
//   baselist_ptr

// baselist:
//   objectinfo1_ptr
//   ..
//   objectinfon_ptr

// objectinfo:
//   nameinfo_ptr
//   5 dwords
//   inheritanceinfo_ptr

// todo: 
//   - process exception info
//   - find typeinfo through string '.?AVtype_info@@'
//   - also name constructors + destructors
//   - set 'this' type for the functions involved.
//   - try to name methods for baseclasses first.
//   - also name mfc msgtables.

auto ea,n,nx,tea,vea,fea,log,ofs,fn,ttea,oea;
auto ea_str, tea_str, vea_str,i;
auto typeinfo; typeinfo= here;
ea_str=dword_to_findstr(typeinfo);
ea=FirstSeg();
Message("searching %08lx %s\n", ea, ea_str);
while ((ea=FindBinary(ea,SEARCH_CASE|SEARCH_NEXT|SEARCH_DOWN, ea_str))!=BADADDR)
{
    if (ea>=0xed0000 && Dword(ea)==typeinfo) {
        n= String(ea+8);
        if (substr(n,1,6)=="?AV?$") {
           n=substr(n,6,strstr(n,"@"));
        }
        else if (substr(n,1,4)=="?AV") {
           n=substr(n,4,strstr(n,"@"));
        }
        else if (substr(n,1,4)=="?AU") {
           n=substr(n,4,strstr(n,"@"));
        }
        else if (substr(n,1,4)=="PAV") {
           n="P"+substr(n,4,strstr(n,"@"));
        }
        if (!MakeNameEx(ea, "name_"+n, SN_NOWARN)) {
		i=1;
		while (!MakeNameEx(ea, "name_"+n+form("X%d", i), SN_NOWARN)) {
			i++;
		}
		n=n+form("X%d", i);
	}
	MakeTable(ea, ea+8+(strlen(String(ea+8))|3)+1,"odal");

        tea_str=dword_to_findstr(ea);
	tea=FirstSeg();
        while ((tea=FindBinary(tea,SEARCH_CASE|SEARCH_NEXT|SEARCH_DOWN, tea_str))!=BADADDR)
        {
            if (Dword(tea)==ea && Dword(tea-12)==0 && Dword(tea-4)<FirstSeg()) {
                vea_str=dword_to_findstr(tea-12);
		vea=FirstSeg();
		if (FindBinary(vea,SEARCH_CASE|SEARCH_NEXT|SEARCH_DOWN, vea_str)==BADADDR) {
			continue;
		}
		ofs=Dword(tea-8);
		if (ofs) {
			nx = n+form("%02X", ofs);
		}
		else {
			nx= n;
		}
		MakeTable(tea-12, tea+8, "dddoo");
		Message("class: %x %x %x  %s\n", Dword(tea-12), Dword(tea-8), Dword(tea-4), nx);
		if (!MakeNameEx(tea-12, "class_"+nx, SN_NOWARN))
			Message("rename error class: %08lx->%08lx\n", ea, tea);

		ttea= Dword(tea+4);
		if (ttea) {
			MakeTable(ttea, ttea+16, "dddo");
			Message("tree: %x %x %x\n", Dword(ttea), Dword(ttea+4), Dword(ttea+8));
			if (!MakeNameEx(ttea, "treeinfo_"+nx, SN_NOWARN))
				Message("rename error treeinfo: %08lx->%08lx->%08lx\n", ea, tea, ttea);

			MakeTable(Dword(ttea+12), Dword(ttea+12)+4*Dword(ttea+8), "o");
			if (!MakeNameEx(Dword(ttea+12), "baselist_"+nx, SN_NOWARN))
				Message("rename error baselist: %08lx->%08lx->%08lx->%08lx\n", ea, tea, ttea, Dword(ttea+12));
			for (i=0 ; i<Dword(ttea+8) ; i++)
			{
				oea= Dword(Dword(ttea+12)+4*i);
				MakeTable(oea, oea+7*4, "odddddo");
				Message("obj: %x %x %x %x %x\n", Dword(oea+4), Dword(oea+8), Dword(oea+12), Dword(oea+16), Dword(oea+20));
				if (!MakeNameEx(oea, "objinfo_"+String(Dword(oea)+8), SN_NOWARN))
					if (!MakeNameEx(oea, "objinfo_"+String(Dword(oea)+8)+form("%02x", Dword(oea+20)), SN_NOWARN))
					if (!MakeNameEx(oea, "objinfo_"+String(Dword(oea)+8)+form("%02x_%02x", Dword(oea+20), Dword(oea+0)), SN_NOWARN))
						Message("rename error objinfo: %08lx->%08lx->%08lx->%08lx->%08lx\n", ea, tea, ttea, Dword(ttea+12), oea);
			}
		}

 
                while ((vea=FindBinary(vea,SEARCH_CASE|SEARCH_NEXT|SEARCH_DOWN, vea_str))!=BADADDR) {
                    if (Dword(vea)==(tea-12) && !isCode(GetFlags(vea)) && !isTail(GetFlags(vea))) {
			MakeTable(vea, vea+4, "o");
                        if (!MakeNameEx(vea+4, "vtbl_"+nx, SN_NOWARN))
				Message("rename error vtbl: %08lx->%08lx->%08lx\n", ea, tea, vea);
                        fea=vea+4;
                        do {
                            fn= Name(Dword(fea));
                            if (substr(fn,0,4)=="sub_" || strstr(fn, "_fn")!=-1) {
                                if (!MakeNameEx(Dword(fea), form("%s_fn%02x", nx, fea-vea-4), SN_NOWARN))
					Message("rename error fn: %08lx->%08lx->%08lx->%08lx\n", ea, tea, vea, fn);
                            }
                            fea=fea+4;
                        } while ((GetFlags(fea)&FF_ANYNAME)==0);
                        Message("%08lx->%08lx->%08lx: ntv %3d %s\n", ea, tea, vea, (fea-vea-4)/4, nx);
                    }
                    else {
                        Message("%08lx->%08lx->%08lx: n++ %s\n", ea, tea, vea, nx);
                    }
                }
            }
            else if (Dword(tea+12)==0xFFFFFFFF && 
			   FindBinary(FirstSeg(), SEARCH_CASE|SEARCH_NEXT|SEARCH_DOWN, dword_to_findstr(tea))!=BADADDR) {
                Message("%08lx->%08lx: nc- %s\n", ea, tea, n);
            }
            else {
                Message("%08lx->%08lx: n-- %s\n", ea, tea, n);
            }
        }
    }
}


// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>
// this script tries to name function arguments 'farg4', 'farg5', etc
// ( the first 4 arguments are always in R0 .. R3 on the arm )
// and name the stack area resevers for passing arguments to other functions
// 'arg4', 'arg5', ...
//
// this script tries to determine how many arguments a function needs.

// note: this script does not yet work very well.

// 
//     E52DE004   STR LR, [SP,#-4]!    : PUSH {LR}
//     E49DE004   LDR LR, [SP],#4      : POP {LR}

// this changes the prepushed args to 'arg%X'
// and the functions args to  farg%X
static analyzefuncframe(fea, recurse)
{
    auto fstart, fend, ea, n, maxarg;
    auto f,m, argn, fargn;
    auto foundpush;
    auto foundpop;

    fstart=GetFunctionAttr(fea, FUNCATTR_START);
    fend= GetFunctionAttr(fea, FUNCATTR_END);
    maxarg= 0;
    for (ea=fstart ; ea!=BADADDR ; ea=NextHead(ea, fend))
    {
        if (Dword(ea)==0xE52DE004) {
            OpNumber(ea, 1);
            foundpush++;
        }
        if (Dword(ea)==0xE49DE004) {
            OpNumber(ea, 1);
            foundpop++;
        }
        if (recurse && GetMnem(ea)=="BL") {
            n= analyzefuncframe(Rfirst0(ea), 0);
            if (n>maxarg)
                maxarg= n;
        }
    }
    if (foundpush==1 && foundpop==1)
        return 4;

    f= GetFrame(fea);
    argn=4;
    fargn=4;
    for (m= GetFirstMember(f); m!=BADADDR ; m=GetStrucNextOff(f, m)) {
        if (argn<maxarg) {
            SetMemberName(f, m, form("arg%X", argn));
            argn++;
        }

        if (substr(GetMemberName(f,m),0,4)=="arg_" || substr(GetMemberName(f,m),0,4)=="farg") {
            SetMemberName(f,m, form("farg%X", fargn));
            fargn++;
        }
    }
    Message("%08lx: change frame to %d args, %d fargs\n", fea, argn, fargn);
    return fargn;

}

// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>
// this script tries to find unintended references
// for instance constants which were incorrectly interpreted as offsets by IDA

static fisstrange(f_start) {
    auto ea, f_end, x, i, is_c, is_t;
    auto next;
    next=0;

    f_end= FindFuncEnd(f_start);

    ea= NextAddr(f_start);
    if (GetReg(f_start, "T")==1) {
        ea= NextAddr(ea);
    }
    while (ea<f_end && ea!=BADADDR) {
        is_t= isTail(GetFlags(ea));
        is_c= isCode(GetFlags(ea));
        i= i+1;
        x= RfirstB0(ea);

        while (x!=BADADDR) {
            if (is_t || x < f_start || f_end <= x) {
                Message("strange code ref: %08lx %s\n", ea, Name(ea));
                if (ea>ScreenEA() && next==0) { next= ea; }
                break;
            }
            x= RnextB0(ea, x);
        }
        x= DfirstB(ea);
        while (x!=BADADDR) {
            if (is_t || x < f_start || f_end <= x) {
                if (is_t || is_c || isData(GetFlags(x))) {
                    Message("strange data ref: %08lx %s\n", ea, Name(ea));
                    if (ea>ScreenEA() && next==0) { next= ea; }
                    break;
                }
            }
            x= DnextB(ea, x);
        }
        ea= NextAddr(ea);
    }
    if (next) {
        Jump(next);
        return 1;
    }
    return 0;
}
static findstrange(void) {
    auto ea;

    ea= ScreenEA();

    ea= NextFunction(ea);
    while (ea!=BADADDR) {
        if (fisstrange(ea)) {
            Message("Function %08lx %s\n", ea, Name(ea));
            return;
        }
        ea= NextFunction(ea);
    }
    Message("No strange refs found after cursor line\n");
}

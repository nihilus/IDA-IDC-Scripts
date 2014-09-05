// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#include <idc.idc>

// these are all very experimental functions, which are quite unfinished.
// it is an attempt to simulate arm instructions.

static DataStart()
{
    return FindData(0,1);
}
static DataEnd()
{
    return FindCode(0,1);
}
static CodeStart()
{
    return FindCode(0,1);
}
static CodeEnd()
{
    return FindCode(0,0);
}
static FixDatasegment()
{
    auto ea,v,x;
    ea=DataStart();
    while(ea<DataEnd()) {
        if (Dword(ea)==0x85e0b100) { MakeTable(ea, ea+15, "g"); }
        ea= ea+4;
    }
    ea=DataStart();x=0;
    while(ea<DataEnd()) {
        v=Dword(ea);
        if (v==0xffffffff || (v>0 && v<10)) { 
           if (x==0) { x= ea; }
        }
        else {
           if (x && (ea-x)/4>1) { 
              MakeDword(x); MakeArray(x, (ea-x)/4);
           }
           x=0;
        }
        ea= ea+4;
    }
    ea=DataStart();
    while(ea<DataEnd()) {
        v=Dword(ea);
        if (v>=DataStart() && v<DataEnd()) {
            MakeTable(ea,ea+4, "s");
        }
        if (v>=CodeStart() && v<CodeEnd()) {
            MakeTable(ea,ea+4, "o");
        }
        ea= ea+4;
    }
    ea=DataStart();x=0;
    while(ea<DataEnd()) {
        v=GetFlags(ea);
        if (isUnknown(v)) { 
           if (x==0) { x= ea; }
        }
        else {
           if (x) { 
              MakeTable(x, ea, "Al");
           }
           x=0;
        }
        ea= ea+4;
    }
}
static FixFlow() {
    auto ea; ea=CodeStart();
    while(ea<CodeEnd()) {
        if (isCode(GetFlags(ea-4)) && isCode(GetFlags(ea)) && isCode(GetFlags(ea+4)) 
                      && !refersto(ea, ea+4) &&
            isMovPC(ea) && isMovLR(ea-4)) {
            AddCodeXref( ea, ea+4, fl_F);
            SetFlags(ea+4, GetFlags(ea+4)|FF_FLOW);
            Message("fixed %08lx\n", ea);
        }
        ea= ea+4;
    }
}
static refersto(from, to) {
    return (Rfirst(from)==to);
}
static isMovPC(ea)
{
    return (GetMnem(ea)=="MOV" && GetOpnd(ea, 0)=="PC");
}
static isMovLR(ea)
{
    return (GetMnem(ea)=="MOV" && GetOpnd(ea, 0)=="LR");
}
static printrefs() 
{
    auto ea,o; ea= ScreenEA(); 
    o=Rfirst(ea); Message("Rfirst(%08lx) :", ea); while (o!=BADADDR) { Message(" %08lx", o); o= Rnext(ea, o); } Message("\n");
    o=RfirstB(ea); Message("RfirstB(%08lx) :", ea); while (o!=BADADDR) { Message(" %08lx", o); o= RnextB(ea, o); } Message("\n");
    o=Rfirst0(ea); Message("Rfirst0(%08lx) :", ea); while (o!=BADADDR) { Message(" %08lx", o); o= Rnext0(ea, o); } Message("\n");
    o=RfirstB0(ea); Message("RfirstB0(%08lx) :", ea); while (o!=BADADDR) { Message(" %08lx", o); o= RnextB0(ea, o); } Message("\n");
}
static FindThreadProcs()
{
    auto o;
    auto o_t;o_t= LocByName("CreateThread");
    o= RfirstB0(o_t);
    while(o!=BADADDR) {
        FindThreadProc(o);
        o= RnextB0(o_t, o);
    }
}
static FindThreadProc(ea)
{
    auto opnd,addr;
    while(RfirstB0(ea)==BADADDR)
    {
        if (GetOpnd(ea,0)=="R2" && GetMnem(ea)=="LDR")
        {
            opnd= GetOpnd(ea,1);
            addr= LocByName(substr(opnd,1, -1));
            if (substr(opnd,0,1)=="=" && addr!=BADADDR)
            {
                Message("threadproc: %08lx %08lx (%s)\n", ea, addr, opnd);
                MakeName(addr, form("threadproc_%08lx", addr));
            }
            else {
                Message("no threadproc found for %08lx : %s\n", ea, opnd);
            }
            break;
        }
        ea= ea-4;
    }
}
static ClearHash(n)
{
    auto k;
    k= GetFirstHashKey(n);
    while (k!="")
    {
        DelHashElement(n,k);
        k= GetNextHashKey(n,k);
    }
}

// function tries to calculate register values and create names for the RIL_IOControl 
// function cases.
static ParseIoctl()
{
    auto n,ea, end, x,opnd,addr;
    x= 0;
    ea= LocByName("RIL_IOControl");
    end= NextFunction(ea);
    ClearHash(1);
    while(ea<end) {
        if (RfirstB0(ea)!=BADADDR)    // xrefs to here
            ClearHash(1);
        if (GetMnem(ea)=="MOV" && substr(GetOpnd(ea,1),0,1)=="#")
            SetHashLong(1, GetOpnd(ea,0), GetOperandValue(ea,1));

        if (GetMnem(ea)=="ORR" && GetOpnd(ea,1)=="R3" && substr(GetOpnd(ea,2),0,1)=="#")
            SetHashLong(1, GetOpnd(ea,0), GetHashLong(1, GetOpnd(ea,0)) | GetOperandValue(ea,2));

//        if (DoesUpdateStatus(Dword(ea)))   // updates status bit?
        n= Dword(ea);
        if ( (((n>>25)&7)==0 || ((n>>25)&7)==1) && (n&0x00100000)!=0)
        {
            x= 0;
            Message("set status: %08lx %s\n", ea, GetMnem(ea));
        }
        if (GetMnem(ea)=="CMP")
        {
            opnd= "";
            if (GetOpnd(ea,0)=="R7") opnd=GetOpnd(ea,1);
            if (GetOpnd(ea,1)=="R7") opnd=GetOpnd(ea,0);
            x= GetHashLong(1, opnd);
            Message("cmp: %08lx %s == %s(%08lx)\n", ea, GetOpnd(ea,0), GetOpnd(ea,1), x);
        }
        if (GetMnem(ea)=="B" && x && (Dword(ea)>>28)==1)    // BNE
        {
            addr= ea+4;
            MakeName(addr, form("handle_ioctl_%08lx_%08lx", x, addr));
            Message("  set %08lx to %08lx\n", addr, x);

            x= 0;
        }

        if (GetMnem(ea)=="B" && x && (Dword(ea)>>28)==0)    // BEQ
        {
            opnd= GetOpnd(ea,0);
            addr= LocByName(opnd);
            MakeName(addr, form("handle_ioctl_%08lx_%08lx", x, addr));
            Message("  set %08lx (%08lx) to %08lx\n", addr, opnd, x);
            x= 0;
        }
//        if (x) Message("%08lx : %08lx %s\n", ea, x, GetMnem(ea));
        ea= ea+4;
    }
}
static DoesUpdateStatus(n)
{
    return ( (((n>>25)&7)==0 || ((n>>25)&7)==1) && (n&0x00100000)!=0);
}

static FixStacks()
{
    auto ea; ea= NextFunction(0);
    while ( ea!=BADADDR)
    {
        FixFuncStack(ea, FindFuncEnd(ea));
        ea= NextFunction(ea);
    }
}

// this function is not finished, the idea is to automatically create function stack frames
static FixFuncStack(start, end)
{
    auto parammap;  // what parameters are saved to be referenced
    auto savedmap;  // what parameters are saved to be referenced
    auto ea;
    auto ea_save;
    auto ea_locals;
    auto savedsize;
    auto localsize;
    auto frameid;
    
    ea= start;

    /*
     * function start is one of these cases:
     *
     * case 1:  ( with references to parameters )
     * MOV   R12, SP
     * STMFD SP!, {Ra-Rb}           // a,b in range 0-3
     * STMFD SP!, {Rx-Ry,R12,LR}    // x,y in range 4-11
     * ...
     * LDMFD SP!, {Rx-Ry,SP,PC}
     *
     * case 2: normal save regs.
     * STMFD SP!, {Rx-Ry,LR}    // x,y in range 4-11
     * ...
     * LDMFD SP!, {Rx-Ry,PC}
     */

    if (GetMnem(ea)=="MOV" && GetOpnd(ea,0)=="R12" && GetOpnd(ea,1)=="SP")
    {
        ea= ea+4;
        // references to params 0-3
        if (GetMnem(ea)=="STM" && GetOpnd(ea,0)=="SP!")
        {
            parammap= Dword(ea)&0xffff;
            ea= ea+4;
        }
        else {
            Message("unknown function entry1: %08lx  %s %s\n", ea, GetMnem(ea), GetOpnd(ea,0));
            return;
        }
    }
    if (GetMnem(ea)=="STM" && GetOpnd(ea,0)=="SP!")
    {
        savedmap= Dword(ea)&0xbfff; // ignore LR

        ea_save= ea;
        ea= ea+4;
    }
    else {
        Message("unknown function entry2: %08lx  %s %s\n", ea, GetMnem(ea), GetOpnd(ea,0));
        return;
    }

    savedsize= 4*CountBits(savedmap);
    /*
     * local variable reservation is one of these cases:
     *
     * case 1: large reservation
     * MOV   R12, =CONSTANT
     * SUB   SP, SP, R12
     * ...
     * MOV   R12, #0x...
     * ORR   R12, R12, #0x...
     * ADD   SP, SP, R12
     *
     * case 2: small reservation
     * SUB   SP, SP, #0x...
     * ...
     * ADD   SP, SP, #0x...
     */

    if (GetMnem(ea)=="LDR" && GetOpnd(ea, 0)=="R12" && substr(GetOpnd(ea,1),0,1)=="=")
    {
        localsize=Dword(GetOperandValue(ea,1));
        ea= ea+4;
    }
    if (GetMnem(ea)=="SUB"  && GetOpnd(ea, 0)=="SP" && GetOpnd(ea,1)=="SP")
    {
        ea_locals= ea;
        if (substr(GetOpnd(ea,2),0,1)=="#")
            localsize= GetOperandValue(ea,2);

        ea= ea+4;
    }
    else {
        localsize= 0;
        ea_locals= 0;
        //Message("unknown function entry3: %08lx  %s %s\n", ea, GetMnem(ea), GetOpnd(ea,0));
        //return;
    }

    /*
     * function exit is one of these cases:
     *
     * case 1: normal exit
     * LDMFD SP!, {...,PC}
     *
     * case 2: jump to subroutine
     * LDMFD SP!, {...,LR}
     * B     sub
     *
     */

// GetFrameArgsSize()!=0 || GetFrameSize()!=4 || GetFrameRegsSize()!=0 || GetFrameLvarSize()!=0

    if (GetSpd(ea)!=0 || GetFrameArgsSize(ea)!=0 || GetFrameSize(ea)!=4 || GetFrameRegsSize(ea)!=0 || GetFrameLvarSize(ea)!=0)
    {
        if (-GetSpd(ea)!=savedsize+localsize)
        {
            Message("spd=%08lx  calced: %08lx\n", GetSpd(ea), savedsize+localsize);
        }
        if (GetFrameRegsSize(ea)!=savedsize)
        {
            Message("saved=%08lx  calced: %08lx\n", GetFrameRegsSize(ea), savedsize);
        }
        if (GetFrameLvarSize(ea)!=localsize)
        {
            Message("local=%08lx calced: %08lx\n", GetFrameLvarSize(ea), localsize);
        }
    }
    Message(" regs=%04x locals=%04x\n", savedsize, localsize);
    SetSpDiff(ea_save, -savedsize);
    if (ea_locals) { SetSpDiff(ea_locals, -localsize); }
    frameid= MakeFrame(ea, localsize, savedsize, 0);
    while (ea<end)
    {
        if (GetMnem(ea)=="STR" || GetMnem(ea)=="LDR")
        {
            if (substr(GetOpnd(ea,1),0,5)=="[SP,#")
            {
                // todo: add variable with
                //   AddStrucMember(frameid, "varname", 0, FF_DWRD, -1, 1);
                OpStkvar(ea,1);
            }
        }
        if (GetMnem(ea)=="MOV" && GetOpnd(ea,1)=="SP")
        {
            // todo: add variable with
            //   AddStrucMember(frameid, "varname", 0, FF_DWRD, -1, 1);
            OpStkVar(ea,2);
        }
        ea= ea+4;
    }
}
static GetBits(dw, b0, b1)
{
    return (dw>>b1)&( (1<<(b0-b1+1))-1 );
}
static GetBit(dw, b)
{
    return (dw>>b)&1;
}

// this function is also not ready.
// the intention is to assist in calculating register values.
static DecodeInsn(op)
{
    if (GetBits(op, 31,28)==15 && GetBit(op, 27)==0)
    {
        // this is the exception '[1a]'
        // undefined instruction [4,7]  ( unpredictable <armv5 )
    }
    else if (GetBits(op, 27,25)==0 && GetBit(op,4)==0)
    {
        if (GetBits(op, 24,23)==2 && GetBit(op,20)==0)
        {
            // misc  instructions - fig3-3
            // cond= GetBits(op, 31,28)      [1a]
            HandleFigure33(op);
        }
        else {
            // data processing immediate shift
            // cond= GetBits(op, 31,28)      [1a]
            // opcode=GetBits(op, 24,21);
            // s=     GetBit(op, 20);
            // Rn=    GetBits(op, 19,16);
            // Rd=    GetBits(op, 15,12);
            // shifta=GetBits(op, 11,7);
            // shift =GetBits(op, 6,5);
            // Rm=    GetBits(op, 3,0);
        }

    }
    else if (GetBits(op, 27,25)==0 && GetBit(op,7)==0 && GetBit(op,4)==1)
    {
        if (GetBits(op, 24,23)==2 && GetBit(op,20)==0)
        {
            // this is the exception '[2a]'
            // misc  instructions  see fig 3-3
            // cond= GetBits(op, 31,28)      [1a]
            HandleFigure33(op);
        }
        else {
            // data processing register shift  [2a]
            // cond= GetBits(op, 31,28)      [1a]
            // opcode=GetBits(op, 24,21);
            // s=     GetBit(op, 20);
            // Rn=    GetBits(op, 19,16);
            // Rd=    GetBits(op, 15,12);
            // Rs=    GetBits(op, 11,8);
            // shift =GetBits(op, 6,5);
            // Rm=    GetBits(op, 3,0);
        }
    }
    else if (GetBits(op, 27,25)==0 && GetBit(op,7)==1 && GetBit(op,4)==1)
    {
        // multiplies, extra load stores see fig 3-2
        // cond= GetBits(op, 31,28)      [1a]
        HandleFigure32(op);
    }
    else if (GetBits(op, 27,25)==1)
    {
        if (GetBits(op, 24,23)==2 && GetBits(op,21,20)==0)
        {
            // this is the exception [2b]
            // undefined instruction [3]  ( unpredictable <armv4 )
        }
        else if (GetBits(op, 24,23)==2 && GetBits(op,21,20)==2)
        {
            // this is the exception [2b]
            // move immediate to status register
            // cond= GetBits(op, 31,28)      [1a]
            // R=     GetBit(op, 22)
            // mask=  GetBits(op, 19,16)
            // SBO =  GetBits(op, 15,12)
            // rotate=GetBits(op, 11,8)
            // imm   =GetBits(op, 7,0);
        }
        else
        {
            // data processing immediate   [2b]
            // cond= GetBits(op, 31,28)      [1a]
            // opcode=GetBits(op, 24,21);
            // s=     GetBit(op, 20);
            // Rn=    GetBits(op, 19,16);
            // Rd=    GetBits(op, 15,12);
            // rotate=GetBits(op, 11,8);
            // imm   =GetBits(op, 7,0);
        }
    }
    else if (GetBits(op, 27,25)==2)
    {
        // load/store immediate offset
        // cond= GetBits(op, 31,28)      [1a]
        // PUBWL= GetBits(op, 24,20);
        // Rn=    GetBits(op, 19,16);
        // Rd=    GetBits(op, 15,12);
        // imm=   GetBits(op, 11,0);
    }
    else if (GetBits(op, 27,25)==3 && GetBit(op, 4)==0)
    {
        // load/store register offset
        // cond= GetBits(op, 31,28)      [1a]
        // PUBWL= GetBits(op, 24,20);
        // Rn=    GetBits(op, 19,16);
        // Rd=    GetBits(op, 15,12);
        // shifta=GetBits(op, 11,7);
        // shift =GetBits(op, 6,5);
        // Rm=    GetBits(op, 3,0);
        //
    }
    else if (GetBits(op, 27,25)==3 && GetBit(op, 4)==1)
    {
        // undefined instruction
    }
    else if (GetBits(op, 27,25)==4)
    {
        if (GetBits(op, 31,28)==15)
        {
            // this is the exception '[1b]'
            // undefined instruction [4]  ( unpredictable <armv5 )
        }
        else {
            // load/store multiple
            // cond= GetBits(op, 31,28)      [1b]
            // PUSWL= GetBits(op, 24,20);
            // Rn=    GetBits(op, 19,16);
            // list=  GetBits(op, 15,0);
        }
    }
    else if (GetBits(op, 27,25)==5)
    {
        if (GetBits(op, 31,28)==15)
        {
            // this is the exception '[1c]'
            // branch/blink and change to thumb [4]  ( unpredictable <armv5 )
            // H= GetBit(op, 24)
            // ofs= GetBits(op, 23,0)
        }
        else {
            // branch/blink
            // cond= GetBits(op, 31,28)      [1c]
            // L= GetBit(op, 24)
            // ofs= GetBits(op, 23,0)
        }
    }
    else if (GetBits(op, 27,25)==6)
    {
        if (GetBits(op, 31,28)==15)
        {
            // unpredictable if < armv5
        }
        // coprocessor load/store, double reg xfr  [6]
        // cond= GetBits(op, 31,28)      [5]
        // PUNWL= GetBits(op, 24,20);
        // Rn=    GetBits(op, 19,16);
        // CRd=   GetBits(op, 15,12);
        // cpnum= GetBits(op, 11,8);
        // ofs=   GetBits(op, 7,0);
    }
    else if (GetBits(op, 27,25)==7)
    {
        if (GetBit(op, 24)==1)
        {
            if (GetBits(op, 31,28)==15)
            {
                // this is the exception '[1d]'
                // undefined instruction[4]  ( unpredictable <armv5 )
            }
            else
            {
                // software interrupt
                // cond= GetBits(op, 31,28)      [1d]
                // swi= GetBits(op, 23,0)
            }
        }
        else {
            if (GetBits(op, 31,28)==15)
            {
                // unpredictable if < armv5
            }

            if (GetBit(op, 4)==0)
            {
                // coprocessor load/store, double reg xfr
                // cond= GetBits(op, 31,28)      [5]
                // opc1=  GetBits(op, 23,20);
                // CRn=   GetBits(op, 19,16);
                // CRd=   GetBits(op, 15,12);
                // cpnum= GetBits(op, 11,8);
                // opc2=  GetBits(op, 7,5);
                // CRm=   GetBits(op, 3,0);

            }
            else
            {
                // coprocessor load/store, double reg xfr
                // cond= GetBits(op, 31,28)      [5]
                // opc1=  GetBits(op, 23,21);
                // L=     GetBit(op, 20);
                // CRn=   GetBits(op, 19,16);
                // Rd=    GetBits(op, 15,12);
                // cpnum= GetBits(op, 11,8);
                // opc2=  GetBits(op, 7,5);
                // CRm=   GetBits(op, 3,0);

            }
        }

    }

}
//  GetBits(op, 27,25)==0 && GetBit(op,7)==1 && GetBit(op,4)==1
static HandleFigure32(op)
{
    if (GetBits(op, 31,28)==15)
    {
        // undefined, unpredictable < armv4
    }
    else if (GetBits(op, 6,5)==0)
    {
        if (GetBits(op, 24,23)==0)
        {
            if (GetBit(op, 22)==0)
            {
                // multiply (accumulate)
                // AS= GetBits(op, 21,20)
                // Rd=    GetBits(op, 19,16);
                // Rn=    GetBits(op, 15,12);
                // Rs=    GetBits(op, 11,8);
                // Rm=    GetBits(op, 3,0);
            }
            else
            {
                // ??
            }
        }
        else if (GetBits(op, 24,23)==1)
        {
            // multiply (accumulate) long
            // UAS= GetBits(op, 22,20)
            // RdHi=  GetBits(op, 19,16);
            // RdLo=  GetBits(op, 15,12);
            // Rs=    GetBits(op, 11,8);
            // Rm=    GetBits(op, 3,0);
        }
        else if (GetBits(op, 24,23)==2)
        {
            if (GetBits(op, 21,20)==0 && GetBits(op, 11,8)==0)
            {
                // swap/swap byte
                // B=  GetBit(op, 22)
                // Rn=    GetBits(op, 19,16);
                // Rd=    GetBits(op, 15,12);
                // Rm=    GetBits(op, 3,0);
            }
            else
            {
                // ??
            }
        }
        else {
            // ??
        }
    }
    else if (GetBits(op, 6,5)==1)
    {
        if (GetBit(op, 22)==0)
        {
            if (GetBits(op, 11,8)==0)
            {
                // load/store halfword regoffset [1]   ( unpredictable <armv4 )
                // PUWL= GetBits(op, 24,23)<<2 | GetBits(op, 21,20)
                // Rn=    GetBits(op, 19,16);
                // Rd=    GetBits(op, 15,12);
                // Rm=    GetBits(op, 3,0);
            }
            else {
                // ??
            }
        }
        else
        {
            // load/store halfword immediate offset [1]   ( unpredictable <armv4 )
                // PUWL= GetBits(op, 24,23)<<2 | GetBits(op, 21,20)
                // Rn=    GetBits(op, 19,16);
                // Rd=    GetBits(op, 15,12);
                // ofs=    GetBits(op, 11,8)<<4 | GetBits(op, 3,0);
        }
    }
    else 
    {
        if (GetBit(op, 22)==0)
        {
            if (GetBits(op, 11,8)==0)
            {
                // PUW=   GetBits(op, 24,23)<<1 | GetBit(op, 21)
                // Rn=    GetBits(op, 19,16);
                // Rd=    GetBits(op, 15,12);
                // Rm=    GetBits(op, 3,0);
                if (GetBit(op, 20)==0)
                {
                    // load/store 2 words reg offset [2]    ( DSP extension )
                    // S= GetBit(op, 5)
                }
                else
                {
                    // load/store signed halfword/byte reg offset [1]   ( unpredictable <armv4 )
                    // H= GetBit(op, 5)
                }
            }
            else {
                // ??
            }
        }
        else {
            // PUW=   GetBits(op, 24,23)<<1 | GetBit(op, 21)
            // Rn=    GetBits(op, 19,16);
            // Rd=    GetBits(op, 15,12);
            // ofs=    GetBits(op, 11,8)<<4 | GetBits(op, 3,0);
            if (GetBit(op, 20)==0)
            {
                // load/store 2 words immediate offset [2]    ( DSP extension )
                // S= GetBit(op, 5)
            }
            else
            {
                // load/store signed halfword/byte immediate offset [1]   ( unpredictable <armv4 )
                // H= GetBit(op, 5)
            }        
        }
    }
}

// GetBits(op, 27,23)==2 && GetBit(op,20)==0 && !( GetBit(op,7)==1 && GetBit(op,4)==1 )
static HandleFigure33(op)
{
    if (GetBits(op, 7,4)==0)
    {
        if (GetBit(op, 21)==0)
        {
            if (GetBits(op, 19,16)==15 && GetBits(op, 11,8)==0 && GetBits(op, 3,0)==0)
            {
                // Move status register to register
                // R = GetBit(op, 22)
                // Rd = GetBits(op, 15,12)
            }
            else {
                // ??
            }
        }
        else {
            if (GetBits(op, 15,12)==15 && GetBits(op, 11,8)==0)
            {
                // move register to status register
                // R = GetBit(op, 22)
                // mask = GetBits(op, 19,16)
                // Rm = GetBits(op, 3,0)
            }
            else {
                // ??
            }
        }
    }
    else if (GetBits(op, 7,4)==1)
    {
        if (GetBits(op, 22,21)==1)
        {
            if (GetBits(op, 19,8)==0xfff)
            {
                // Branch/exchange instruction set (>=armv5 && armv4t)
                // Rm= GetBits(op, 3,0)
            }
            else // bit19-8 != all ones
            {
                // ??
            }
        }
        else if (GetBits(op, 22,21)==3)
        {
            if (GetBits(op, 19,16)==15 && GetBits(op, 11,8)==15)
            {
                // Count leading zeros [2]  (undef in armv4, unpred<armv4)
                // Rd= GetBits(op, 15,12)
                // Rm= GetBits(op, 3,0)
            }
            else {
                // ??
            }
        }
        else
        {
            // ??
        }
    }
    else if (GetBits(op, 7,4)==3)
    {
        if (GetBits(op, 22,21)==1 && GetBits(op, 19,8)==0xfff)
        {
            // Branch and link/exchange instruction set [2]  (undef in armv4, unpred<armv4)
            // Rm= GetBits(op, 3,0)
        }
        else
        {
            // ??
        }
    }
    else if (GetBits(op, 7,4)==5)
    {
        if (GetBits(op, 11,8)==15)
        {
            // Enhanced DSP add/substracts [4]
            // op= GetBits(op, 22,21)
            // Rn= GetBits(op, 19,16)
            // Rd= GetBits(op, 15,12)
            // Rm= GetBits(op, 0,3)
        }
        else {
            // ??
        }
    }
    else if (GetBits(op, 7,4)==7)
    {
        if (GetBits(op, 22,21)==1)
        {
            if (GetBits(op, 31,28)==0xe)
            {
                // software breakpoint [2,3]  (undef armv4, unpred <armv4)
                // imm= GetBits(op, 19,8) << 4 | GetBits(op, 3,0)
            }
            else {
                // unpredictable
            }
        }
        else {
            // ??
        }
    }
    else if (GetBit(op, 7)==1 && GetBit(op, 4)==0)
    {
        // Enhanced DSP multiplies [4]
        // op= GetBits(op, 22,21)
        // Rd= GetBits(op, 19,16)
        // Rn= GetBits(op, 15,12)
        // Rs= GetBits(op, 11,8)
        // yx= GetBits(op, 6,5)
        // Rm= GetBits(op, 0,3)
    }
    else {
        // ??
    }
}

/* data processing opcodes
 *
 * 0x0 AND Rd:=Rn & opnd
 * 0x1 EOR Rd:=Rn ^ opnd
 * 0x2 SUB Rd:=Rn - opnd
 * 0x3 RSB Rd:=opnd - Rn
 * 0x4 ADD Rd:=Rn + opnd
 * 0x5 ADC Rd:=Rn + opnd + carry
 * 0x6 SBC Rd:=Rn - opnd - !carry
 * 0x7 RSC Rd:=opnd - Rn - !carry
 * 0x8 TST flags (Rn & opnd)
 * 0x9 TEQ flags (Rn ^ opnd)
 * 0xa CMP flags (Rn - opnd)
 * 0xb CMN flags (Rn + opnd)
 * 0xc ORR Rd:=Rn | opnd
 * 0xd MOV Rd:= opnd
 * 0xe BIC Rd:=Rn & ~opnd
 * 0xf MVN Rd:= ~opnd
 *
 *
 * conditions
 * 0x0 EQ     ==       Z==1
 * 0x1 NE     !=       Z==0
 * 0x2 CS HS  uint>=   C==1
 * 0x3 CC LO  uint<    C==0
 * 0x4 MI     <0       N==1
 * 0x5 PL     >=0      N==0
 * 0x6 VS     overflow V==1
 * 0x7 VC     no ov    V==0
 * 0x8 HI     uint>    C==1 && Z==0
 * 0x9 LS     uint<=   C==0 || Z==1
 * 0xa GE     int>=    N==V
 * 0xb LT     int<     N!=V
 * 0xc GT     int>     N==V && Z==0
 * 0xd LE     int<=    N!=V || Z==1
 * 0xe AL     always
 * 0xf NV     never  or invalid
 *
 */

static CountBits(n)
{
    auto count;
    auto i;
    while(n) {
        if (n<0)
            count++;
        n = n<<1;
    }
    return count;
}


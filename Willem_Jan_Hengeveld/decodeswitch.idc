auto r3,i, ea,subreg, subval, cmpreg,cmpval,target, f0, f1,m;
f0= GetFunctionAttr(here,FUNCATTR_START);
f1= GetFunctionAttr(here,FUNCATTR_END);
for (ea=f0 ; ea!=BADADDR ; ea=NextHead(ea,f1))
{
    m= GetMnem(ea);
    if (!isCode(GetFlags(ea))) {
    }
    else if (m=="MOV" && GetOpnd(ea,0)=="R3" && GetOpType(ea,1)==o_imm) {
        r3= GetOperandValue(ea,1);
    }
    else if (m=="LDR" && GetOpnd(ea,0)=="R3" && GetOpType(ea,1)==o_mem) {
        r3= Dword(GetOperandValue(ea,1));
    }
    else if (m=="CMP") {
        cmpreg=GetOpnd(ea,0);
        if (GetOpType(ea,1)==o_imm) {
            cmpval=GetOperandValue(ea,1);
        }
        else if (GetOpnd(ea,1)=="R3") {
            cmpval= r3;
        }
    }
    else if (m=="B" && (Dword(ea)>>28)==0) {
        for (target=Rfirst(ea) ; target!=BADADDR ; target=Rnext(ea,target)) {
            if (target!=NextHead(ea,f1))
                break;
        }
        Message("%08lx = %s  %8x -> %08lx: %s %s\n", ea, cmpreg, cmpval, target, Comment(NextHead(target,f1)), Comment(target));
        MakeNameEx(target, form("loc%08lx_eq_%x", target, cmpval), SN_LOCAL);
    }
    else if (m=="B" && (Dword(ea)>>28)==1) {
        target=NextHead(ea,f1);
        Message("%08lx ! %s  %8x -> %08lx: %s %s\n", ea, cmpreg, cmpval, target, Comment(NextHead(target,f1)), Comment(target));
        MakeNameEx(target, form("loc%08lx_eq_%x", target, cmpval), SN_LOCAL);
    }
    else if (m=="SUB") {
        subreg= GetOpnd(ea,1);
        if (GetOpType(ea,2)==o_imm) {
            subval=GetOperandValue(ea,2);
        }
        else if (GetOpnd(ea,2)=="R3") {
            subval= r3;
        }
    }
    else if (m=="ADD" && GetOpType(ea,0)==o_reg && GetOpnd(ea, 0)=="PC") {
        if (Dword(ea-4)&0x06000000) {
            for (i=0 ; i<=cmpval ; i++)
            {
                target= Byte(ea+4+i)+ea+8;
                Message("%08lx B %s  %8x -> %08lx: %s %s\n", ea, subreg, i+subval, target, Comment(NextHead(target,f1)), Comment(target));
                MakeNameEx(target, form("loc%08lx_eq_%x", target, i+subval), SN_LOCAL);
            }
        }
        else {
            for (i=0 ; i<=cmpval ; i++)
            {
                target= Word(ea+4+2*i)+ea+8;
                Message("%08lx H %s  %8x -> %08lx: %s %s\n", ea, subreg, i+subval, target, Comment(NextHead(target,f1)), Comment(target));
                MakeNameEx(target, form("loc%08lx_eq_%x", target, i+subval), SN_LOCAL);
            }
        }
    }
}


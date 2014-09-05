from idaapi import *
from sets import Set

def getinsn(ea):
    return DecodeInstruction(ea)

def isbranch(a):
    return a.itype in Set([NN_ja,NN_jnbe,NN_jbe,NN_jna,NN_jae,NN_jnb,NN_jnae,NN_jnl,NN_jnge,NN_jnle,NN_jng,NN_jb,NN_jg,NN_jle,NN_jge,NN_jl,NN_jnc,NN_jc,NN_jno,NN_jo,NN_jns,NN_js,NN_jnp,NN_jp,NN_jpo,NN_jpe,NN_jne,NN_je,NN_jnz,NN_jz])

def aresame(a,b):
    eqjumps= [
        Set([NN_ja,NN_jnbe]),          # !C&&!Z
        Set([NN_jbe, NN_jna]),         # C||Z
        Set([NN_jae, NN_jnb, NN_jnc]), # !C
        Set([NN_jb, NN_jnae, NN_jc]),  # C
        Set([NN_jg, NN_jnle]),         # !Z&&S==O
        Set([NN_jle, NN_jng]),         # Z||S!=O
        Set([NN_jge, NN_jnl]),         # S==O
        Set([NN_jl, NN_jnge]),         # S!=O
        Set([NN_jnp, NN_jpo]),         # !P
        Set([NN_jp, NN_jpe]),          # P
        Set([NN_jne, NN_jnz]),         # !Z
        Set([NN_je, NN_jz]),           # Z
        # jno, jo, jns, js  don't have synonyms
    ]
    ma= a.itype
    mb= b.itype
    for s in eqjumps:
        if ma in s and mb in s:
            return True
        if ma in s != mb in s:
            return False

    return False

def areopposite(a,b):
    opposites=[
        [Set([NN_ja,NN_jnbe]), Set([NN_jbe,NN_jna])],               # !C&&!Z   .. C||Z
        [Set([NN_jae,NN_jnb,NN_jnc]), Set([NN_jb,NN_jnae,NN_jc])],  # !C       .. C
        [Set([NN_jg,NN_jnle]),  Set([NN_jle,NN_jng])],              # !Z&&S==O .. Z||S!=O
        [Set([NN_jge, NN_jnl]), Set([NN_jl,NN_jnge])],              # S==O     .. S!=O
        [Set([NN_jnp,NN_jpo]), Set([NN_jp,NN_jpe])],                # !P       .. P
        [Set([NN_jne,NN_jnz]), Set([NN_je,NN_jz])],                 # !Z       .. Z
        [Set([NN_jno]), Set([NN_jo])],                              # !O       .. O
        [Set([NN_jns]), Set([NN_js])],                              # !S       .. S
    ]
    ma= a.itype
    mb= b.itype
    for pair in opposites:
        if ma in pair[0] and mb in pair[1]:
            return True
        if ma in pair[1] and mb in pair[0]:
            return True
        if ma in pair[0] != mb in pair[1]:
            return False
        if ma in pair[1] != mb in pair[0]:
            return False
    return False



# xchg a,b
# xchg b,a
def isxchgnop(i0):
    if i0.itype != NN_xchg:
        return False
    ra=GetOpnd(i0.ea,0)
    rb=GetOpnd(i0.ea,1)
    i1=getinsn(i0.ea+i0.size)
    if i1.itype != NN_xchg:
        return False
    sa=GetOpnd(i1.ea,0)
    sb=GetOpnd(i1.ea,1)

    return (sa==ra and sb==rb) or (sa==rb and sb==ra)


# shl r, 20h*n
# shr r, 20h*n
def isshnop(a):
    if a.itype in Set([NN_shl, NN_shr]):
        return (GetOpnd(a.ea,1)%32)==0
    return False

# mov r,r
def ismovnop(a):
    if a.itype==NN_mov:
        return GetOpnd(a.ea,0)==GetOpnd(a.ea,1)
    return False

def isnop(ea):
    insn= getinsn(ea)
    if Byte(ea)==0x90:
        return ItemSize(ea)
    if isxchgnop(insn):
        return 2*ItemSize(ea)
    if isshnop(insn):
        return ItemSize(ea)
    if ismovnop(insn):
        return ItemSize(ea)
    return 0


def getnopsize(ea):
    ea0= ea
    while 1:
        n= isnop(ea)
        if n==0:
            break
        ea += n
    return ea-ea0

def branchtarget(a):
    return a.Operands[0].addr

def makejump(ea, target):
    # use long or short jump, depending on range
    # EB <byte>  : -128 .. +127
    # E9 <dword> : -2G .. +2G
    # EA <dword> : jump absolute
    rel32= target-ea-5
    rel8= target-ea-2
    if rel8>-128 and rel8<128:
        MakeUnknown(ea, 2, 0)
        PatchByte(ea, 0xEB)
        if rel8<0:
            PatchByte(ea+1, 0x100+rel8)
        else:
            PatchByte(ea+1, rel8)
    else:
        MakeUnknown(ea, 5, 0)
        PatchByte(ea, 0xE9)
        if rel32<0:
            PatchByte(ea+1, 0x100000000+rel32)
        else:
            PatchByte(ea+1, rel32)
    MakeCode(ea)

def makenop(ea, n):
    MakeUnknown(ea, n, 0)
    for i in range(n):
        PatchByte(ea+i, 0x90)
        MakeCode(ea+i)
    msg("makenop(%08x, %x)\n" % (ea, n));

def deobfuscate(ea):
    # first make sure the current insn is disassembled
    if not isHead(GetFlags(ea)):
        MakeUnkn(PrevHead(ea), 0)
    if not isCode(GetFlags(ea)):
        MakeCode(ea)

    # check for jmp $+1
    if Byte(ea)==0xEB and Byte(ea+1)==0xFF:
        makenop(ea, 1)
        return

    # check for  jno+jo+jo == jmp
# jno    A
# .. nops ..
# jo    x
# 
# x:  jo  A
    ea += getnopsize(ea)

    b0= getinsn(ea)
    if isbranch(b0):
        ea2= ea+b0.size
        ea2 += getnopsize(ea2)
        b1= getinsn(ea2)
        if isbranch(b1):
            msg("both branch\n")
            if areopposite(b0, b1):
                t0= branchtarget(b0)
                t1= branchtarget(b1)
                b2= getinsn(t1)
                msg("opposites b1=%d b2=%d  t0=%x b2->%x\n" % (b1.itype, b2.itype, t0, branchtarget(b2)))
                if aresame(b1, b2) and t0==branchtarget(b2):
                    makejump(ea, t0)
                    makenop(ea+b0.size, ea2+b1.size-(ea+b0.size))
                    return
                else:
                    makejump(b1.ea, t1)
                    return

    # check for call  + pop [esp-4]
    if b0.itype==NN_call:
        t0= branchtarget(b0)
        if Dword(t0)==0xFC24448F:       # pop [esp-4]
            makejump(ea, t0)
            makenop(t0, 4)
            return

    # check for push + retn
    if b0.itype==NN_push:
        ea2= ea+b0.size
        ea2 += getnopsize(ea2)
        b1= getinsn(ea2)
        if b1.itype==NN_retn:
            makejump(ea, b0.Operands[0].value)
            return



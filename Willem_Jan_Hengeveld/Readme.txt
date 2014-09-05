From: http://itsme.home.xs4all.nl/projects/ida/idcscripts.html

ida idc scripts

I use these scripts when disassembling code, it allows you to quickly apply structure to selected area's.
addstrcmt.idc	adds referenced strings as comments.
fixobjc.idc	processes the objective-C typeinfo, and names methods accordingly
parsersc.idc	unfinished - processes resource data
findrel.idc	finds PC-relative references, for ARM, ARMthumb and X86
rilgsm.idc	unfinished - emulates arm insns
wm.idc	adds all windows messages in one large enum
xipstructs.idc	helps disassembling windows ce bootloaders
fixframe.idc	unfinished: tries to find howmany arguments a function has, and passes to other functions
kernel-structs.idc	names all kernel api's in a windows ce kernel
these 6 scripts belong together, if you include hotkeys.idc in ida.idc, and call 'addhotkeys();' from main. all hotkeys described below will automatically be added
hotkeys.idc	contains hotkey wrappers for the scripts below
swapinsn.idc	exchange 2 instructions, while keeping relative offsets intact
formatdata.idc	data formatter, see below
findstrangerefs.idc	finds constants changed into offset unintendedly
setdataofs.idc	finds offset bases for register relative references.
showrefs.idc	dumps lots of information about an address
keys added by hotkeys.idc:

Shift-I	_idc0	repeat last manual idc script
Shift-H	HK_Help	show help + info (like xrefs and flags) on current line
Shift-C	HK_Code	covert selection to code
Shift-O	HK_Offset	convert selection to offsets, also correctly handling Thumb offsets ( which have bit0 set )
Shift-G	HK_Guid	convert current data to a GUID
Shift-L	HK_Align	
Shift-A	HK_String_mixed	detect and convert to string, unicode and ascii strings
Shift-D	HK_Dwords	convert to dwords
Shift-P	HK_ParsePdata	process the .pdata section, and update function definitions accordingly
Shift-F	FixFunctions	change function bounds to include constant pools, this makes it easier to see where data is referenced from
Shift-J	FixJumpCalls	
Shift-R	findstrange	find incorrect offsets ( like off_20000, when an immediate was intended )
Shift-U	summarize_unk	group all unknown data
Shift-X	HK_ExchangeUp	rotate selected instruction range up
Shift-Y	HK_ExchangeDown	rotate selected instruction range down
Shift-V	HK_setregofs	try to find the value of the current REG+ofs expression
Shift-T	HK_setthis	assumes the function is named like TYPE_methodname, and a struct 'struc_TYPE' exists. then it traces where R0 ends up, and creates struc_TYPE fields, and new TYPE_methodname functions accordingly
data formatter

format specifiers

o	pointer to data
s	pointer to ascii string
s	pointer to unicode string
d[N]	dword
w[N]	word
b[N]	byte
c	pointer to code
p	pointer to proc ( function )
A[N]	fixed length or zero terminated ascii or unicode string
a[N]	ascii string
i	instructions
l[N]	align dword, or N: align 1<<N
g	guid
examples

Table("Al");
scans selected area for unicode or ascii strings, converts remaining bytes to 'align' directives'
Table("a4dcddd")
creates table with 4 ascii chars, dword, code ref, 3 dwords.
Table("a4dcd3")
creates table with 4 ascii chars, dword, code ref, an array of 3 dwords.

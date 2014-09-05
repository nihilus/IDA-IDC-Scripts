Typeinfo IDC scripts collection
Version 1.0 24.02.2003 Igor Skochinsky <skochinsky@mail.ru>
A quick and dirty doc.

Here are some IDC scripts I've written for IDA and have been using for 
quite a long time. I tried to extract as much info as possible from the 
different RTTI structures made by Borland compilers (and a bit from MS).
I started them before IDA got any RTTI support, and they still have some 
features missing in IDA. I thought they might be useful for IDA community.

Delphi_Typeinfo.idc - parses Delphi classes RTTI. You need to edit the 
script before loading to set the correct Delphi version. It then registers 
a few hotkeys (sorry, GUI users) to parse the class VMT/typeinfo.

bcc.idc - parsing Borland C++ tpids and exception infos. Inspired by IDA 
parser, which didn't work for all cases so I tried to improve it :)

ms_typeinfo.idc - extracts a class name for a VMT if the RTTI for it is
present.

ti_incl.idc, utils.idc - support files for Delphi_Typeinfo.idc.

Scripts are tested with freeware IDA 4.1, but should work on later 
versions, maybe with minor modifications.

Feel free to use them in any way you want, but I would appreciate any 
changes/fixes/feature additions sent to me.

Usage examples:

1. Delphi 4 (edit Delphi_Typeinfo.idc to uncomment "#define D4" and load it)

mov     ecx, ds:off_0_5AB580       <- form variable
mov     eax, ds:off_0_5ABAAC       <- Application object
mov     eax, [eax]
mov     edx, ds:off_0_487D70       <- form class pointer
call    TApplication::CreateForm

Follow off_0_487D70 and press Ctrl-F8 there
You'll get something like this:

TAboutBoxClass  dd offset TAboutBox     ; DATA XREF: start+83r
                                        ; Pointer to self
                dd 0                    ; Pointer to interface table
                dd 0                    ; Pointer to Automation initialization
                dd 0
                dd offset tiTAboutBox   ; Pointer to type information table
                dd offset ftTAboutBox   ; Pointer to field definition table
                dd offset mtTAboutBox   ; Pointer to method definition table
                dd 0                    ; Pointer to dynamic method table
                dd offset aTaboutbox    ; Class name pointer
                dd 334h                 ; Instance size
                dd offset TFormClass    ; Pointer to parent class
                dd offset TComponent::SafeCallException ; SafeCallException  m
                dd offset TCustomForm::AfterConstruction ; AfterConstruction
                dd offset TCustomForm::BeforeDestruction ; BeforeDestruction m
                dd offset TObject::Dispatch ; Dispatch method
                dd offset TCustomForm::DefaultHandler ; DefaultHandler method
                dd offset TObject::NewInstance ; NewInstance method
                dd offset TObject::FreeInstance ; FreeInstance method
                dd offset TCustomForm::Destroy ; destructor Destroy
TAboutBox       dd offset TWinControl::Virtual00 ; DATA XREF: CODE:00487D70o
                                        ; CODE:00487FFFo
                                        ; Virtual method 00
                dd offset TCustomForm::Virtual04 ; Virtual method 04
                dd offset TPersistent::Virtual08 ; Virtual method 08
                ...............

The script also creates the class structure with all fields that can be 
extracted from RTTI info.

2. Borland C++/Builder (load bcc.idc)

Here's an example of parsed tpid (after pressing Shift-F7 at the beginning of the structure):

`__tpdsc__'[Sysutils::Exception] dd 0Ch                  ; tpSize            
                                        ; DATA XREF: .text:004013B8o        
                                        ; .text:00401538o ...               
                dw TM_IS_STRUCT or TM_IS_CLASS; tpMask                       
                dw 30h                  ; tpName                             
                dd 0                    ; tpcVptrOffs                        
                dd CF_HAS_CTOR or CF_HAS_DTOR or CF_HAS_BASES or CF_HAS_VTABPPTR or CF_HAS_VIRTDT or CF_DELPHICLASS; tpcFlags
                dw 44h                  ; tpcBaseList                        
                dw 54h                  ; tpcVbasList                        
                dd 0                    ; tpcDlOpAddr                        
                dw 0                    ; tpcDlOpMask                        
                dw 0                    ; tpcDaOpMask                        
                dd 0                    ; tpcDaOpAddr                        
                dd 3                    ; tpcDtorCount                       
                dd 3                    ; tpcNVdtCount                       
                dd offset Sysutils::Exception::~Exception(void); tpcDtorAddr 
                dw 3                    ; tpcDtorMask                        
                dw 58h                  ; tpcDtMembers                       
                db 'Sysutils::Exception',0 ; Name of the type                
; Base classes:                                                              
                dd offset `__tpdsc__'[System::TObject]; blType ; Parent      
                dd 0                    ; blOffs
                dd 3                    ; blFlags
                dd 0                    ; End of list
; Virtual base classes:
                dd 0                    ; End of list
; Destructible members:
                dd offset `__tpdsc__'[System::AnsiString]; dmType
                dd 4                    ; dmOffs
                dd 0                    ; End of list

3. MS Visual C++

Load ms_typeinfo.idc when cursor is on 0046E5F8 (beginning of vtable)

.rdata:0046E5F4                            dd offset dword_0_46F360
.rdata:0046E5F8 const exception::`vftable' dd offset sub_0_45BFB3
.rdata:0046E5F8                            dd offset sub_0_45C06C

You'll get vtable renamed if the pointer at VMT-4 points to a valid 
typeinfo.

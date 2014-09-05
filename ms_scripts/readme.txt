Microsoft VC++ Reversing Helpers
Igor Skochinsky <skochinsky@mail.ru>

These IDC scripts help with the reversing of MSVC programs. 

ms_ehseh.idc: scans the whole program for typical SEH/EH code sequences and
comments all related structures and fields. Commented are stack variables,
exception handlers, exception types and other. It also tries to fix
function boundaries that are sometimes incorrectly determined by IDA.

ms_rtti4.idc: scans the whole program for RTTI structures and vftables. For
some simple cases, identifies and renames constructors and destructors.
Outputs a file with the list of all vftables with referencing functions and
class hierarchy.

For more information see the following OpenRCE articles written in conjunction with these scripts: 

http://www.openrce.org/articles/full_view/21
Reversing Microsoft Visual C++ Part I: Exception Handling 

http://www.openrce.org/articles/full_view/23
Reversing Microsoft Visual C++ Part II: Classes, Methods and RTTI

Version 1.0 21.09.2006
Initial release for OpenRCE
 
Version 1.1 19.06.2012
Minor updates: fixed #includes to work from any directory; changed hotkeys to not conflict with IDA's defaults.

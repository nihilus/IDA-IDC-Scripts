// vim: ft=cpp sw=4 ts=4 et
/* (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl>
 * 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 */
#define UNLOADED_FILE   1
#include <idc.idc>
// this script adds an enum 'windows_messages'
// containing all messages in one enum, instead of many different enums
// you have to look through until your windows message is found.

static main() {
auto id;
id = AddEnum(-1, "windows_messages", FF_0NUMH);

AddConstEx(id, "WM_NULL", 0x0000, -1);
AddConstEx(id, "WM_CREATE", 0x0001, -1);
AddConstEx(id, "WM_DESTROY", 0x0002, -1);
AddConstEx(id, "WM_MOVE", 0x0003, -1);
AddConstEx(id, "WM_SIZEWAIT", 0x0004, -1);
AddConstEx(id, "WM_SIZE", 0x0005, -1);
AddConstEx(id, "WM_ACTIVATE", 0x0006, -1);
AddConstEx(id, "WM_SETFOCUS", 0x0007, -1);
AddConstEx(id, "WM_KILLFOCUS", 0x0008, -1);
AddConstEx(id, "WM_SETVISIBLE", 0x0009, -1);
AddConstEx(id, "WM_ENABLE", 0x000a, -1);
AddConstEx(id, "WM_SETREDRAW", 0x000b, -1);
AddConstEx(id, "WM_SETTEXT", 0x000c, -1);
AddConstEx(id, "WM_GETTEXT", 0x000d, -1);
AddConstEx(id, "WM_GETTEXTLENGTH", 0x000e, -1);
AddConstEx(id, "WM_PAINT", 0x000f, -1);
AddConstEx(id, "WM_CLOSE", 0x0010, -1);
AddConstEx(id, "WM_QUERYENDSESSION", 0x0011, -1);
AddConstEx(id, "WM_QUIT", 0x0012, -1);
AddConstEx(id, "WM_QUERYOPEN", 0x0013, -1);
AddConstEx(id, "WM_ERASEBKGND", 0x0014, -1);
AddConstEx(id, "WM_SYSCOLORCHANGE", 0x0015, -1);
AddConstEx(id, "WM_ENDSESSION", 0x0016, -1);
AddConstEx(id, "WM_SYSTEMERROR", 0x0017, -1);
AddConstEx(id, "WM_SHOWWINDOW", 0x0018, -1);
AddConstEx(id, "WM_CTLCOLOR", 0x0019, -1);
AddConstEx(id, "WM_SETTINGCHANGE", 0x001a, -1);
AddConstEx(id, "WM_WININICHANGE", 0x001a, -1);
AddConstEx(id, "WM_DEVMODECHANGE", 0x001b, -1);
AddConstEx(id, "WM_ACTIVATEAPP", 0x001c, -1);
AddConstEx(id, "WM_FONTCHANGE", 0x001d, -1);
AddConstEx(id, "WM_TIMECHANGE", 0x001e, -1);
AddConstEx(id, "WM_CANCELMODE", 0x001f, -1);
AddConstEx(id, "WM_SETCURSOR", 0x0020, -1);
AddConstEx(id, "WM_MOUSEACTIVATE", 0x0021, -1);
AddConstEx(id, "WM_CHILDACTIVATE", 0x0022, -1);
AddConstEx(id, "WM_QUEUESYNC", 0x0023, -1);
AddConstEx(id, "WM_GETMINMAXINFO", 0x0024, -1);
AddConstEx(id, "WM_LOGOFF", 0x0025, -1);
AddConstEx(id, "WM_PAINTICON", 0x0026, -1);
AddConstEx(id, "WM_ICONERASEBKGND", 0x0027, -1);
AddConstEx(id, "WM_NEXTDLGCTL", 0x0028, -1);
AddConstEx(id, "WM_ALTTABACTIVE", 0x0029, -1);
AddConstEx(id, "WM_SPOOLERSTATUS", 0x002a, -1);
AddConstEx(id, "WM_DRAWITEM", 0x002b, -1);
AddConstEx(id, "WM_MEASUREITEM", 0x002c, -1);
AddConstEx(id, "WM_DELETEITEM", 0x002d, -1);
AddConstEx(id, "WM_VKEYTOITEM", 0x002e, -1);
AddConstEx(id, "WM_CHARTOITEM", 0x002f, -1);
AddConstEx(id, "WM_SETFONT", 0x0030, -1);
AddConstEx(id, "WM_GETFONT", 0x0031, -1);
AddConstEx(id, "WM_SETHOTKEY", 0x0032, -1);
AddConstEx(id, "WM_GETHOTKEY", 0x0033, -1);
AddConstEx(id, "WM_FILESYSCHANGE", 0x0034, -1);
AddConstEx(id, "WM_ISACTIVEICON", 0x0035, -1);
AddConstEx(id, "WM_QUERYPARKICON", 0x0036, -1);
AddConstEx(id, "WM_QUERYDRAGICON", 0x0037, -1);
AddConstEx(id, "WM_WINHELP", 0x0038, -1);
AddConstEx(id, "WM_COMPAREITEM", 0x0039, -1);
AddConstEx(id, "WM_FULLSCREEN", 0x003a, -1);
AddConstEx(id, "WM_CLIENTSHUTDOWN", 0x003b, -1);
AddConstEx(id, "WM_DDEMLEVENT", 0x003c, -1);
AddConstEx(id, "WM_GETOBJECT", 0x003d, -1);

AddConstEx(id, "MM_CALCSCROLL", 0x003f, -1);
AddConstEx(id, "WM_TESTING", 0x0040, -1);
AddConstEx(id, "WM_COMPACTING", 0x0041, -1);
AddConstEx(id, "WM_OTHERWINDOWCREATED", 0x0042, -1);
AddConstEx(id, "WM_OTHERWINDOWDESTROYED", 0x0043, -1);
AddConstEx(id, "WM_COMMNOTIFY", 0x0044, -1);
AddConstEx(id, "WM_MEDIASTATUSCHANGE", 0x0045, -1);
AddConstEx(id, "WM_WINDOWPOSCHANGING", 0x0046, -1);
AddConstEx(id, "WM_WINDOWPOSCHANGED", 0x0047, -1);
AddConstEx(id, "WM_POWER", 0x0048, -1);
AddConstEx(id, "WM_COPYGLOBALDATA", 0x0049, -1);
AddConstEx(id, "WM_COPYDATA", 0x004a, -1);
AddConstEx(id, "WM_CANCELJOURNAL", 0x004b, -1);
AddConstEx(id, "WM_LOGONNOTIFY", 0x004c, -1);
AddConstEx(id, "WM_KEYF1", 0x004d, -1);
AddConstEx(id, "WM_NOTIFY", 0x004e, -1);
AddConstEx(id, "WM_ACCESS_WINDOW", 0x004f, -1);
AddConstEx(id, "WM_INPUTLANGCHANGEREQUEST", 0x0050, -1);
AddConstEx(id, "WM_INPUTLANGCHANGE", 0x0051, -1);
AddConstEx(id, "WM_TCARD", 0x0052, -1);
AddConstEx(id, "WM_HELP", 0x0053, -1);
AddConstEx(id, "WM_USERCHANGED", 0x0054, -1);
AddConstEx(id, "WM_NOTIFYFORMAT", 0x0055, -1);
AddConstEx(id, "WM_QM_ACTIVATE", 0x0060, -1);
AddConstEx(id, "WM_HOOK_DO_CALLBACK", 0x0061, -1);
AddConstEx(id, "WM_SYSCOPYDATA", 0x0062, -1);
AddConstEx(id, "WM_FINALDESTROY", 0x0070, -1);
AddConstEx(id, "WM_MEASUREITEM_CLIENTDATA", 0x0071, -1);
AddConstEx(id, "WM_CONTEXTMENU", 0x007b, -1);
AddConstEx(id, "WM_STYLECHANGING", 0x007c, -1);
AddConstEx(id, "WM_STYLECHANGED", 0x007d, -1);
AddConstEx(id, "WM_DISPLAYCHANGE", 0x007e, -1);
AddConstEx(id, "WM_GETICON", 0x007f, -1);
AddConstEx(id, "WM_SETICON", 0x0080, -1);
AddConstEx(id, "WM_NCCREATE", 0x0081, -1);
AddConstEx(id, "WM_NCDESTROY", 0x0082, -1);
AddConstEx(id, "WM_NCCALCSIZE", 0x0083, -1);
AddConstEx(id, "WM_NCHITTEST", 0x0084, -1);
AddConstEx(id, "WM_NCPAINT", 0x0085, -1);
AddConstEx(id, "WM_NCACTIVATE", 0x0086, -1);
AddConstEx(id, "WM_GETDLGCODE", 0x0087, -1);
AddConstEx(id, "WM_SYNCPAINT", 0x0088, -1);
AddConstEx(id, "WM_SYNCTASK", 0x0089, -1);
AddConstEx(id, "WM_NCMOUSEMOVE", 0x00a0, -1);
AddConstEx(id, "WM_NCLBUTTONDOWN", 0x00a1, -1);
AddConstEx(id, "WM_NCLBUTTONUP", 0x00a2, -1);
AddConstEx(id, "WM_NCLBUTTONDBLCLK", 0x00a3, -1);
AddConstEx(id, "WM_NCRBUTTONDOWN", 0x00a4, -1);
AddConstEx(id, "WM_NCRBUTTONUP", 0x00a5, -1);
AddConstEx(id, "WM_NCRBUTTONDBLCLK", 0x00a6, -1);
AddConstEx(id, "WM_NCMBUTTONDOWN", 0x00a7, -1);
AddConstEx(id, "WM_NCMBUTTONUP", 0x00a8, -1);
AddConstEx(id, "WM_NCMBUTTONDBLCLK", 0x00a9, -1);
AddConstEx(id, "WM_NCXBUTTONDOWN", 0x00ab, -1);
AddConstEx(id, "WM_NCXBUTTONUP", 0x00ac, -1);
AddConstEx(id, "WM_NCXBUTTONDBLCLK", 0x00ad, -1);
AddConstEx(id, "EM_GETSEL", 0x00B0, -1);
AddConstEx(id, "EM_SETSEL", 0x00B1, -1);
AddConstEx(id, "EM_GETRECT", 0x00B2, -1);
AddConstEx(id, "EM_SETRECT", 0x00B3, -1);
AddConstEx(id, "EM_SETRECTNP", 0x00B4, -1);
AddConstEx(id, "EM_SCROLL", 0x00B5, -1);
AddConstEx(id, "EM_LINESCROLL", 0x00B6, -1);
AddConstEx(id, "EM_SCROLLCARET", 0x00B7, -1);
AddConstEx(id, "EM_GETMODIFY", 0x00B8, -1);
AddConstEx(id, "EM_SETMODIFY", 0x00B9, -1);
AddConstEx(id, "EM_GETLINECOUNT", 0x00BA, -1);
AddConstEx(id, "EM_LINEINDEX", 0x00BB, -1);
AddConstEx(id, "EM_SETHANDLE", 0x00BC, -1);
AddConstEx(id, "EM_GETHANDLE", 0x00BD, -1);
AddConstEx(id, "EM_GETTHUMB", 0x00BE, -1);
AddConstEx(id, "EM_LINELENGTH", 0x00C1, -1);
AddConstEx(id, "EM_REPLACESEL", 0x00C2, -1);
AddConstEx(id, "EM_SETFONT", 0x00C3, -1);
AddConstEx(id, "EM_GETLINE", 0x00C4, -1);
AddConstEx(id, "EM_LIMITTEXT", 0x00C5, -1);
AddConstEx(id, "EM_CANUNDO", 0x00C6, -1);
AddConstEx(id, "EM_UNDO", 0x00C7, -1);
AddConstEx(id, "EM_FMTLINES", 0x00C8, -1);
AddConstEx(id, "EM_LINEFROMCHAR", 0x00C9, -1);
AddConstEx(id, "EM_SETWORDBREAK", 0x00CA, -1);
AddConstEx(id, "EM_SETTABSTOPS", 0x00CB, -1);
AddConstEx(id, "EM_SETPASSWORDCHAR", 0x00CC, -1);
AddConstEx(id, "EM_EMPTYUNDOBUFFER", 0x00CD, -1);
AddConstEx(id, "EM_GETFIRSTVISIBLELINE", 0x00CE, -1);
AddConstEx(id, "EM_SETREADONLY", 0x00CF, -1);
AddConstEx(id, "EM_SETWORDBREAKPROC", 0x00D0, -1);
AddConstEx(id, "EM_GETWORDBREAKPROC", 0x00D1, -1);
AddConstEx(id, "EM_GETPASSWORDCHAR", 0x00D2, -1);
AddConstEx(id, "EM_SETMARGINS", 0x00D3, -1);
AddConstEx(id, "EM_GETMARGINS", 0x00D4, -1);
AddConstEx(id, "EM_POSFROMCHAR", 0x00D5, -1);
AddConstEx(id, "EM_CHARFROMPOS", 0x00D6, -1);
// ;Internal
AddConstEx(id, "SBM_SETPOS", 0x00E0, -1);
AddConstEx(id, "SBM_GETPOS", 0x00E1, -1);
AddConstEx(id, "SBM_SETRANGE", 0x00E2, -1);
AddConstEx(id, "SBM_GETRANGE", 0x00E3, -1);
AddConstEx(id, "SBM_ENABLE_ARROWS", 0x00E4, -1);
AddConstEx(id, "SBM_SETRANGEREDRAW", 0x00E6, -1);
AddConstEx(id, "SBM_SETSCROLLINFO", 0x00E9, -1);
AddConstEx(id, "SBM_GETSCROLLINFO", 0x00EA, -1);
// ;Internal
AddConstEx(id, "BM_GETCHECK", 0x00F0, -1);
AddConstEx(id, "BM_SETCHECK", 0x00F1, -1);
AddConstEx(id, "BM_GETSTATE", 0x00F2, -1);
AddConstEx(id, "BM_SETSTATE", 0x00F3, -1);
AddConstEx(id, "BM_SETSTYLE", 0x00F4, -1);
AddConstEx(id, "BM_CLICK", 0x00F5, -1);
AddConstEx(id, "BM_GETIMAGE", 0x00F6, -1);
AddConstEx(id, "BM_SETIMAGE", 0x00F7, -1);

AddConstEx(id, "WM_INPUT", 0x00ff, -1);
AddConstEx(id, "WM_KEYDOWN", 0x0100, -1);
AddConstEx(id, "WM_KEYUP", 0x0101, -1);
AddConstEx(id, "WM_CHAR", 0x0102, -1);
AddConstEx(id, "WM_DEADCHAR", 0x0103, -1);
AddConstEx(id, "WM_SYSKEYDOWN", 0x0104, -1);
AddConstEx(id, "WM_SYSKEYUP", 0x0105, -1);
AddConstEx(id, "WM_SYSCHAR", 0x0106, -1);
AddConstEx(id, "WM_SYSDEADCHAR", 0x0107, -1);
AddConstEx(id, "WM_YOMICHAR", 0x0108, -1);
AddConstEx(id, "WM_UNICHAR", 0x0109, -1);
AddConstEx(id, "WM_CONVERTREQUEST", 0x010a, -1);
AddConstEx(id, "WM_CONVERTRESULT", 0x010b, -1);
AddConstEx(id, "WM_IM_INFO", 0x010c, -1);
AddConstEx(id, "WM_IME_STARTCOMPOSITION", 0x010d, -1);
AddConstEx(id, "WM_IME_ENDCOMPOSITION", 0x010e, -1);
AddConstEx(id, "WM_IME_COMPOSITION", 0x010f, -1);
AddConstEx(id, "WM_INITDIALOG", 0x0110, -1);
AddConstEx(id, "WM_COMMAND", 0x0111, -1);
AddConstEx(id, "WM_SYSCOMMAND", 0x0112, -1);
AddConstEx(id, "WM_TIMER", 0x0113, -1);
AddConstEx(id, "WM_HSCROLL", 0x0114, -1);
AddConstEx(id, "WM_VSCROLL", 0x0115, -1);
AddConstEx(id, "WM_INITMENU", 0x0116, -1);
AddConstEx(id, "WM_INITMENUPOPUP", 0x0117, -1);
AddConstEx(id, "WM_SYSTIMER", 0x0118, -1);
AddConstEx(id, "WM_MENUSELECT", 0x011f, -1);
AddConstEx(id, "WM_MENUCHAR", 0x0120, -1);
AddConstEx(id, "WM_ENTERIDLE", 0x0121, -1);
AddConstEx(id, "WM_MENURBUTTONUP", 0x0122, -1);
AddConstEx(id, "WM_MENUDRAG", 0x0123, -1);
AddConstEx(id, "WM_MENUGETOBJECT", 0x0124, -1);
AddConstEx(id, "WM_UNINITMENUPOPUP", 0x0125, -1);
AddConstEx(id, "WM_MENUCOMMAND", 0x0126, -1);
AddConstEx(id, "WM_CHANGEUISTATE", 0x0127, -1);
AddConstEx(id, "WM_UPDATEUISTATE", 0x0128, -1);
AddConstEx(id, "WM_QUERYUISTATE", 0x0129, -1);
AddConstEx(id, "WM_LBTRACKPOINT", 0x0131, -1);
AddConstEx(id, "WM_CTLCOLORMSGBOX", 0x0132, -1);
AddConstEx(id, "WM_CTLCOLOREDIT", 0x0133, -1);
AddConstEx(id, "WM_CTLCOLORLISTBOX", 0x0134, -1);
AddConstEx(id, "WM_CTLCOLORBTN", 0x0135, -1);
AddConstEx(id, "WM_CTLCOLORDLG", 0x0136, -1);
AddConstEx(id, "WM_CTLCOLORSCROLLBAR", 0x0137, -1);
AddConstEx(id, "WM_CTLCOLORSTATIC", 0x0138, -1);

AddConstEx(id, "CB_GETEDITSEL", 0x0140, -1);
AddConstEx(id, "CB_LIMITTEXT", 0x0141, -1);
AddConstEx(id, "CB_SETEDITSEL", 0x0142, -1);
AddConstEx(id, "CB_ADDSTRING", 0x0143, -1);
AddConstEx(id, "CB_DELETESTRING", 0x0144, -1);
AddConstEx(id, "CB_DIR", 0x0145, -1);
AddConstEx(id, "CB_GETCOUNT", 0x0146, -1);
AddConstEx(id, "CB_GETCURSEL", 0x0147, -1);
AddConstEx(id, "CB_GETLBTEXT", 0x0148, -1);
AddConstEx(id, "CB_GETLBTEXTLEN", 0x0149, -1);
AddConstEx(id, "CB_INSERTSTRING", 0x014A, -1);
AddConstEx(id, "CB_RESETCONTENT", 0x014B, -1);
AddConstEx(id, "CB_FINDSTRING", 0x014C, -1);
AddConstEx(id, "CB_SELECTSTRING", 0x014D, -1);
AddConstEx(id, "CB_SETCURSEL", 0x014E, -1);
AddConstEx(id, "CB_SHOWDROPDOWN", 0x014F, -1);
// ;Internal NT
AddConstEx(id, "CB_GETITEMDATA", 0x0150, -1);
AddConstEx(id, "CB_SETITEMDATA", 0x0151, -1);
AddConstEx(id, "CB_GETDROPPEDCONTROLRECT", 0x0152, -1);
AddConstEx(id, "CB_SETITEMHEIGHT", 0x0153, -1);
AddConstEx(id, "CB_GETITEMHEIGHT", 0x0154, -1);
AddConstEx(id, "CB_SETEXTENDEDUI", 0x0155, -1);
AddConstEx(id, "CB_GETEXTENDEDUI", 0x0156, -1);
AddConstEx(id, "CB_GETDROPPEDSTATE", 0x0157, -1);
AddConstEx(id, "CB_FINDSTRINGEXACT", 0x0158, -1);
AddConstEx(id, "CB_SETLOCALE", 0x0159, -1);
AddConstEx(id, "CB_GETLOCALE", 0x015A, -1);
AddConstEx(id, "CB_GETTOPINDEX", 0x015B, -1);
AddConstEx(id, "CB_SETTOPINDEX", 0x015C, -1);
AddConstEx(id, "CB_GETHORIZONTALEXTENT", 0x015D, -1);
AddConstEx(id, "CB_SETHORIZONTALEXTENT", 0x015E, -1);
AddConstEx(id, "CB_GETDROPPEDWIDTH", 0x015F, -1);
AddConstEx(id, "CB_SETDROPPEDWIDTH", 0x0160, -1);
AddConstEx(id, "CB_INITSTORAGE", 0x0161, -1);
// ;Internal
AddConstEx(id, "STM_SETICON", 0x0170, -1);
AddConstEx(id, "STM_GETICON", 0x0171, -1);
AddConstEx(id, "STM_SETIMAGE", 0x0172, -1);
AddConstEx(id, "STM_GETIMAGE", 0x0173, -1);
// ;Internal
AddConstEx(id, "LB_ADDSTRING", 0x0180, -1);
AddConstEx(id, "LB_INSERTSTRING", 0x0181, -1);
AddConstEx(id, "LB_DELETESTRING", 0x0182, -1);
AddConstEx(id, "LB_SELITEMRANGEEX", 0x0183, -1);
AddConstEx(id, "LB_RESETCONTENT", 0x0184, -1);
AddConstEx(id, "LB_SETSEL", 0x0185, -1);
AddConstEx(id, "LB_SETCURSEL", 0x0186, -1);
AddConstEx(id, "LB_GETSEL", 0x0187, -1);
AddConstEx(id, "LB_GETCURSEL", 0x0188, -1);
AddConstEx(id, "LB_GETTEXT", 0x0189, -1);
AddConstEx(id, "LB_GETTEXTLEN", 0x018A, -1);
AddConstEx(id, "LB_GETCOUNT", 0x018B, -1);
AddConstEx(id, "LB_SELECTSTRING", 0x018C, -1);
AddConstEx(id, "LB_DIR", 0x018D, -1);
AddConstEx(id, "LB_GETTOPINDEX", 0x018E, -1);
AddConstEx(id, "LB_FINDSTRING", 0x018F, -1);
// ;Internal NT
AddConstEx(id, "LB_GETSELCOUNT", 0x0190, -1);
AddConstEx(id, "LB_GETSELITEMS", 0x0191, -1);
AddConstEx(id, "LB_SETTABSTOPS", 0x0192, -1);
AddConstEx(id, "LB_GETHORIZONTALEXTENT", 0x0193, -1);
AddConstEx(id, "LB_SETHORIZONTALEXTENT", 0x0194, -1);
AddConstEx(id, "LB_SETCOLUMNWIDTH", 0x0195, -1);
AddConstEx(id, "LB_ADDFILE", 0x0196, -1);
AddConstEx(id, "LB_SETTOPINDEX", 0x0197, -1);
AddConstEx(id, "LB_GETITEMRECT", 0x0198, -1);
AddConstEx(id, "LB_GETITEMDATA", 0x0199, -1);
AddConstEx(id, "LB_SETITEMDATA", 0x019A, -1);
AddConstEx(id, "LB_SELITEMRANGE", 0x019B, -1);
AddConstEx(id, "LB_SETANCHORINDEX", 0x019C, -1);
AddConstEx(id, "LB_GETANCHORINDEX", 0x019D, -1);
AddConstEx(id, "LB_SETCARETINDEX", 0x019E, -1);
AddConstEx(id, "LB_GETCARETINDEX", 0x019F, -1);
// ;Internal NT
AddConstEx(id, "LB_SETITEMHEIGHT", 0x01A0, -1);
AddConstEx(id, "LB_GETITEMHEIGHT", 0x01A1, -1);
AddConstEx(id, "LB_FINDSTRINGEXACT", 0x01A2, -1);
AddConstEx(id, "LBCB_CARETON", 0x01A3, -1);
AddConstEx(id, "LBCB_CARETOFF", 0x01A4, -1);
AddConstEx(id, "LB_SETLOCALE", 0x01A5, -1);
AddConstEx(id, "LB_GETLOCALE", 0x01A6, -1);
AddConstEx(id, "LB_SETCOUNT", 0x01A7, -1);
AddConstEx(id, "LB_INITSTORAGE", 0x01A8, -1);
AddConstEx(id, "LB_ITEMFROMPOINT", 0x01A9, -1);
AddConstEx(id, "LB_INSERTSTRINGUPPER", 0x01AA, -1);
AddConstEx(id, "LB_INSERTSTRINGLOWER", 0x01AB, -1);
AddConstEx(id, "LB_ADDSTRINGUPPER", 0x01AC, -1);
AddConstEx(id, "LB_ADDSTRINGLOWER", 0x01AD, -1);
// ;Internal
AddConstEx(id, "MN_SETHMENU", 0x01E0, -1);
AddConstEx(id, "MN_GETHMENU", 0x01E1, -1);
AddConstEx(id, "MN_SIZEWINDOW", 0x01E2, -1);
AddConstEx(id, "MN_OPENHIERARCHY", 0x01E3, -1);
AddConstEx(id, "MN_CLOSEHIERARCHY", 0x01E4, -1);
AddConstEx(id, "MN_SELECTITEM", 0x01E5, -1);
AddConstEx(id, "MN_CANCELMENUS", 0x01E6, -1);
AddConstEx(id, "MN_SELECTFIRSTVALIDITEM", 0x01E7, -1);
AddConstEx(id, "MN_GETPPOPUPMENU", 0x01EA, -1);
AddConstEx(id, "MN_FINDMENUWINDOWFROMPOINT", 0x01EB, -1);
AddConstEx(id, "MN_SHOWPOPUPWINDOW", 0x01EC, -1);
AddConstEx(id, "MN_BUTTONDOWN", 0x01ED, -1);
AddConstEx(id, "MN_MOUSEMOVE", 0x01EE, -1);
AddConstEx(id, "MN_BUTTONUP", 0x01EF, -1);
AddConstEx(id, "MN_SETTIMERTOOPENHIERARCHY", 0x01F0, -1);
AddConstEx(id, "MN_DBLCLK", 0x01F1, -1);

AddConstEx(id, "WM_MOUSEMOVE", 0x0200, -1);
AddConstEx(id, "WM_LBUTTONDOWN", 0x0201, -1);
AddConstEx(id, "WM_LBUTTONUP", 0x0202, -1);
AddConstEx(id, "WM_LBUTTONDBLCLK", 0x0203, -1);
AddConstEx(id, "WM_RBUTTONDOWN", 0x0204, -1);
AddConstEx(id, "WM_RBUTTONUP", 0x0205, -1);
AddConstEx(id, "WM_RBUTTONDBLCLK", 0x0206, -1);
AddConstEx(id, "WM_MBUTTONDOWN", 0x0207, -1);
AddConstEx(id, "WM_MBUTTONUP", 0x0208, -1);
AddConstEx(id, "WM_MBUTTONDBLCLK", 0x0209, -1);
AddConstEx(id, "WM_MOUSEWHEEL", 0x020a, -1);
AddConstEx(id, "WM_XBUTTONDOWN", 0x020b, -1);
AddConstEx(id, "WM_XBUTTONUP", 0x020c, -1);
AddConstEx(id, "WM_XBUTTONDBLCLK", 0x020d, -1);
AddConstEx(id, "WM_PARENTNOTIFY", 0x0210, -1);
AddConstEx(id, "WM_ENTERMENULOOP", 0x0211, -1);
AddConstEx(id, "WM_EXITMENULOOP", 0x0212, -1);
AddConstEx(id, "WM_SIZING", 0x0213, -1);
AddConstEx(id, "WM_CAPTURECHANGED", 0x0215, -1);
AddConstEx(id, "WM_MOVING", 0x0216, -1);
AddConstEx(id, "WM_POWERBROADCAST", 0x0218, -1);
AddConstEx(id, "WM_DEVICECHANGE", 0x0219, -1);
AddConstEx(id, "WM_MDICREATE", 0x0220, -1);
AddConstEx(id, "WM_MDIDESTROY", 0x0221, -1);
AddConstEx(id, "WM_MDIACTIVATE", 0x0222, -1);
AddConstEx(id, "WM_MDIRESTORE", 0x0223, -1);
AddConstEx(id, "WM_MDINEXT", 0x0224, -1);
AddConstEx(id, "WM_MDIMAXIMIZE", 0x0225, -1);
AddConstEx(id, "WM_MDITILE", 0x0226, -1);
AddConstEx(id, "WM_MDICASCADE", 0x0227, -1);
AddConstEx(id, "WM_MDIICONARRANGE", 0x0228, -1);
AddConstEx(id, "WM_MDIGETACTIVE", 0x0229, -1);
AddConstEx(id, "WM_DROPOBJECT", 0x022A, -1);
AddConstEx(id, "WM_QUERYDROPOBJECT", 0x022B, -1);
AddConstEx(id, "WM_BEGINDRAG", 0x022C, -1);
AddConstEx(id, "WM_DRAGLOOP", 0x022D, -1);
AddConstEx(id, "WM_DRAGSELECT", 0x022E, -1);
AddConstEx(id, "WM_DRAGMOVE", 0x022F, -1);
AddConstEx(id, "WM_MDISETMENU", 0x0230, -1);
AddConstEx(id, "WM_ENTERSIZEMOVE", 0x0231, -1);
AddConstEx(id, "WM_EXITSIZEMOVE", 0x0232, -1);
AddConstEx(id, "WM_DROPFILES", 0x0233, -1);
AddConstEx(id, "WM_MDIREFRESHMENU", 0x0234, -1);
AddConstEx(id, "WM_HANGEULFIRST", 0x0280, -1);
AddConstEx(id, "WM_KANJIFIRST", 0x0280, -1);
AddConstEx(id, "WM_IME_SETCONTEXT", 0x0281, -1);
AddConstEx(id, "WM_IME_NOTIFY", 0x0282, -1);
AddConstEx(id, "WM_IME_CONTROL", 0x0283, -1);
AddConstEx(id, "WM_IME_COMPOSITIONFULL", 0x0284, -1);
AddConstEx(id, "WM_IME_SELECT", 0x0285, -1);
AddConstEx(id, "WM_IME_CHAR", 0x0286, -1);
AddConstEx(id, "WM_IME_SYSTEM", 0x0287, -1);
AddConstEx(id, "WM_IME_REQUEST", 0x0288, -1);
AddConstEx(id, "WM_IME_KEYDOWN", 0x0290, -1);
AddConstEx(id, "WM_IME_KEYUP", 0x0291, -1);
AddConstEx(id, "WM_HANGEULLAST", 0x029F, -1);
AddConstEx(id, "WM_KANJILAST", 0x029F, -1);
AddConstEx(id, "WM_NCMOUSEHOVER", 0x02a0, -1);
AddConstEx(id, "WM_MOUSEHOVER", 0x02a1, -1);
AddConstEx(id, "WM_NCMOUSELEAVE", 0x02a2, -1);
AddConstEx(id, "WM_MOUSELEAVE", 0x02a3, -1);
AddConstEx(id, "WM_TRACKMOUSEEVENT_LAST", 0x02af, -1);
AddConstEx(id, "WM_WTSSESSION_CHANGE", 0x02b1, -1);
AddConstEx(id, "WM_TABLET_FIRST", 0x02c0, -1);
AddConstEx(id, "WM_TABLET_LAST", 0x02df, -1);
AddConstEx(id, "WM_CUT", 0x0300, -1);
AddConstEx(id, "WM_COPY", 0x0301, -1);
AddConstEx(id, "WM_PASTE", 0x0302, -1);
AddConstEx(id, "WM_CLEAR", 0x0303, -1);
AddConstEx(id, "WM_UNDO", 0x0304, -1);
AddConstEx(id, "WM_RENDERFORMAT", 0x0305, -1);
AddConstEx(id, "WM_RENDERALLFORMATS", 0x0306, -1);
AddConstEx(id, "WM_DESTROYCLIPBOARD", 0x0307, -1);
AddConstEx(id, "WM_DRAWCLIPBOARD", 0x0308, -1);
AddConstEx(id, "WM_PAINTCLIPBOARD", 0x0309, -1);
AddConstEx(id, "WM_VSCROLLCLIPBOARD", 0x030a, -1);
AddConstEx(id, "WM_SIZECLIPBOARD", 0x030b, -1);
AddConstEx(id, "WM_ASKCBFORMATNAME", 0x030c, -1);
AddConstEx(id, "WM_CHANGECBCHAIN", 0x030d, -1);
AddConstEx(id, "WM_HSCROLLCLIPBOARD", 0x030e, -1);
AddConstEx(id, "WM_QUERYNEWPALETTE", 0x030f, -1);
AddConstEx(id, "WM_PALETTEISCHANGING", 0x0310, -1);
AddConstEx(id, "WM_PALETTECHANGED", 0x0311, -1);
AddConstEx(id, "WM_HOTKEY", 0x0312, -1);
AddConstEx(id, "WM_SYSMENU", 0x0313, -1);
AddConstEx(id, "WM_HOOKMSG", 0x0314, -1);
AddConstEx(id, "WM_EXITPROCESS", 0x0315, -1);
AddConstEx(id, "WM_WAKETHREAD", 0x0316, -1);
AddConstEx(id, "WM_PRINT", 0x0317, -1);
AddConstEx(id, "WM_PRINTCLIENT", 0x0318, -1);
AddConstEx(id, "WM_APPCOMMAND", 0x0319, -1);
AddConstEx(id, "WM_THEMECHANGED", 0x031a, -1);
AddConstEx(id, "WM_HANDHELDFIRST", 0x0358, -1);
AddConstEx(id, "WM_HANDHELDLAST", 0x035f, -1);
AddConstEx(id, "WM_AFXFIRST", 0x0360, -1);
AddConstEx(id, "WM_AFXLAST", 0x037f, -1);
AddConstEx(id, "WM_PENWINFIRST", 0x0380, -1);
AddConstEx(id, "WM_PENWINLAST", 0x038F, -1);

AddConstEx(id, "WM_INTERNAL_COALESCE_FIRST", 0x0390, -1);
AddConstEx(id, "WM_COALESCE_FIRST", 0x0390, -1);
AddConstEx(id, "WM_COALESCE_LAST", 0x039F, -1);
AddConstEx(id, "WM_COALESCE_FIRST", 0x03A0, -1);
AddConstEx(id, "WM_INTERNAL_COALESCE_FIRST", 0x03A0, -1);
AddConstEx(id, "WM_MM_RESERVED_FIRST", 0x03A0, -1);
AddConstEx(id, "WM_COALESCE_LAST", 0x03AF, -1);
AddConstEx(id, "WM_MM_RESERVED_FIRST", 0x03B0, -1);
AddConstEx(id, "WM_MM_RESERVED_LAST", 0x03DF, -1);
AddConstEx(id, "WM_DDE_INITIATE", 0x03e0, -1);
AddConstEx(id, "WM_DDE_TERMINATE", 0x03e1, -1);
AddConstEx(id, "WM_DDE_ADVISE", 0x03e2, -1);
AddConstEx(id, "WM_DDE_UNADVISE", 0x03e3, -1);
AddConstEx(id, "WM_DDE_ACK", 0x03e4, -1);
AddConstEx(id, "WM_DDE_DATA", 0x03e5, -1);
AddConstEx(id, "WM_DDE_REQUEST", 0x03e6, -1);
AddConstEx(id, "WM_DDE_POKE", 0x03e7, -1);
AddConstEx(id, "WM_DDE_EXECUTE", 0x03e8, -1);

AddConstEx(id, "WM_DBNOTIFICATION", 0x03fd, -1);
AddConstEx(id, "WM_NETCONNECT", 0x03fe, -1);
AddConstEx(id, "WM_HIBERNATE", 0x03ff, -1);


id= AddEnum(-1,"enum_VirtualKeys",0);
//0000: VK_T0,VK_T1,VK_T2,VK_T3,VK_T4,VK_T5,VK_T6,VK_T7,VK_T8,VK_T9
//0001: VK_LBUTTON
AddConstEx(id, "VK_LBUTTON", 0x1, -1);
//0002: VK_RBUTTON,VVK_INTL
AddConstEx(id, "VK_RBUTTON", 0x2, -1);
AddConstEx(id, "VVK_INTL", 0x2, -1);
//0003: VK_CANCEL
AddConstEx(id, "VK_CANCEL", 0x3, -1);
//0004: VK_MBUTTON,VVK_NUMERIC,VVK_SYMBOL
AddConstEx(id, "VK_MBUTTON", 0x4, -1);
AddConstEx(id, "VVK_SYMBOL", 0x4, -1);
AddConstEx(id, "VVK_NUMERIC", 0x4, -1);
//0005: VK_XBUTTON1
AddConstEx(id, "VK_XBUTTON1", 0x5, -1);
//0006: VK_XBUTTON2
AddConstEx(id, "VK_XBUTTON2", 0x6, -1);
//0008: VK_BACK
AddConstEx(id, "VK_BACK", 0x8, -1);
//0009: HK_SPEEDDIAL,VK_TAB
AddConstEx(id, "VK_TAB", 0x9, -1);
AddConstEx(id, "HK_SPEEDDIAL", 0x9, -1);
//000c: CERT_PVK_FILE_PROP_ID,VK_CLEAR
AddConstEx(id, "VK_CLEAR", 0xc, -1);
AddConstEx(id, "CERT_PVK_FILE_PROP_ID", 0xc, -1);
//000d: HK_DIRECTORY,VK_RETURN,VK_TACTION
AddConstEx(id, "VK_RETURN", 0xd, -1);
AddConstEx(id, "VK_TACTION", 0xd, -1);
AddConstEx(id, "HK_DIRECTORY", 0xd, -1);
//0010: VK_SHIFT,VVK_SHIFT
AddConstEx(id, "VK_SHIFT", 0x10, -1);
AddConstEx(id, "VVK_SHIFT", 0x10, -1);
//0011: VK_CONTROL,VVK_CONTROL
AddConstEx(id, "VK_CONTROL", 0x11, -1);
AddConstEx(id, "VVK_CONTROL", 0x11, -1);
//0012: VK_MENU
AddConstEx(id, "VK_MENU", 0x12, -1);
//0013: VK_PAUSE,VVK_INTL_LS
AddConstEx(id, "VK_PAUSE", 0x13, -1);
AddConstEx(id, "VVK_INTL_LS", 0x13, -1);
//0014: VK_CAPITAL,VVK_CAPITAL
AddConstEx(id, "VK_CAPITAL", 0x14, -1);
AddConstEx(id, "VVK_CAPITAL", 0x14, -1);
//0015: VK_HANGEUL,VK_HANGUL,VK_KANA
AddConstEx(id, "VK_KANA", 0x15, -1);
AddConstEx(id, "VK_HANGEUL", 0x15, -1);
AddConstEx(id, "VK_HANGUL", 0x15, -1);
//0017: VK_JUNJA
AddConstEx(id, "VK_JUNJA", 0x17, -1);
//0018: VK_FINAL
AddConstEx(id, "VK_FINAL", 0x18, -1);
//0019: VK_HANJA,VK_KANJI,VVK_CHINA,VVK_CHINESE
AddConstEx(id, "VK_KANJI", 0x19, -1);
AddConstEx(id, "VVK_CHINA", 0x19, -1);
AddConstEx(id, "VK_HANJA", 0x19, -1);
AddConstEx(id, "VVK_CHINESE", 0x19, -1);
//001b: HK_VOICEMAIL,VK_ESCAPE,VK_TBACK
AddConstEx(id, "VK_ESCAPE", 0x1b, -1);
AddConstEx(id, "HK_VOICEMAIL", 0x1b, -1);
AddConstEx(id, "VK_TBACK", 0x1b, -1);
//001c: VK_CONVERT,VVK_SHAPE
AddConstEx(id, "VK_CONVERT", 0x1c, -1);
AddConstEx(id, "VVK_SHAPE", 0x1c, -1);
//001d: VK_NOCONVERT
AddConstEx(id, "VK_NOCONVERT", 0x1d, -1);
//0020: VK_SPACE
AddConstEx(id, "VK_SPACE", 0x20, -1);
//0021: HK_VOLUMEUP,VK_PRIOR
AddConstEx(id, "VK_PRIOR", 0x21, -1);
AddConstEx(id, "HK_VOLUMEUP", 0x21, -1);
//0022: HK_VOLUMEDOWN,VK_NEXT
AddConstEx(id, "VK_NEXT", 0x22, -1);
AddConstEx(id, "HK_VOLUMEDOWN", 0x22, -1);
//0023: HK_MENU,SENTINEL,VK_END
AddConstEx(id, "VK_END", 0x23, -1);
AddConstEx(id, "SENTINEL", 0x23, -1);
AddConstEx(id, "HK_MENU", 0x23, -1);
//0024: HK_HOME,VK_HOME
AddConstEx(id, "VK_HOME", 0x24, -1);
AddConstEx(id, "HK_HOME", 0x24, -1);
//0025: VK_LEFT,VK_TLEFT
AddConstEx(id, "VK_LEFT", 0x25, -1);
AddConstEx(id, "VK_TLEFT", 0x25, -1);
//0026: VK_TUP,VK_UP
AddConstEx(id, "VK_UP", 0x26, -1);
AddConstEx(id, "VK_TUP", 0x26, -1);
//0027: VK_RIGHT,VK_TRIGHT
AddConstEx(id, "VK_RIGHT", 0x27, -1);
AddConstEx(id, "VK_TRIGHT", 0x27, -1);
//0028: VK_DOWN,VK_TDOWN
AddConstEx(id, "VK_DOWN", 0x28, -1);
AddConstEx(id, "VK_TDOWN", 0x28, -1);
//0029: VK_SELECT
AddConstEx(id, "VK_SELECT", 0x29, -1);
//002a: VK_PRINT
AddConstEx(id, "VK_PRINT", 0x2a, -1);
//002b: VK_EXECUTE
AddConstEx(id, "VK_EXECUTE", 0x2b, -1);
//002c: VK_SNAPSHOT
AddConstEx(id, "VK_SNAPSHOT", 0x2c, -1);
//002d: HK_STAR,VK_INSERT
AddConstEx(id, "VK_INSERT", 0x2d, -1);
AddConstEx(id, "HK_STAR", 0x2d, -1);
//002e: HK_POUND,VK_DELETE
AddConstEx(id, "VK_DELETE", 0x2e, -1);
AddConstEx(id, "HK_POUND", 0x2e, -1);
//002f: VK_HELP
AddConstEx(id, "VK_HELP", 0x2f, -1);
//0030: VK_0
AddConstEx(id, "VK_0", 0x30, -1);
//0031: VK_1
AddConstEx(id, "VK_1", 0x31, -1);
//0032: VK_2
AddConstEx(id, "VK_2", 0x32, -1);
//0033: VK_3
AddConstEx(id, "VK_3", 0x33, -1);
//0034: VK_4
AddConstEx(id, "VK_4", 0x34, -1);
//0035: VK_5
AddConstEx(id, "VK_5", 0x35, -1);
//0036: VK_6
AddConstEx(id, "VK_6", 0x36, -1);
//0037: VK_7
AddConstEx(id, "VK_7", 0x37, -1);
//0038: VK_8
AddConstEx(id, "VK_8", 0x38, -1);
//0039: VK_9
AddConstEx(id, "VK_9", 0x39, -1);
//0041: VK_A
AddConstEx(id, "VK_A", 0x41, -1);
//0042: VK_B
AddConstEx(id, "VK_B", 0x42, -1);
//0043: VK_C
AddConstEx(id, "VK_C", 0x43, -1);
//0044: VK_D
AddConstEx(id, "VK_D", 0x44, -1);
//0045: VK_E
AddConstEx(id, "VK_E", 0x45, -1);
//0046: VK_F
AddConstEx(id, "VK_F", 0x46, -1);
//0047: VK_G
AddConstEx(id, "VK_G", 0x47, -1);
//0048: VK_H
AddConstEx(id, "VK_H", 0x48, -1);
//0049: VK_I
AddConstEx(id, "VK_I", 0x49, -1);
//004a: VK_J
AddConstEx(id, "VK_J", 0x4a, -1);
//004b: VK_K
AddConstEx(id, "VK_K", 0x4b, -1);
//004c: VK_L
AddConstEx(id, "VK_L", 0x4c, -1);
//004d: VK_M
AddConstEx(id, "VK_M", 0x4d, -1);
//004e: VK_N
AddConstEx(id, "VK_N", 0x4e, -1);
//004f: VK_O
AddConstEx(id, "VK_O", 0x4f, -1);
//0050: VK_P
AddConstEx(id, "VK_P", 0x50, -1);
//0051: VK_Q
AddConstEx(id, "VK_Q", 0x51, -1);
//0052: VK_R
AddConstEx(id, "VK_R", 0x52, -1);
//0053: VK_S
AddConstEx(id, "VK_S", 0x53, -1);
//0054: VK_T
AddConstEx(id, "VK_T", 0x54, -1);
//0055: VK_U
AddConstEx(id, "VK_U", 0x55, -1);
//0056: VK_V
AddConstEx(id, "VK_V", 0x56, -1);
//0057: VK_W
AddConstEx(id, "VK_W", 0x57, -1);
//0058: VK_X
AddConstEx(id, "VK_X", 0x58, -1);
//0059: VK_Y
AddConstEx(id, "VK_Y", 0x59, -1);
//005a: VK_Z
AddConstEx(id, "VK_Z", 0x5a, -1);
//005b: VK_LWIN,VK_THOME
AddConstEx(id, "VK_LWIN", 0x5b, -1);
AddConstEx(id, "VK_THOME", 0x5b, -1);
//005c: VK_RWIN
AddConstEx(id, "VK_RWIN", 0x5c, -1);
//005d: VK_APPS
AddConstEx(id, "VK_APPS", 0x5d, -1);
//005f: VK_SLEEP
AddConstEx(id, "VK_SLEEP", 0x5f, -1);
//0060: VK_NUMPAD0
AddConstEx(id, "VK_NUMPAD0", 0x60, -1);
//0061: VK_NUMPAD1
AddConstEx(id, "VK_NUMPAD1", 0x61, -1);
//0062: VK_NUMPAD2
AddConstEx(id, "VK_NUMPAD2", 0x62, -1);
//0063: VK_NUMPAD3
AddConstEx(id, "VK_NUMPAD3", 0x63, -1);
//0064: VK_NUMPAD4
AddConstEx(id, "VK_NUMPAD4", 0x64, -1);
//0065: VK_NUMPAD5
AddConstEx(id, "VK_NUMPAD5", 0x65, -1);
//0066: VK_NUMPAD6
AddConstEx(id, "VK_NUMPAD6", 0x66, -1);
//0067: VK_NUMPAD7
AddConstEx(id, "VK_NUMPAD7", 0x67, -1);
//0068: VK_NUMPAD8
AddConstEx(id, "VK_NUMPAD8", 0x68, -1);
//0069: VK_NUMPAD9
AddConstEx(id, "VK_NUMPAD9", 0x69, -1);
//006a: VK_MULTIPLY
AddConstEx(id, "VK_MULTIPLY", 0x6a, -1);
//006b: VK_ADD
AddConstEx(id, "VK_ADD", 0x6b, -1);
//006c: VK_SEPARATOR
AddConstEx(id, "VK_SEPARATOR", 0x6c, -1);
//006d: VK_SUBTRACT
AddConstEx(id, "VK_SUBTRACT", 0x6d, -1);
//006e: VK_DECIMAL
AddConstEx(id, "VK_DECIMAL", 0x6e, -1);
//006f: VK_DIVIDE
AddConstEx(id, "VK_DIVIDE", 0x6f, -1);
//0070: HK_CONTEXT1,VK_F1,VK_TSOFT1
AddConstEx(id, "VK_F1", 0x70, -1);
AddConstEx(id, "VK_TSOFT1", 0x70, -1);
AddConstEx(id, "HK_CONTEXT1", 0x70, -1);
//0071: HK_CONTEXT2,VK_F2,VK_TSOFT2
AddConstEx(id, "VK_F2", 0x71, -1);
AddConstEx(id, "HK_CONTEXT2", 0x71, -1);
AddConstEx(id, "VK_TSOFT2", 0x71, -1);
//0072: HK_CONTEXT3,VK_F3,VK_TTALK
AddConstEx(id, "VK_F3", 0x72, -1);
AddConstEx(id, "VK_TTALK", 0x72, -1);
AddConstEx(id, "HK_CONTEXT3", 0x72, -1);
//0073: HK_CONTEXT4,VK_F4,VK_TEND
AddConstEx(id, "VK_F4", 0x73, -1);
AddConstEx(id, "VK_TEND", 0x73, -1);
AddConstEx(id, "HK_CONTEXT4", 0x73, -1);
//0074: HK_HOOKSWITCH,VK_F5
AddConstEx(id, "VK_F5", 0x74, -1);
AddConstEx(id, "HK_HOOKSWITCH", 0x74, -1);
//0075: HK_SPEAKER,VK_DONE,VK_F6,VK_TVOLUMEUP
AddConstEx(id, "VK_F6", 0x75, -1);
AddConstEx(id, "VK_DONE", 0x75, -1);
AddConstEx(id, "VK_TVOLUMEUP", 0x75, -1);
AddConstEx(id, "HK_SPEAKER", 0x75, -1);
//0076: HK_MUTE,VK_F7,VK_MOJI,VK_TVOLUMEDOWN
AddConstEx(id, "VK_F7", 0x76, -1);
AddConstEx(id, "VK_TVOLUMEDOWN", 0x76, -1);
AddConstEx(id, "VK_MOJI", 0x76, -1);
AddConstEx(id, "HK_MUTE", 0x76, -1);
//0077: HK_HOLD,VK_F8,VK_TSTAR
AddConstEx(id, "VK_F8", 0x77, -1);
AddConstEx(id, "VK_TSTAR", 0x77, -1);
AddConstEx(id, "HK_HOLD", 0x77, -1);
//0078: HK_TRANSFER,VK_F9,VK_TPOUND
AddConstEx(id, "VK_F9", 0x78, -1);
AddConstEx(id, "VK_TPOUND", 0x78, -1);
AddConstEx(id, "HK_TRANSFER", 0x78, -1);
//0079: HK_REDIAL,VK_F10,VK_TRECORD
AddConstEx(id, "VK_F10", 0x79, -1);
AddConstEx(id, "HK_REDIAL", 0x79, -1);
AddConstEx(id, "VK_TRECORD", 0x79, -1);
//007a: HK_CONFERENCE,VK_F11,VK_SYMBOL
AddConstEx(id, "VK_F11", 0x7a, -1);
AddConstEx(id, "VK_SYMBOL", 0x7a, -1);
AddConstEx(id, "HK_CONFERENCE", 0x7a, -1);
//007b: HK_SHUTDOWN,VK_F12
AddConstEx(id, "VK_F12", 0x7b, -1);
AddConstEx(id, "HK_SHUTDOWN", 0x7b, -1);
//007c: VK_F13
AddConstEx(id, "VK_F13", 0x7c, -1);
//007d: VK_F14
AddConstEx(id, "VK_F14", 0x7d, -1);
//007e: VK_F15
AddConstEx(id, "VK_F15", 0x7e, -1);
//007f: VK_F16
AddConstEx(id, "VK_F16", 0x7f, -1);
//0080: VK_F17,VK_TFLIP
AddConstEx(id, "VK_F17", 0x80, -1);
AddConstEx(id, "VK_TFLIP", 0x80, -1);
//0081: VK_F18,VK_TPOWER
AddConstEx(id, "VK_F18", 0x81, -1);
AddConstEx(id, "VK_TPOWER", 0x81, -1);
//0082: VK_F19,VK_REDKEY
AddConstEx(id, "VK_F19", 0x82, -1);
AddConstEx(id, "VK_REDKEY", 0x82, -1);
//0083: VK_F20,VK_ROCKER
AddConstEx(id, "VK_F20", 0x83, -1);
AddConstEx(id, "VK_ROCKER", 0x83, -1);
//0084: VK_DPAD,VK_F21
AddConstEx(id, "VK_F21", 0x84, -1);
AddConstEx(id, "VK_DPAD", 0x84, -1);
//0085: VK_F22
AddConstEx(id, "VK_F22", 0x85, -1);
//0086: VK_ACTION,VK_F23
AddConstEx(id, "VK_F23", 0x86, -1);
AddConstEx(id, "VK_ACTION", 0x86, -1);
//0087: VK_F24
AddConstEx(id, "VK_F24", 0x87, -1);
//0090: VK_NUMLOCK,VK_OEM_NUMBER
AddConstEx(id, "VK_NUMLOCK", 0x90, -1);
AddConstEx(id, "VK_OEM_NUMBER", 0x90, -1);
//0091: VK_OEM_SCROLL,VK_SCROLL
AddConstEx(id, "VK_SCROLL", 0x91, -1);
AddConstEx(id, "VK_OEM_SCROLL", 0x91, -1);
//0092: VK_OEM_SHIFT
AddConstEx(id, "VK_OEM_SHIFT", 0x92, -1);
//00a0: VK_LSHIFT
AddConstEx(id, "VK_LSHIFT", 0xa0, -1);
//00a1: VK_RSHIFT
AddConstEx(id, "VK_RSHIFT", 0xa1, -1);
//00a2: VK_LCONTROL
AddConstEx(id, "VK_LCONTROL", 0xa2, -1);
//00a3: VK_RCONTROL
AddConstEx(id, "VK_RCONTROL", 0xa3, -1);
//00a4: VK_LMENU
AddConstEx(id, "VK_LMENU", 0xa4, -1);
//00a5: VK_RMENU
AddConstEx(id, "VK_RMENU", 0xa5, -1);
//00a6: VK_BROWSER_BACK
AddConstEx(id, "VK_BROWSER_BACK", 0xa6, -1);
//00a7: VK_BROWSER_FORWARD
AddConstEx(id, "VK_BROWSER_FORWARD", 0xa7, -1);
//00a8: VK_BROWSER_REFRESH
AddConstEx(id, "VK_BROWSER_REFRESH", 0xa8, -1);
//00a9: VK_BROWSER_STOP
AddConstEx(id, "VK_BROWSER_STOP", 0xa9, -1);
//00aa: VK_BROWSER_SEARCH
AddConstEx(id, "VK_BROWSER_SEARCH", 0xaa, -1);
//00ab: VK_BROWSER_FAVORITES
AddConstEx(id, "VK_BROWSER_FAVORITES", 0xab, -1);
//00ac: VK_BROWSER_HOME
AddConstEx(id, "VK_BROWSER_HOME", 0xac, -1);
//00ad: VK_VOLUME_MUTE
AddConstEx(id, "VK_VOLUME_MUTE", 0xad, -1);
//00ae: VK_VOLUME_DOWN
AddConstEx(id, "VK_VOLUME_DOWN", 0xae, -1);
//00af: VK_VOLUME_UP
AddConstEx(id, "VK_VOLUME_UP", 0xaf, -1);
//00b0: VK_MEDIA_NEXT_TRACK
AddConstEx(id, "VK_MEDIA_NEXT_TRACK", 0xb0, -1);
//00b1: VK_MEDIA_PREV_TRACK
AddConstEx(id, "VK_MEDIA_PREV_TRACK", 0xb1, -1);
//00b2: VK_MEDIA_STOP
AddConstEx(id, "VK_MEDIA_STOP", 0xb2, -1);
//00b3: VK_MEDIA_PLAY_PAUSE
AddConstEx(id, "VK_MEDIA_PLAY_PAUSE", 0xb3, -1);
//00b4: VK_LAUNCH_MAIL
AddConstEx(id, "VK_LAUNCH_MAIL", 0xb4, -1);
//00b5: VK_LAUNCH_MEDIA_SELECT
AddConstEx(id, "VK_LAUNCH_MEDIA_SELECT", 0xb5, -1);
//00b6: VK_LAUNCH_APP1
AddConstEx(id, "VK_LAUNCH_APP1", 0xb6, -1);
//00b7: VK_LAUNCH_APP2
AddConstEx(id, "VK_LAUNCH_APP2", 0xb7, -1);
//00b9: VK_OEM_0
AddConstEx(id, "VK_OEM_0", 0xb9, -1);
//00ba: VK_OEM_1,VK_SEMICOLON
AddConstEx(id, "VK_OEM_1", 0xba, -1);
AddConstEx(id, "VK_SEMICOLON", 0xba, -1);
//00bb: VK_EQUAL,VK_OEM_PLUS
AddConstEx(id, "VK_OEM_PLUS", 0xbb, -1);
AddConstEx(id, "VK_EQUAL", 0xbb, -1);
//00bc: VK_COMMA,VK_OEM_COMMA
AddConstEx(id, "VK_COMMA", 0xbc, -1);
AddConstEx(id, "VK_OEM_COMMA", 0xbc, -1);
//00bd: VK_HYPHEN,VK_OEM_MINUS
AddConstEx(id, "VK_HYPHEN", 0xbd, -1);
AddConstEx(id, "VK_OEM_MINUS", 0xbd, -1);
//00be: VK_OEM_PERIOD,VK_PERIOD
AddConstEx(id, "VK_OEM_PERIOD", 0xbe, -1);
AddConstEx(id, "VK_PERIOD", 0xbe, -1);
//00bf: VK_OEM_2,VK_SLASH
AddConstEx(id, "VK_SLASH", 0xbf, -1);
AddConstEx(id, "VK_OEM_2", 0xbf, -1);
//00c0: VK_BACKQUOTE,VK_OEM_3
AddConstEx(id, "VK_OEM_3", 0xc0, -1);
AddConstEx(id, "VK_BACKQUOTE", 0xc0, -1);
//00c1: VK_APP1,VK_APP_LAUNCH1
AddConstEx(id, "VK_APP_LAUNCH1", 0xc1, -1);
AddConstEx(id, "VK_APP1", 0xc1, -1);
//00c2: VK_APP2,VK_APP_LAUNCH2
AddConstEx(id, "VK_APP_LAUNCH2", 0xc2, -1);
AddConstEx(id, "VK_APP2", 0xc2, -1);
//00c3: VK_APP3,VK_APP_LAUNCH3
AddConstEx(id, "VK_APP3", 0xc3, -1);
AddConstEx(id, "VK_APP_LAUNCH3", 0xc3, -1);
//00c4: VK_APP4,VK_APP_LAUNCH4
AddConstEx(id, "VK_APP_LAUNCH4", 0xc4, -1);
AddConstEx(id, "VK_APP4", 0xc4, -1);
//00c5: VK_APP5,VK_APP_LAUNCH5
AddConstEx(id, "VK_APP5", 0xc5, -1);
AddConstEx(id, "VK_APP_LAUNCH5", 0xc5, -1);
//00c6: VK_APP6,VK_APP_LAUNCH6
AddConstEx(id, "VK_APP6", 0xc6, -1);
AddConstEx(id, "VK_APP_LAUNCH6", 0xc6, -1);
//00c7: VK_APP_LAUNCH7
AddConstEx(id, "VK_APP_LAUNCH7", 0xc7, -1);
//00c8: VK_APP_LAUNCH8
AddConstEx(id, "VK_APP_LAUNCH8", 0xc8, -1);
//00c9: VK_APP_LAUNCH9
AddConstEx(id, "VK_APP_LAUNCH9", 0xc9, -1);
//00ca: VK_APP_LAUNCH10
AddConstEx(id, "VK_APP_LAUNCH10", 0xca, -1);
//00cb: VK_APP_LAUNCH11
AddConstEx(id, "VK_APP_LAUNCH11", 0xcb, -1);
//00cc: VK_APP_LAUNCH12
AddConstEx(id, "VK_APP_LAUNCH12", 0xcc, -1);
//00cd: VK_APP_LAUNCH13
AddConstEx(id, "VK_APP_LAUNCH13", 0xcd, -1);
//00ce: VK_APP_LAUNCH14
AddConstEx(id, "VK_APP_LAUNCH14", 0xce, -1);
//00cf: VK_APP_LAUNCH15
AddConstEx(id, "VK_APP_LAUNCH15", 0xcf, -1);
//00db: VK_LBRACKET,VK_OEM_4
AddConstEx(id, "VK_OEM_4", 0xdb, -1);
AddConstEx(id, "VK_LBRACKET", 0xdb, -1);
//00dc: VK_BACKSLASH,VK_OEM_5
AddConstEx(id, "VK_OEM_5", 0xdc, -1);
AddConstEx(id, "VK_BACKSLASH", 0xdc, -1);
//00dd: VK_OEM_6,VK_RBRACKET
AddConstEx(id, "VK_OEM_6", 0xdd, -1);
AddConstEx(id, "VK_RBRACKET", 0xdd, -1);
//00de: VK_APOSTROPHE,VK_OEM_7
AddConstEx(id, "VK_APOSTROPHE", 0xde, -1);
AddConstEx(id, "VK_OEM_7", 0xde, -1);
//00df: VK_OEM_8,VK_OFF
AddConstEx(id, "VK_OFF", 0xdf, -1);
AddConstEx(id, "VK_OEM_8", 0xdf, -1);
//00e0: VK_OEM_9
AddConstEx(id, "VK_OEM_9", 0xe0, -1);
//00e2: VK_EXTEND_BSLASH,VK_OEM_102
AddConstEx(id, "VK_OEM_102", 0xe2, -1);
AddConstEx(id, "VK_EXTEND_BSLASH", 0xe2, -1);
//00e5: VK_PROCESSKEY
AddConstEx(id, "VK_PROCESSKEY", 0xe5, -1);
//00f0: VK_DBE_ALPHANUMERIC,VVK_ALPHANUM,VVK_ENGLISH
AddConstEx(id, "VK_DBE_ALPHANUMERIC", 0xf0, -1);
AddConstEx(id, "VVK_ENGLISH", 0xf0, -1);
AddConstEx(id, "VVK_ALPHANUM", 0xf0, -1);
//00f1: VK_DBE_KATAKANA
AddConstEx(id, "VK_DBE_KATAKANA", 0xf1, -1);
//00f2: VK_DBE_HIRAGANA
AddConstEx(id, "VK_DBE_HIRAGANA", 0xf2, -1);
//00f3: VK_DBE_SBCSCHAR
AddConstEx(id, "VK_DBE_SBCSCHAR", 0xf3, -1);
//00f4: VK_DBE_DBCSCHAR
AddConstEx(id, "VK_DBE_DBCSCHAR", 0xf4, -1);
//00f5: VK_DBE_ROMAN
AddConstEx(id, "VK_DBE_ROMAN", 0xf5, -1);
//00f6: VK_ATTN,VK_DBE_NOROMAN
AddConstEx(id, "VK_DBE_NOROMAN", 0xf6, -1);
AddConstEx(id, "VK_ATTN", 0xf6, -1);
//00f7: VK_CRSEL,VK_DBE_ENTERWORDREGISTERMODE
AddConstEx(id, "VK_DBE_ENTERWORDREGISTERMODE", 0xf7, -1);
AddConstEx(id, "VK_CRSEL", 0xf7, -1);
//00f8: VK_DBE_ENTERIMECONFIGMODE,VK_EXSEL
AddConstEx(id, "VK_DBE_ENTERIMECONFIGMODE", 0xf8, -1);
AddConstEx(id, "VK_EXSEL", 0xf8, -1);
//00f9: VK_DBE_FLUSHSTRING,VK_EREOF
AddConstEx(id, "VK_EREOF", 0xf9, -1);
AddConstEx(id, "VK_DBE_FLUSHSTRING", 0xf9, -1);
//00fa: VK_DBE_CODEINPUT,VK_PLAY
AddConstEx(id, "VK_DBE_CODEINPUT", 0xfa, -1);
AddConstEx(id, "VK_PLAY", 0xfa, -1);
//00fb: VK_DBE_NOCODEINPUT,VK_ZOOM
AddConstEx(id, "VK_DBE_NOCODEINPUT", 0xfb, -1);
AddConstEx(id, "VK_ZOOM", 0xfb, -1);
//00fc: VK_DBE_DETERMINESTRING,VK_NONAME
AddConstEx(id, "VK_NONAME", 0xfc, -1);
AddConstEx(id, "VK_DBE_DETERMINESTRING", 0xfc, -1);
//00fd: VK_DBE_ENTERDLGCONVERSIONMODE,VK_PA1
AddConstEx(id, "VK_DBE_ENTERDLGCONVERSIONMODE", 0xfd, -1);
AddConstEx(id, "VK_PA1", 0xfd, -1);
//00fe: VK_OEM_CLEAR
AddConstEx(id, "VK_OEM_CLEAR", 0xfe, -1);
//00ff: VK__none_
AddConstEx(id, "VK__none_", 0xff, -1);
}

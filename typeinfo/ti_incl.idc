#include <idc.idc>


#ifdef D1  // Delphi 1:
#define vmtTypeInfo          (-32)
#define vmtFieldTable        (-30)
#define vmtMethodTable       (-28)
#define vmtDynamicTable      (-26)
#define vmtClassName         (-24)
#define vmtInstanceSize      (-22)
#define vmtParent            (-20)
#define vmtDefaultHandler    (-16)
#define vmtNewInstance       (-12)
#define vmtFreeInstance      (-8 )
#define vmtDestroy           (-4 )
#endif

#ifdef D2  // Delphi 2:
#define vmtSelfPtr           (-52)
#define vmtInitTable         (-48)
#define vmtTypeInfo          (-44)
#define vmtFieldTable        (-40)
#define vmtMethodTable       (-36)
#define vmtDynamicTable      (-32)
#define vmtClassName         (-28)
#define vmtInstanceSize      (-24)
#define vmtParent            (-20)
#define vmtDefaultHandler    (-16)
#define vmtNewInstance       (-12)
#define vmtFreeInstance      (-8 )
#define vmtDestroy           (-4 )

//fake vars
#define vmtIntfTable          (-1)        //new in D3
#define vmtAutoTable          (-1)        //new in D3
#define vmtSafeCallException  (-1)
#define vmtAfterConstruction  (-1)  
#define vmtBeforeDestruction  (-1)  
#define vmtDispatch           (-1)   //new in D4
#define vmtSafeCallException  (-1)        //new in D3
#endif                          

#ifdef D3  // Delphi 3: 
#define vmtSelfPtr           (-64)
#define vmtIntfTable         (-60)        //new in D3
#define vmtAutoTable         (-56)        //new in D3
#define vmtInitTable         (-52)
#define vmtTypeInfo          (-48)
#define vmtFieldTable        (-44)
#define vmtMethodTable       (-40)
#define vmtDynamicTable      (-36)
#define vmtClassName         (-32)
#define vmtInstanceSize      (-28)
#define vmtParent            (-24)
#define vmtSafeCallException (-20)        //new in D3
#define vmtDefaultHandler    (-16)
#define vmtNewInstance       (-12)
#define vmtFreeInstance      (-8 )
#define vmtDestroy           (-4 )
//fake vars
#define vmtAfterConstruction  (-1)
#define vmtBeforeDestruction  (-1)
#define vmtDispatch           (-1)   //new in D4
#endif

#ifdef D4  //   Delphi 4: 
#define vmtSelfPtr            (-76)
#define vmtIntfTable          (-72)
#define vmtAutoTable          (-68)
#define vmtInitTable          (-64)
#define vmtTypeInfo           (-60)
#define vmtFieldTable         (-56)
#define vmtMethodTable        (-52)
#define vmtDynamicTable       (-48)
#define vmtClassName          (-44)
#define vmtInstanceSize       (-40)
#define vmtParent             (-36)
#define vmtSafeCallException  (-32)
#define vmtAfterConstruction  (-28)   //new in D4
#define vmtBeforeDestruction  (-24)   //new in D4
#define vmtDispatch           (-20)   //new in D4
#define vmtDefaultHandler     (-16)
#define vmtNewInstance        (-12)
#define vmtFreeInstance       (-8 )
#define vmtDestroy            (-4 )
#endif                            

#ifdef BCB  //   Delphi 4:      
#define vmtSelfPtr            (-64)
#define vmtInitTable          (-60)
#define vmtTypeInfo           (-56)
#define vmtFieldTable         (-52)
#define vmtMethodTable        (-48)
#define vmtDynamicTable       (-44)
#define vmtClassName          (-40)
#define vmtInstanceSize       (-36)
#define vmtParent             (-32)
#define vmtAfterConstruction  (-28)   //new in D4
#define vmtBeforeDestruction  (-24)   //new in D4
#define vmtDispatch           (-20)   //new in D4
#define vmtDefaultHandler     (-16)
#define vmtNewInstance        (-12)
#define vmtFreeInstance       (-8 )
#define vmtDestroy            (-4 )

#define vmtSafeCallException  (-1)
#define vmtIntfTable          (-1)
#define vmtAutoTable          (-1)
#define D4
#endif                            

 /*
   TTypeKind = (tkUnknown, tkInteger, tkChar, tkEnumeration, tkFloat,
    tkString, tkSet, tkClass, tkMethod, tkWChar, tkLString, tkWString,
    tkVariant, tkArray, tkRecord, tkInterface, tkInt64, tkDynArray);
 */
#ifndef FPC
#define tkUnknown 0
#define tkInteger 1
#define tkChar    2
#define tkEnumeration 3
#define tkFloat   4
#define tkString  5
#define tkSet     6
#define tkClass   7
#define tkMethod  8
#define tkWChar   9
#define tkLString 10
#define tkWString 11
#define tkVariant 12
#define tkArray   13
#define tkRecord  14
#define tkInterface 15
#define tkInt64   16
#define tkDynArray 17
#else //FPC
#define tkUnknown 0
#define tkInteger 1
#define tkChar    2
#define tkEnumeration 3
#define tkFloat   4
#define tkString  5
#define tkSet     6
#define tkClass   7
#define tkMethod  8
#define tkLString 9
#define tkWString 10
#define tkVariant 11
#define tkArray   12
#define tkRecord  13
#define tkInterface 14
#define tkInt64   15
#define tkDynArray 16

#define tkWChar   -1
#endif //FPC

#define otSByte 0
#define otUByte 1
#define otSWord 2
#define otUWord 3
#define otSLong 4
#define otULong 5

#define mkProcedure      0
#define mkFunction       1
#define mkConstructor    2
#define mkDestructor     3
#define mkClassProcedure 4
#define mkClassFunction  5
#define mkSafeProcedure  6
#define mkSafeFunction   7

static InitEnums()
{
 auto enum_id,enum_name;

 enum_name="VMT_Offsets";
 enum_id = AddEnum( GetEnumQty() + 1, enum_name, FF_0NUMH);
 if ( enum_id == -1) {
     enum_id = GetEnum( enum_name );
     if(enum_id == -1) Message("Enum not created/not found\n");
 }
 if (enum_id!=-1)
 {
   AddConst(enum_id,"vmtTypeInfo"       ,vmtTypeInfo      );
   AddConst(enum_id,"vmtFieldTable"     ,vmtFieldTable    );
   AddConst(enum_id,"vmtMethodTable"    ,vmtMethodTable   );
   AddConst(enum_id,"vmtDynamicTable"   ,vmtDynamicTable  );
   AddConst(enum_id,"vmtClassName"      ,vmtClassName     );
   AddConst(enum_id,"vmtInstanceSize"   ,vmtInstanceSize  );
   AddConst(enum_id,"vmtParent"         ,vmtParent        );
   AddConst(enum_id,"vmtDefaultHandler" ,vmtDefaultHandler);
   AddConst(enum_id,"vmtNewInstance"    ,vmtNewInstance   );
   AddConst(enum_id,"vmtFreeInstance"   ,vmtFreeInstance  );
   AddConst(enum_id,"vmtDestroy"        ,vmtDestroy       );
   AddConst(enum_id,"vmtSelfPtr"        ,vmtSelfPtr       );
   AddConst(enum_id,"vmtInitTable"      ,vmtInitTable     );
#ifdef D3
   AddConst(enum_id,"vmtIntfTable"      ,vmtIntfTable     );
   AddConst(enum_id,"vmtAutoTable"      ,vmtAutoTable     );
   AddConst(enum_id,"vmtSafeCallException" ,vmtSafeCallException);
#endif
#ifdef D4
   AddConst(enum_id,"vmtIntfTable"      ,vmtIntfTable     );
   AddConst(enum_id,"vmtAutoTable"      ,vmtAutoTable     );
   AddConst(enum_id,"vmtSafeCallException" ,vmtSafeCallException);
   AddConst(enum_id,"vmtAfterConstruction" ,vmtAfterConstruction);
   AddConst(enum_id,"vmtBeforeDestruction" ,vmtBeforeDestruction);
   AddConst(enum_id,"vmtDispatch"          ,vmtDispatch         );
#endif
 }
 enum_name="TTypeKind";
 enum_id = AddEnum( GetEnumQty() + 1, enum_name, FF_0NUMH);
 if ( enum_id == -1) {
     enum_id = GetEnum( enum_name );
     if(enum_id == -1) Message("Enum not created/not found\n");
 }
 if (enum_id!=-1)
 {
   AddConst(enum_id,"tkUnknown",tkUnknown);
   AddConst(enum_id,"tkInteger",tkInteger);
   AddConst(enum_id,"tkChar",tkChar);
   AddConst(enum_id,"tkEnumeration",tkEnumeration);
   AddConst(enum_id,"tkFloat",tkFloat);
   AddConst(enum_id,"tkString",tkString);
   AddConst(enum_id,"tkSet",tkSet);
   AddConst(enum_id,"tkClass",tkClass);
   AddConst(enum_id,"tkMethod",tkMethod);
   AddConst(enum_id,"tkWChar",tkWChar);
   AddConst(enum_id,"tkLString",tkLString);
   AddConst(enum_id,"tkWString",tkWString);
   AddConst(enum_id,"tkVariant",tkVariant);
   AddConst(enum_id,"tkArray",tkArray);
   AddConst(enum_id,"tkRecord",tkRecord);
   AddConst(enum_id,"tkInterface",tkInterface);
   AddConst(enum_id,"tkInt64",tkInt64);
   AddConst(enum_id,"tkDynArray",tkDynArray);
 }
 /*
  TOrdType = (otSByte, otUByte, otSWord, otUWord, otSLong);
 */
 enum_id=AddEnum(GetEnumQty()+1,"TOrdType",FF_0NUMH);
 if (enum_id!=-1)
 {
   AddConst(enum_id,"otSByte",0);
   AddConst(enum_id,"otUByte",1);
   AddConst(enum_id,"otSWord",2);
   AddConst(enum_id,"otUWord",3);
   AddConst(enum_id,"otSLong",4);
 }

 /*
  TFloatType = (ftSingle, ftDouble, ftExtended, ftComp, ftCurr);
 */
 enum_id=AddEnum(GetEnumQty()+1,"TFloatType",FF_0NUMH);
 if (enum_id!=-1)
 {
   AddConst(enum_id,"ftSingle",0);
   AddConst(enum_id,"ftDouble",1);
   AddConst(enum_id,"ftExtended",2);
   AddConst(enum_id,"ftComp",3);
   AddConst(enum_id,"ftCurr",4);
 }

 /*
  TMethodKind = (mkProcedure, mkFunction, mkConstructor, mkDestructor,
    mkClassProcedure, mkClassFunction,
    { Obsolete }
    mkSafeProcedure, mkSafeFunction);
 */

 enum_id=AddEnum(GetEnumQty()+1,"TMethodKind",FF_0NUMH);
 if (enum_id!=-1)
 {
   AddConst(enum_id,"mkProcedure",0);
   AddConst(enum_id,"mkFunction",1);
   AddConst(enum_id,"mkConstructor",2);
   AddConst(enum_id,"mkDestructor",3);
   AddConst(enum_id,"mkClassProcedure",4);
   AddConst(enum_id,"mkClassFunction",5);
   AddConst(enum_id,"mkSafeProcedure",6);
   AddConst(enum_id,"mkSafeFunction",7);
 }

}
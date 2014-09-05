#if !defined(UTILS_IDC)
#define UTILS_IDC 1

/*
// File:
//   utils.idc
//
// Created by:
//   Atli Gudmundsson (agudmundsson@symantec.com)
//
// Purpose:
//   Container for various auxiliary utility functions
//
// Usage:
//   Include in main script as #include <utils.idc>
//
// Fixes/additions
//   amg - 02-09-2002 - 1st version (functions moved from pe_sections.idc and pe_dlls.idc).
*/

static WarningMessage(outString)
{
  Message(outString + "\n");
  Warning(outString);
}

/*
// Function:
//   MySeek
// Input:
//   fhandle
//   offset
//   method (0 - from start of file, 1 - from current pos, 2 - from end of file)
// Returns:
//    0 - success
//   -1 - a file error, unable to seek to that address.
// Notes:
//   The function also prints messages (if return value != 0), which indicate what happened.
*/
static MySeek(fhandle, offset, method)
{
  if(fseek(fhandle, offset, method) != 0)
  {
    Message("  file seek error (method:offset 0x%x:%.8X)!", method, offset);
    return -1;
  }
  return 0;
}

/*
// Function:
//   fgetStr
// Purpose:
//   Returns an ASCII string, read from the current file position.  After the read
//   the file pointer will be positioned 'size' bytes from where the read started.
// Input:
//   fhandle
//   size 
// Returns:
//   a string
*/
static fgetStr(fHandle, size)
{
  auto result, charRead;

  result = "\0";
  charRead = "A";

  while(size && (charRead != '\0'))
  {
    charRead = fgetc(fHandle);

    result = result + charRead;

    --size;
  }

  if(charRead != '\0')
  {
    result = result + '\0';
  }

  if(size != 0)
  {
    MySeek(fHandle, size, 1);
  }

  return result;
}

/*
sec per day         =     sd =      24*60*60 =      86400 = 0x00015180
sec per normal year =     sy =        365*sd =   31536000 = 0x01e13380
sec per leap year   =    sly =       sy + sd =   31622400 = 0x01e28500
sec per normal 4 year cycle (with no leap year)
                    =    s4y =          4*sy =  126144000 = 0x0784ce00
sec per normal 4 year cycle (with one leap year)
                    =   s4ly =     4*sy + sd =  126230400 = 0x07861f80
sec per normal 100 year cycle (not including the leap years)
                    =  s100y =        25*s4y = 3153600000 = 0xbbf81e00
sec per normal 100 year cycle (including the leap years)
                    = s100ly =       25*s4ly = 3155760000 = 0xbc191380

sec till 1972       =  s1972 =          2*sy =   63072000 = 0x03c26700
sec till 2000       =  s2000 =   2*sy + 7*c4 =  946684800 = 0x386d4380
sec in 100 year cycle after 1999 (not including 1999)
                    =   c100 =         25*c4 = 3155760000 = 0xbc191380
sec till 2100       =  s2100 = s2000 + 25*c4 = 4102444800 = 0xf4865700

note: 2100 is not a leap year (centuries only on 400 year intervals).
*/

static ULDateToStr(TimeStamp)
{
  auto year, month, day, hour, min;
  auto leap;
  auto RetString;

  if((TimeStamp == 0xffffffff) || (TimeStamp == 0))
  {
    return "uninitialized";
  }

  // note: ida doesn't support unsigned values...  there for...

  year = 1970;

  while(TimeStamp < 0)
  {
    year        = year + 68;              // ok, since 2000 is a leap year.
    TimeStamp   = TimeStamp - 2145916800; // 68 years (in seconds)
  }

  leap        = TimeStamp/126230400;      // div by 4 year cycle number (with leap year)
  TimeStamp   = TimeStamp - leap*126230400;

  year        = year + leap*4;
  leap        = 0;

  if(TimeStamp >= 31536000)
  {
    year++;
    TimeStamp = TimeStamp - 31536000;

    if(TimeStamp >= 31536000)
    {
      year++;
      TimeStamp = TimeStamp - 31536000;

      if(year != 2100)
      {
        if(TimeStamp >= 31622400)
        {
          year++;
          TimeStamp = TimeStamp - 31622400;
        }
        else
        {
          leap = 1;
        }
      }
      else
      {
        if(TimeStamp >= 31536000)
        {
          year++;
          TimeStamp = TimeStamp - 31536000;

          if(TimeStamp >= 31536000)
          {
            // because this is not a leap year we might have one too many days.
            year++;
            TimeStamp = TimeStamp - 31536000;
          }
        }
      }
    }
  }

  //      year - year number
  //      leap - 1 if it is a leap year
  // TimeStamp - number of seconds passed into the year

  day       = TimeStamp/86400;       // 0 <= day < 365
  TimeStamp = TimeStamp - day*86400;
  month     = 1;

  while(1)
  {
    // jan - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // feb - 28 + 1(leap)
    if(day < (28 + leap))
      break;
    day = day - (28 + leap);
    month++;

    // mar - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // apr - 30
    if(day < 30)
      break;
    day = day - 30;
    month++;

    // may - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // jun - 30
    if(day < 30)
      break;
    day = day - 30;
    month++;

    // jul - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // aug - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // sep - 30
    if(day < 30)
      break;
    day = day - 30;
    month++;

    // okt - 31
    if(day < 31)
      break;
    day = day - 31;
    month++;

    // nov - 30
    if(day < 30)
      break;
    day = day - 30;
    month++;

    // des - 31
    break;
  }

  day = day + 1;

  // TimeStamp - number of seconds passed into the day-month-year

  hour      = TimeStamp/3600;
  TimeStamp = TimeStamp - (hour*3600);
  min       = TimeStamp/60;
  TimeStamp = TimeStamp - (min*60);

  RetString = form("%i-%s-%i %i:%.02i:%.02i", day, getMonthStr(month), year, hour, min, TimeStamp);

  return RetString;
}

static getMonthStr(month)
{
  if(!--month)
  {
    return "jan";
  }

  if(!--month)
  {
    return "feb";
  }

  if(!--month)
  {
    return "mar";
  }

  if(!--month)
  {
    return "apr";
  }

  if(!--month)
  {
    return "may";
  }

  if(!--month)
  {
    return "jun";
  }

  if(!--month)
  {
    return "jul";
  }

  if(!--month)
  {
    return "aug";
  }

  if(!--month)
  {
    return "sep";
  }

  if(!--month)
  {
    return "oct";
  }

  if(!--month)
  {
    return "nov";
  }

  if(!--month)
  {
    return "dec";
  }

  return "invalid";
}

static ULDosDateToStr(TimeStamp)
{
  auto year, month, day, hour, min, sec;
  auto leap;
  auto RetString;

  if((TimeStamp == 0xffffffff) || (TimeStamp == 0))
  {
    return "uninitialized";
  }

  // TimeStamp is a DOS date of the following format
  //
  // 33222222222211111111110000000000
  // 10987654321098765432109876543210
  // |    |     |    |      |   |
  // |    |     |    |      |   +++++ --- day         (5)  4 -  0
  // |    |     |    |      ++++ -------- month       (4)  8 -  5
  // |    |     |    +++++++ ------------ year - 1980 (7) 15 -  9
  // |    |     +++++ ------------------- seconds/2   (5) 20 - 16
  // |    ++++++ ------------------------ minutes     (6) 26 - 21
  // +++++ ------------------------------ hours       (5) 31 - 27

  day   =  (TimeStamp)       & 0x1f;
  month =  (TimeStamp >> 5)  & 0x0f;
  year  = ((TimeStamp >> 9)  & 0x7f) + 1980;
  sec   = ((TimeStamp >> 16) & 0x1f) << 1;
  min   =  (TimeStamp >> 21) & 0x3f;
  hour  =  (TimeStamp >> 27) & 0x1f;

  RetString = form("%i-%s-%i %i:%.02i:%.02i", day, getMonthStr(month), year, hour, min, sec);

  return RetString;
}

/*
// Function:
//   Str
// Purpose:
//   gets the zero terminated c-string, located at address ea.
//   basically a Byte() function for strings.
// Input:
//   ea
// Returns:
//   the str at the particular address OR
//   the empty str, if nothing was there.
// Notes:
//   no notes.
*/
static Str(ea)
{
  auto retStr;
  auto in_char;

  retStr = "";

  while((SegStart(ea) != BADADDR) && (in_char = Byte(ea++)))
  {
    retStr = form("%s%c", retStr, in_char);
  }

  return retStr;
}

/*
// Function:
//   ForceStruct
// Purpose:
//   Force the creation of a structure at a particular ea, effectively
//   overwrides any data creation by IDA.
// Input:
//   ea
//   name
// Returns:
//   nothing
// Notes:
//   The function prints a message and warns the user if anything unusual happend.
*/
static ForceStruct(ea, name)
{
  auto sHandle, i;

  sHandle = GetStrucIdByName(name);

  if(sHandle == -1)
  {
    WarningMessage("Unable to find the " + name + " structure!\n");
    return -1;
  }
  
  i = GetStrucSize(sHandle);

  while(i--)
  {
    MakeUnkn(ea + i, 0);
  }
  
  MakeStruct(ea, name);
}

static ForceName(ea, name)
{
  if(ea)
  {
    if(isTail(GetFlags(ea)))
    {
      MakeUnkn(ea, 0);
    }

    MakeName(ea, name);
  }
}

static ForceWord(ea)
{
  if(ea)
  {
    if(isTail(GetFlags(ea)))
    {
      MakeUnkn(ea, 0);
    }

    if(isTail(GetFlags(ea+1)))
    {
      MakeUnkn(ea+1, 0);
    }

    MakeWord(ea);
  }
}

static ForceDword(ea)
{
  if(ea)
  {
    if(isTail(GetFlags(ea)))
    {
      MakeUnkn(ea, 0);
    }

    if(isTail(GetFlags(ea+1)))
    {
      MakeUnkn(ea+1, 0);
    }

    if(isTail(GetFlags(ea+2)))
    {
      MakeUnkn(ea+2, 0);
    }

    if(isTail(GetFlags(ea+3)))
    {
      MakeUnkn(ea+3, 0);
    }

    MakeDword(ea);
  }
}

static ForceStr(ea, endea)
{
  if(ea)
  {
    auto oldStrType;

    if(isTail(GetFlags(ea)))
    {
      MakeUnkn(ea, 0);
    }

    oldStrType = GetLongPrm(INF_STRTYPE); // save the old string type
    SetLongPrm(INF_STRTYPE, ASCSTR_TERMCHR); // set the string type to ASCII, zero terminated

    MakeStr(ea, endea);

    SetLongPrm(INF_STRTYPE, oldStrType); // restore the old string type
  }
}

static LEWord(ea)
{
  // if undefined then we want to get a zero and not a 0xff.

  auto flags;
  auto retval;
  
  if(hasValue(GetFlags(ea)))
  {
    retval = Byte(ea);
  }
  else
  {
    retval = 0;
  }

  if(hasValue(GetFlags(++ea)))
  {
    retval = retval | (Byte(ea) << 8);
  }

  return retval;
}

static LEDword(ea)
{
  // if undefined then we want to get a zero and not a 0xff.

  auto flags;
  auto retval;
  
  if(hasValue(GetFlags(ea)))
  {
    retval = Byte(ea);
  }
  else
  {
    retval = 0;
  }

  if(hasValue(GetFlags(++ea)))
  {
    retval = retval | (Byte(ea) << 8);
  }

  if(hasValue(GetFlags(++ea)))
  {
    retval = retval | (Byte(ea) << 16);
  }

  if(hasValue(GetFlags(++ea)))
  {
    retval = retval | (Byte(ea) << 24);
  }

  return retval;
}

static FirstNamedSeg(SegToFind)
{
  auto segName;
  auto current;

#if defined(DEBUG_THIS)
  WarningMessage(form("FirstNamedSeg: %s\n", SegToFind));
#endif

  current = FirstSeg();

  while(current != BADADDR)
  {
    segName = SegName(current);

#if defined(DEBUG_THIS)
    WarningMessage(form("- SegName: %s", segName));
#endif

    if(segName == SegToFind)
    {
      return current;
    }

    current = NextSeg(current);
  }

  return BADADDR;
}


static toupper(value)
{
  if((value < "a") || (value > "z"))
  {
    return value;
  }

  if(value == "a")
  {
    return "A";
  }
  else if(value == "b")
  {
    return "B";
  }
  else if(value == "c")
  {
    return "C";
  }
  else if(value == "d")
  {
    return "D";
  }
  else if(value == "e")
  {
    return "E";
  }
  else if(value == "f")
  {
    return "F";
  }
  else if(value == "g")
  {
    return "G";
  }
  else if(value == "h")
  {
    return "H";
  }
  else if(value == "i")
  {
    return "I";
  }
  else if(value == "j")
  {
    return "J";
  }
  else if(value == "k")
  {
    return "K";
  }
  else if(value == "l")
  {
    return "L";
  }
  else if(value == "m")
  {
    return "M";
  }
  else if(value == "n")
  {
    return "N";
  }
  else if(value == "o")
  {
    return "O";
  }
  else if(value == "p")
  {
    return "P";
  }
  else if(value == "q")
  {
    return "Q";
  }
  else if(value == "r")
  {
    return "R";
  }
  else if(value == "s")
  {
    return "S";
  }
  else if(value == "t")
  {
    return "T";
  }
  else if(value == "u")
  {
    return "U";
  }
  else if(value == "v")
  {
    return "V";
  }
  else if(value == "w")
  {
    return "W";
  }
  else if(value == "x")
  {
    return "X";
  }
  else if(value == "y")
  {
    return "Y";
  }
  else if(value == "z")
  {
    return "Z";
  }
}

static AddNZOffset(sHandle, name, s_offset, base,  PEoffset)
{
  if(LEDword(base + PEoffset + s_offset) == 0)
  {
    return AddStrucMember(sHandle, name, s_offset, FF_DWRD, -1, 4); 
  }
  else
  {
    return AddStrucMember(sHandle, name, s_offset, FF_DWRD | FF_0OFF, base, 4); 
  }
}

static CommentFlagOn(comment, flags, flag_num, string)
{
  auto retstr, mask;

  retstr  = "";
  mask    = (1 << flag_num);

  if(flags & mask)
  {
    retstr = "\n    " + form("0x%08x - 1 - ", mask) + string;
  }

  return retstr;
}

#endif // define UTILS_IDC
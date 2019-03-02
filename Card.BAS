Rem BasicCard Sample Source Code Template
Rem ------------------------------------------------------------------
Rem Copyright (C) 2008 ZeitControl GmbH
Rem You have a royalty-free right to use, modify, reproduce and 
Rem distribute the Sample Application Files (and/or any modified 
Rem version) in any way you find useful, provided that you agree 
Rem that ZeitControl GmbH has no warranty, obligations or liability
Rem for any Sample Application Files.
Rem ------------------------------------------------------------------
Option Explicit

#include Card.def

#IfDef MultiAppBasicCard
  ' This section is required for MultiApplication BasicCards only
  ' it is ignored for Enhanced and Professional BasicCards
  #Include COMPONNT.DEF
  Dir "\"
    Application "DefaultApp" ' Make this the Default Application
      Lock=Execute:Always
  End Dir
#EndIf

' This variable is of storage type EEPROM
' and thus persistent
EEPROM CardData as String

' This command just returns "Hello World" in response
' Since no input data is required, LC is set to 0
Command &H88 &H00 getHOTP(Data as String)
    'Data = HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")
    private intCounter as Long = 0
    private i as byte
    for i = 1 to 8:
        intCounter = (intCounter Shl 8) + asc(Data(i))
    next

    Data = HOTP("12345678901234567890", intCounter, 6)
End Command

' This command saves Data in EEPROM.
' Since no output data is required, LE is disabled
Command &H88 &H02 WriteData(Data as String, Disable LE)
   ' Just copy it to EEPROM variable to save it
   CardData=Data
End Command

' This command reads data written by WriteData and 
' returns this data in response.
' Since no input data is required, LC is set to 0
Command &H88 &H04 ReadData(LC=0, Data as String)
   Data=CardData
End Command



Command &H88 &H06 Benchmark()
    private pool as String*64
    private i as Integer = 0
    for i = 1 to 100
        pool = ShaHash(pool)
    next
   
End Command
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



Command &H88 &H00 API_AT(Data as string)
    Data = ATCOMMAND(Data)
End Command

Command &H88 &H88 EXECUTE_FACTORY_RESET(Data as String)
    call FACTORY_RESET(Data)
End Command
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

#include CARDAPI.term.def
#Include COMMANDS.DEF
#Include COMMERR.DEF
#include MISC.DEF
#Include CARDUTIL.DEF

#include AES.DEF
#include SHA.DEF

#include STRING.card.bas
#include BUFFERS.card.bas
#include HMAC.card.bas
#include HOTP.card.bas
#include CRYPTO.card.bas






BEGIN:



'  Execution starts here

' Wait for a card
Call WaitForCard()
' Reset the card and check status code SW1SW2
ResetCard : Call CheckSW1SW2()



public buffer as string
private default_password as string = "7004b87c57cc598f518e839b3b4000aa949c531b4ebf45da1688994a2676c535"

print "Start."


print "Check card status."
buffer = "AT+STATUS"
call API_AT(buffer) : call CheckSW1SW2()
print "Card status: ", buffer

if buffer = "+STATUS:UNINITIALIZED" then
    print("Reset card.")
    call EXECUTE_FACTORY_RESET("killme") : call CheckSW1SW2()
    
    buffer = "AT+SETPWD=" + default_password
    call API_AT(buffer) : call CheckSW1SW2()
end if

buffer = "AT+UNLOCK=" + default_password
call API_AT(buffer) : call CheckSW1SW2()

buffer = "AT+STATUS"
call API_AT(buffer) : call CheckSW1SW2()
if buffer = "+STATUS:UNLOCKED" then
    print "CARD UNLOCKED >>"
    print ""
else
    goto TERMINATE
end if
   


while 1
    print "AT+";
    Line Input buffer
    buffer = "AT+" + buffer
    call API_AT(buffer)
    call CheckSW1SW2()
    print buffer
    print ""
wend






TERMINATE:

private a$
print "Press any key to start agin..."
Line Input a$
GOTO BEGIN
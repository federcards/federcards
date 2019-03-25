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
#include SECMSG.term.bas


Declare Key &H01(32)





BEGIN:



'  Execution starts here

' Wait for a card
Call WaitForCard()
' Reset the card and check status code SW1SW2
ResetCard : Call CheckSW1SW2()



public buffer as string

buffer = "test"
call EXECUTE_FACTORY_RESET(buffer) : call CheckSW1SW2()

' A String variable to hold the response
private card_status as string*1

call API_CARD_STATUS(card_status)
call CheckSW1SW2()

private password as string
private challenge as string=""
private challenge_secret as string
private challenge_answer as string
private default_password_tried as byte = 0

while card_status(1) <> chr$(&HFF)
    if card_status(1) = chr$(&H00) then
        print "Card disabled or needs factory reset."
        GOTO TERMINATE
    end if
    
    
    print "Requesting challenge"
    call API_GET_CHALLENGE(challenge)
    print Str2Hex(challenge)
    print ""
    
    if not default_password_tried then
        password = "FEDER CARD"
        default_password_tried = 1
    else
        print "Input password, remaining times: " + chr$(asc(card_status(1)) + 48)
        Line Input password
    end if
    
    challenge_secret = SECMSG_DECRYPT_CHALLENGE(password, challenge)
    challenge_answer = SECMSG_GENERATE_ANSWER(password, challenge_secret)
    print "Answer: "; Str2Hex(challenge_answer)
    
    buffer = challenge_answer
    call API_SET_ANSWER(buffer)
    card_status = buffer(1)
    
wend

Key(&H01) = Sha256Hash(challenge_secret)

call ProEncryption(P1=AlgAes128, P2=&H01, Rnd, Rnd)
call CheckSW1SW2()


if SECMSG_IN_FORCE() then
    print "********** Secure Messaging Started. **********"
else
    print "!!!!!!!!!! Secure Messaging Failure. !!!!!!!!!!"
    GOTO TERMINATE
end if


buffer = "AT+STATUS"
call API_AT(buffer) : call CheckSW1SW2()
if buffer = "UNINITIALIZED" then
    buffer = "AT+SETPWD=TEST"
    call API_AT(buffer) : call CheckSW1SW2()
end if
buffer = "AT+UNLOCK=TEST"
call API_AT(buffer) : call CheckSW1SW2()

buffer = "AT+STATUS"
call API_AT(buffer) : call CheckSW1SW2()
if buffer = "UNLOCKED" then
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
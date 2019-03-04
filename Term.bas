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

#include BUFFERS.card.bas
#include HMAC.card.bas
#include HOTP.card.bas
#include CRYPTO.card.bas
#include SECMSG.term.bas

Declare Key &H01(32)


Function Str2Hex(ByVal strInput as String) as String
    private i as Integer
    for i = 1 to len(strInput)
        Str2Hex = Str2Hex + Hex$(asc(strInput(i)))
    next
End Function


BEGIN:



'  Execution starts here

' Wait for a card
Call WaitForCard()
' Reset the card and check status code SW1SW2
ResetCard : Call CheckSW1SW2()



public buffer as string

' A String variable to hold the response
private card_status as string*1

call API_CARD_STATUS(card_status)
call CheckSW1SW2()

private password as string
private challenge as string=""
private challenge_secret as string
private challenge_answer as string

while card_status(1) <> chr$(&HFF)
    if card_status(1) = chr$(&H00) then
        print "Card disabled or needs factory reset."
        GOTO TERMINATE
    end if
    
    
    print "Requesting challenge"
    call API_GET_CHALLENGE(challenge)
    print Str2Hex(challenge)
    print ""
    
    
    print "Input password, remaining times: " + chr$(asc(card_status(1)) + 48)
    Line Input password
    
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
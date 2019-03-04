#include SECMSG.common.bas

' ******************************************************************************
' Secure messaging Negotiation and Management
'
' Usage:
' 
' API should call SECMSG_GET_CHALLENGE() for current challenge that needs to be
' answered in order to start encryption. This challenge does not change within a
' session before an answer is inputed.
'   To answer the challenge, a call to SECMSG_SET_ANSWER() is necessary. The
' answer is verified, and if wrong for sequentially 5 times, the card is
' disabled and only initialization commands will be accepted. As return value
' for each call, the remaining allowed attempts is returned upon verification
' failure, or, if successful, &HFF is returned.


const SECMSG_FRESH_ATTEMPTS = 5


Eeprom SECMSG_SHAREDSECRET as string*SECMSG_SHAREDSECRET_LENGTH
Eeprom SECMSG_REMAINING_ATTEMPTS as Byte


function SECMSG_FACTORY_RESET() as Byte
    ' returns 1 if successful, else 0
    ' THIS FUNCTION MUST NOT BE CALLED INDIVIDUALLY. IT MUST BE PART OF The
    ' TOTAL FACTORY RESET PROCEDURE!
    if SECMSG_REMAINING_ATTEMPTS > 0 then
        SECMSG_FACTORY_RESET = 0
        exit function
    end if
    SECMSG_SHAREDSECRET = "FEDER CARD"
    SECMSG_REMAINING_ATTEMPTS = SECMSG_FRESH_ATTEMPTS
    SECMSG_FACTORY_RESET = 1
    Disable Key &H01
end function




public SECMSG_CHALLENGE_SECRET as string
public SECMSG_REQUIRED_ANSWER as string
public SECMSG_READY as byte = 0


function SECMSG_IN_FORCE() as Byte
    ' if secmsg is already started
    if (ALGORITHM <> 0 or KEYNUMBER <> 0) and SECMSG_READY <> 0 then
        SECMSG_IN_FORCE = 1
    else
        SECMSG_IN_FORCE = 0
        Disable Key &H01
    end if
end function





function SECMSG_GET_CHALLENGE() as String
    private challenge as String
    
    if SECMSG_IN_FORCE() or SECMSG_READY <> 0 or SECMSG_REMAINING_ATTEMPTS < 1 then
        ' if secure messaging is ready or already started, or died, forbid further challenges
        SECMSG_GET_CHALLENGE = ""
        exit function
    end if
    
    if SECMSG_CHALLENGE_SECRET = "" then ' generate a new challenge
        SECMSG_CHALLENGE_SECRET = Left$(crypto_random32bytes(), 16) 'one block only
        SECMSG_REQUIRED_ANSWER = Left$(ShaHash(SECMSG_CHALLENGE_SECRET + "answer"), 16)
    end if
    challenge = AES(256, Sha256Hash(SECMSG_SHAREDSECRET), SECMSG_CHALLENGE_SECRET)
    SECMSG_GET_CHALLENGE = challenge
end function


function SECMSG_STATUS() as Byte
    if SECMSG_REMAINING_ATTEMPTS < 1 then
        SECMSG_STATUS = &H00    ' tell outside this is already died, exit
        Disable Key &H01
        exit function
    end if
    if SECMSG_READY <> 0 or SECMSG_IN_FORCE() then
        SECMSG_STATUS = &HFF    ' tell outside we are ready for encryption
        exit function
    end if
    SECMSG_STATUS = SECMSG_REMAINING_ATTEMPTS
end function


function SECMSG_SET_ANSWER(answer as String) as Byte
    private decrypted_answer as string
    private last_attempts as byte
    if SECMSG_REMAINING_ATTEMPTS < 1 then
        SECMSG_SET_ANSWER = &H00    ' tell outside this is already died, exit
        exit function
    end if
    if SECMSG_READY <> 0 or SECMSG_IN_FORCE() then
        SECMSG_SET_ANSWER = &HFF    ' tell outside we are ready for encryption
        exit function
    end if
    
    private k as string
    private ss as string
    ss = SECMSG_SHAREDSECRET
    k = Sha256Hash(ss)
    
    last_attempts = SECMSG_REMAINING_ATTEMPTS
    SECMSG_REMAINING_ATTEMPTS = last_attempts - 1
    
    decrypted_answer = AES(-256, k, answer)
    if decrypted_answer = SECMSG_REQUIRED_ANSWER then
        SECMSG_REMAINING_ATTEMPTS = SECMSG_FRESH_ATTEMPTS
        SECMSG_READY = 1
        SECMSG_SET_ANSWER = &HFF
        ' Set key and enable it
        Key(&H01) = Sha256Hash(SECMSG_CHALLENGE_SECRET)
        Enable Key &H01
    else
        SECMSG_READY = 0
        SECMSG_SET_ANSWER = SECMSG_REMAINING_ATTEMPTS
        Disable Key &H01
    end if
    SECMSG_CHALLENGE_SECRET = ""
    SECMSG_REQUIRED_ANSWER = ""
    
end function

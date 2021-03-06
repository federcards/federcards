#include SECMSG.common.bas


function SECMSG_IN_FORCE() as Byte
    ' if secmsg is already started
    if ALGORITHM <> 0 or KEYNUMBER <> 0 then
        SECMSG_IN_FORCE = 1
    else
        SECMSG_IN_FORCE = 0
    end if
end function

function SECMSG_DECRYPT_CHALLENGE(sharedsecret as string*SECMSG_SHAREDSECRET_LENGTH, challenge as string) as string
    private k as string
    k = Sha256Hash(sharedsecret)
    SECMSG_DECRYPT_CHALLENGE = AES(-256, k, challenge)
end function


function SECMSG_GENERATE_ANSWER(sharedsecret as string*SECMSG_SHAREDSECRET_LENGTH, challenge_secret as string) as string
    'This should be called from terminal only
    private k as string
    k = Sha256Hash(sharedsecret)
    SECMSG_GENERATE_ANSWER = AES(256, k, LEFT$(ShaHash(challenge_secret + "answer"), 16))
end function
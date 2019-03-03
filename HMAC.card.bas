' ******************************************************************************
' This file defines function
'  HMAC_SHA1(strKey, strMessage) as String
' which calculates a SHA1 based HMAC for given message.
' ******************************************************************************


const SHA1_BLOCK_SIZE = 64
const SHA1_OUTPUT_SIZE = 20


Sub BUFFER64_XOR_INTO(intSrcBuffer as Byte, intDstBuffer as Byte, byteWith as Byte)
    private i as Integer
    for i = 1 to SHA1_BLOCK_SIZE
        BUFFER64(intDstBuffer)(i) = chr$(asc(BUFFER64(intSrcBuffer)(i)) xor byteWith)
    next
End Sub


Function HMAC_SHA1(strKey as String, strMessage as String) as String
    private o_key_pad as string
    private i_key_pad as string
    
    if len(strKey) > SHA1_BLOCK_SIZE then
        Left$(BUFFER64(BUFFER64_HMAC_SHA1_KEY), SHA1_BLOCK_SIZE) = ShaHash(strKey)
    else
        Left$(BUFFER64(BUFFER64_HMAC_SHA1_KEY), SHA1_BLOCK_SIZE) = strKey
    end if
    
    call BUFFER64_XOR_INTO(BUFFER64_HMAC_SHA1_KEY, BUFFER64_HMAC_I_PAD, &H36)
    call BUFFER64_XOR_INTO(BUFFER64_HMAC_SHA1_KEY, BUFFER64_HMAC_O_PAD, &H5C)
    
    
    HMAC_SHA1 = ShaHash(BUFFER64(BUFFER64_HMAC_O_PAD) + ShaHash(BUFFER64(BUFFER64_HMAC_I_PAD) + strMessage))
End Function
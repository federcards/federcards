' ******************************************************************************
' RFC4226 HOTP: An HMAC-Based One-Time Password Algorithm
'
' Usage: HOTP(strSecret as String, intCounter as Long, 6) -> String
'
' strSecret must be bytes-based secret, not encoded in any format.
' ******************************************************************************




const HOTP_ALPHABET = "0123456789"


function HOTP_INT2STRING(intCounter as Long) as String*8
    private result as String
    do while intCounter <> 0
        result = chr$(intCounter and &HFF) + result
        intCounter = intCounter Shr 8
    loop
    Right$(HOTP_INT2STRING, len(result)) = result
end function


function HOTP(strSecret as String, intCounter as Long, intOutputLength as Byte) as String
    private result as String
    private strCounter as String 
    private strHash as String
    private longCode as Long
    private offset as Byte
    private a as Long, b as Long, c as Long, d as Long
    private i as Byte
    
    strCounter = HOTP_INT2STRING(intCounter)
    strHash = HMAC_SHA1(strSecret, strCounter)
    
    offset = (asc(strHash(SHA1_OUTPUT_SIZE)) and &H0F) + 1
    
    a = asc(strHash(offset)) and &H7F
    b = asc(strHash(offset+1)) and &HFF
    c = asc(strHash(offset+2)) and &HFF
    d = asc(strHash(offset+3)) and &HFF
    
    longCode = (a Shl 24) or (b Shl 16) or (c Shl 8) or d
    for i = 1 to intOutputLength
        HOTP = HOTP_ALPHABET((longCode mod 10) + 1) + HOTP
        longCode = longCode / 10
    next

end function
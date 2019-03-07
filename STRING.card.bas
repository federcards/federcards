const HEX_ALPHABET = "0123456789ABCDEF"

function dec2str(dec as integer) as string
    private x as byte
    do
        x = dec mod 10
        dec2str = chr$(48+x) + dec2str
        dec = dec / 10
    loop while dec
end function

function str2dec(strInput as string) as long
    ' decodes a positive(without leading +) decimal or 0
    ' returns -1 if not decodable!
    private i as integer
    private c as byte
    for i=len(strInput) to 1 step -1
        c = asc(strInput(i))
        if c < 48 or c > 57 then
            str2dec = -1
            exit function
        end if
        c = c - 48
        str2dec = str2dec * 10 + c
    next       
end function

function str2hex(ByVal strInput as String) as String
    private i as integer
    private c as byte
    for i = 1 to len(strInput)
        c = asc(strInput(i))
        Str2Hex = Str2Hex + HEX_ALPHABET(1+(c/16)) + HEX_ALPHABET(1+(c mod 16))
    next
end function

function _char2hex(byval c as string*1) as integer
    private x as byte
    x = asc(c)
    if x >= 48 and x <= 57 then
        _char2hex = x - 48
    else if x >= 65 and x <= 70 then
        _char2hex = x - 65
    else if x >= 97 and x <= 102 then
        _char2hex = x - 97
    else
        _char2hex = -1
    end if    
end function

function hex2str(byval hexInput as string) as String
    private i as byte
    private h as integer
    private l as integer
    
    if len(hexInput) mod 2 then
        hex2str = ""
        exit function
    end if
    
    for i = 1 to len(hexInput) step 2
        h = _char2hex(hexInput(i))
        l = _char2hex(hexInput(i+1))
        if h < 0 or l < 0 then
            hex2str = ""
            exit function
        end if
        hex2str = hex2str + chr$( ((h and &HF) Shl 4) + (l and &HF) )
    next
    
end function
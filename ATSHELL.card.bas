' This is the AT-command shell taking over the whole communication after secure
' messaging is started successfully. All inputs are called via API_AT command
' and redirected to the AT(data as string) function in this file.

const ATCOMMAND_ARGS_MAXCOUNT = 5

public ATCOMMAND_NAME as string
public ATCOMMAND_ARGS(ATCOMMAND_ARGS_MAXCOUNT) as string
public ATCOMMAND_ARGSCOUNT as byte = 0


sub ATCOMMAND_PARSE(src as string)
    ' Parse incoming ATCommand and put parsed result to public variables
    '  AT+CMDNAME=arg1,arg2,arg3,arg4,arg5
    '  AT+CMDNAME
    ATCOMMAND_NAME = ""
    ATCOMMAND_ARGSCOUNT = 0
    
    if Left$(src, 3) <> "AT+" then
        exit sub
    end if
    src = Mid$(src, 4)
    
    
    private i as integer
    private j as integer
    private k as integer
    
    for i=1 to len(src)
        if src(i) = "=" then
            exit for
        end if
    next
    ATCOMMAND_NAME = Left$(src, i-1)
    
    private argstr as string
    argstr = Mid$(src, i+1)
    i = 1
    k = 0
    if Right$(argstr, 1) <> "," then
        argstr = argstr + ","
    end if
    for j=1 to len(argstr)
        if argstr(j) = "," then
            k = k + 1
            ATCOMMAND_ARGS(k) = Mid$(argstr, i, j-i)
            i = j + 1
            if k >= ATCOMMAND_ARGS_MAXCOUNT then
                exit for
            end if
        end if
    next
    ATCOMMAND_ARGSCOUNT = k
    
    if ATCOMMAND_NAME = "" then
        ATCOMMAND_ARGSCOUNT = 0
        exit sub
    end if
    
    
    
    
    
    
end sub




function ATCOMMAND(data as string) as string  
    call ATCOMMAND_PARSE(data)
    if ATCOMMAND_NAME = "" then
        ATCOMMAND = "INVALID_COMMAND"
        exit function
    end if
    
    private i as byte
    ATCOMMAND = ATCOMMAND_NAME + "="
    for i=1 to ATCOMMAND_ARGSCOUNT
        ATCOMMAND = ATCOMMAND + ATCOMMAND_ARGS(i) + "|"
    next
end function
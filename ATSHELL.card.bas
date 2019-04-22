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
    private i as integer
    private j as integer
    private k as integer
    
    ATCOMMAND_NAME = ""
    ATCOMMAND_ARGSCOUNT = 0
    for i=1 to ATCOMMAND_ARGS_MAXCOUNT
        ATCOMMAND_ARGS(i) = ""
    next
    
    if Left$(src, 3) <> "AT+" then
        exit sub
    end if
    src = Mid$(src, 4)
    

    for i=1 to len(src)
        if src(i) = "=" then
            exit for
        end if
    next
    ATCOMMAND_NAME = Left$(src, i-1)
    
    if len(ATCOMMAND_NAME) > 16 then ' ATCOMMAND cannot be so long
        ATCOMMAND_NAME = ""
        exit sub
    end if
    
    for i=1 to len(ATCOMMAND_NAME) ' ensures ATCOMMAND_NAME must be alphabetic
        j = asc(ATCOMMAND_NAME(i))
        if j < 65 or j > 122 then
            ATCOMMAND_NAME = ""
            exit sub
        end if
    next
    
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
    private newid as byte
    private retstr as string

    call ATCOMMAND_PARSE(data)
    select case ATCOMMAND_NAME
        case "ATTEMPTS":
            ATCOMMAND = dec2str(E2PROM_DECRYPTION_ATTEMPTS_MAX - E2PROM_DECRYPTION_FAILURE_COUNTER)
    
        case "UNLOCK": ' unlock, verify password
            if E2PROM_UNLOCK(ATCOMMAND_ARGS(1)) then
                ATCOMMAND = "OK"
            else
                ATCOMMAND = E2PROM_ERROR_TEXT '"UNLOCK_FAILURE"
            end if
            
        case "STATUS": ' check lock status
            select case E2PROM_LOCKED()
                case 0:
                    ATCOMMAND = "UNLOCKED"
                case &HFF:
                    ATCOMMAND = "UNINITIALIZED"
                case else:
                    ATCOMMAND = "LOCKED"
            end select
            
        case "LOCK": ' lock
            call E2PROM_LOCK()
            ATCOMMAND = "OK"
            
        case "SETPWD": ' set password
            if E2PROM_SET_PASSWORD(ATCOMMAND_ARGS(1)) then
                ATCOMMAND = "OK"
            else
                ATCOMMAND = E2PROM_ERROR_TEXT '"SET_E2PROM_PASSWORD_FAILED"
            end if
            
        case "COUNT": ' count all entries
            ATCOMMAND = "+COUNT:" + dec2str(E2PROM_COUNT())
            
        case "NEXTMETA": ' read metadata of a record
            retstr = E2PROM_NEXTMETA()                
            if retstr = "" then
                ATCOMMAND = E2PROM_ERROR_TEXT
            else
                ATCOMMAND = "+NEXTMETA:" + retstr
            end if
            
        case "SETMETA":
            if E2PROM_SET_IDENTIFIER(str2dec(ATCOMMAND_ARGS(1)), ATCOMMAND_ARGS(2)) then
                ATCOMMAND = "OK"
            else
                ATCOMMAND = E2PROM_ERROR_TEXT
            end if
            
        case "GETDATA": ' read entry data
            retstr = E2PROM_GETDATA(str2dec(ATCOMMAND_ARGS(1)), ATCOMMAND_ARGS(2), ATCOMMAND_ARGS(3))
            if retstr = "" then
                ATCOMMAND = E2PROM_ERROR_TEXT
            else
                ATCOMMAND = "+GETDATA:" + retstr
            end if
            
        case "SETDATA": 'set entry data
            if E2PROM_SETDATA(str2dec(ATCOMMAND_ARGS(1)), ATCOMMAND_ARGS(2)) then
                ATCOMMAND = "OK"
            else
                ATCOMMAND = E2PROM_ERROR_TEXT
            end if
            
        case "ADDPWDENTRY":
            newid = E2PROM_ADD_ENTRY(E2PROM_ENTRY_PASSWORD)
            if newid = 0 then
                ATCOMMAND = E2PROM_ERROR_TEXT
            else
                ATCOMMAND = "+ADDPWDENTRY:" + dec2str(newid)
            end if
            
        case "ADDHOTPENTRY":
            newid = E2PROM_ADD_ENTRY(E2PROM_ENTRY_HOTP)
            if newid = 0 then
                ATCOMMAND = E2PROM_ERROR_TEXT
            else
                ATCOMMAND = "+ADDHOTPENTRY:" + dec2str(newid)
            end if
            
        case else:
            ATCOMMAND = "INVALID_COMMAND"
    end select
end function
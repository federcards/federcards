' ******************************************************************************
' E2PROM storage management
'
' ******************************************************************************

const E2PROM_STATUS_UNINITIALIZED = &H00
const E2PROM_STATUS_INITIALIZED = &HF0

const E2PROM_METADATA_IDENTIFIER_SIZE_LIMIT = 100
const E2PROM_ENTRY_SIZE_LIMIT = 100

const E2PROM_ENTRY_EMPTY = 0
const E2PROM_ENTRY_PASSWORD = 1
const E2PROM_ENTRY_HOTP = 2
const E2PROM_PASSWORD_MINLENGTH = 4

public E2PROM_ERROR_TEXT as string = ""
sub E2PROM_SETERROR(e as string)
    E2PROM_ERROR_TEXT = e
end sub




type E2PROM_TYPE_METADATA
    identifier as String*E2PROM_METADATA_IDENTIFIER_SIZE_LIMIT  'unencrypted identifier for human
    encrypted_key as String*(CRYPTO_OVERHEAD+32)                'decryption key, stored encrypted with main key
end type


Eeprom E2PROM_MAIN_KEY as String


' Following string contains, for each storage entry, a byte indicating which
' kind of data has been stored: empty, password, or HOTP secret.
Eeprom E2PROM_STORAGE_STATUS as String*STORAGE_ITEMS
' For each storage entry, an unencrypted identifier, as well as the key used for
' encryption, is stored in metadata array.
Eeprom E2PROM_METADATA(STORAGE_ITEMS) as E2PROM_TYPE_METADATA
' Actual storage, each item max. 224 bytes.
Eeprom E2PROM_DATA(STORAGE_ITEMS) as String


sub ERASE_ENTRY(byref dest as String, length as Integer)
    private i as byte
    for i =1 to 4
        dest = crypto_random_bytes(length)
    next
end sub 


sub E2PROM_DELETE(id as Integer)
    if id > STORAGE_ITEMS or id < 1 then
        exit sub
    end if
    call ERASE_ENTRY(E2PROM_METADATA(id).encrypted_key, 48)
    E2PROM_METADATA(id).identifier = ""
end sub


sub E2PROM_RESET()
    ' Clear the main key, mark all entry as deleted
    ' - This earses the main key first, which renders all entries undecryptable
    ' - After that, all entries are marked deleted.
    ' - However, unencrypted identifiers of entries are not erased, making it
    '   possible if an adversary can read out EEPROM.
    private i as integer
    private new_status as string*STORAGE_ITEMS
    call ERASE_ENTRY(E2PROM_MAIN_KEY, 64)
    E2PROM_MAIN_KEY = ""
    for i=1 to STORAGE_ITEMS
        new_status(i) = chr$(0)
    next
    E2PROM_STORAGE_STATUS = new_status    
end sub


function E2PROM_DERIVE_KEY_FROM_PASSWORD(password as string) as string
    E2PROM_DERIVE_KEY_FROM_PASSWORD = Sha256Hash(HMAC_SHA1("TODO: SET A SALT PER CARD", password))
end function


' **** Locking and unlocking main key ****
'
'  * Unlock a main key means the main key will be stored in RAM in cleartext.
'  * Only unlocked status allows access to storage, and changing password.
'  * Once only the unlocking procedure failed, encrypted storage will be
'    destroyed. The storage can be reused with setting a new password, however
'    old entries cannot be decrypted.


public E2PROM_MAIN_KEY_DECRYPTED as string


function E2PROM_LOCKED() as byte
    if E2PROM_MAIN_KEY_DECRYPTED = "" then
        if E2PROM_MAIN_KEY = "" then
            E2PROM_LOCKED = &HFF
        else
            E2PROM_LOCKED = 1
        end if
    else
        E2PROM_LOCKED = 0
    end if
end function


function strcpy(byref src as string) as string
    strcpy = Mid$(src, 1)
end function


function E2PROM_UNLOCK(password as string) as byte
    ' Try to verify password and decrypt main key.
    ' - Returns 0 if failed, where main key must have been destroyed, or
    ' - Returns 1 if success.
    
    private derived_password as string
    private temp_main_key as string
    
    E2PROM_UNLOCK = 0
    
    if not E2PROM_LOCKED() then 'if already unlocked
        call E2PROM_SETERROR("ALREADY_UNLOCKED")
        exit function
    end if
    
    if len(password) < E2PROM_PASSWORD_MINLENGTH then
        call E2PROM_SETERROR("PASSWORD_TOO_SHORT")
        exit function
    end if
    
    if E2PROM_MAIN_KEY = "" then
        ' if E2PROM has no main key, it needs to set one password first.
        call E2PROM_SETERROR("E2PROM_UNINITIALIZED")
        exit function
    end if
    
    temp_main_key = strcpy(E2PROM_MAIN_KEY)
    E2PROM_MAIN_KEY = crypto_random_bytes(64)
    
    derived_password = E2PROM_DERIVE_KEY_FROM_PASSWORD(password)
    E2PROM_MAIN_KEY_DECRYPTED = crypto_decrypt(derived_password, temp_main_key)
    
    if E2PROM_MAIN_KEY_DECRYPTED <> "" then
        ' Decryption success, write the main key back
        E2PROM_MAIN_KEY = temp_main_key
        E2PROM_UNLOCK = 1
    else
        ' Destroy E2PROM_MAIN_KEY
        call E2PROM_RESET()
        call E2PROM_SETERROR("E2PROM_UNINITIALIZED")
        E2PROM_UNLOCK = 0
    end if
end function


sub E2PROM_LOCK()
    E2PROM_MAIN_KEY_DECRYPTED = ""
end sub


function E2PROM_SET_PASSWORD(password as string) as byte
    private main_key_decrypted as string
    private new_password_derived as string
    if len(password) < E2PROM_PASSWORD_MINLENGTH then
        ' Reject too short password
        call E2PROM_SETERROR("PASSWORD_TOO_SHORT")
        E2PROM_SET_PASSWORD = 0
        exit function
    end if
    ' First, get the decrypted main key
    if not E2PROM_LOCKED() then
        ' ... when E2PROM is unlocked, read from RAM
        main_key_decrypted = E2PROM_MAIN_KEY_DECRYPTED
    else
        ' ... or when E2PROM is locked
        if E2PROM_MAIN_KEY = "" then
            ' only do set password when MAIN_KEY is empty(destroyed) before.
            main_key_decrypted = crypto_random32bytes()
        else
            call E2PROM_SETERROR("UNLOCK_REQUIRED")
            E2PROM_SET_PASSWORD = 0
            exit function
        end if
    end if
    
    new_password_derived = E2PROM_DERIVE_KEY_FROM_PASSWORD(password)
    E2PROM_MAIN_KEY = crypto_encrypt(new_password_derived, main_key_decrypted)
    E2PROM_SET_PASSWORD = 1
end function


function E2PROM_COUNT() as byte
    private i as byte
    for i = 1 to STORAGE_ITEMS
        if asc(E2PROM_STORAGE_STATUS(i)) <> 0 then
            E2PROM_COUNT = E2PROM_COUNT + 1
        end if
    next
end function

' **** Access to E2PROM stored entries ****
'
'  * E2PROM_SET_IDENTIFIER(index, newIdentifier)
'    Set the identifier of an existing entry. The identifier length must not
'    exceed E2PROM_METADATA_IDENTIFIER_SIZE_LIMIT, and entry with given index
'    must not be empty. If no errors found, return 1, otherwise 0.

function E2PROM_ADD_ENTRY(entry_type as byte) as byte
    ' Find an empty slot and set its type to entry_type.
    ' On error, return 0. Otherwise the index of this new entry is returned.
    private found as byte = 0
    E2PROM_ADD_ENTRY = 0
    
    if E2PROM_LOCKED() then
        call E2PROM_SETERROR("UNLOCK_REQUIRED")
        exit function
    end if   
    if entry_type <> E2PROM_ENTRY_PASSWORD and entry_type <> E2PROM_ENTRY_HOTP then
        call E2PROM_SETERROR("INVALID_ENTRY_TYPE")
        exit function
    end if
    
    for E2PROM_ADD_ENTRY = 1 to STORAGE_ITEMS
        if asc(E2PROM_STORAGE_STATUS(E2PROM_ADD_ENTRY)) = 0 then
            found = 1
            exit for
        end if
    next
    if not found then
        call E2PROM_SETERROR("STORAGE_FULL")
        E2PROM_ADD_ENTRY = 0
        exit function
    end if
    E2PROM_STORAGE_STATUS(E2PROM_ADD_ENTRY) = chr$(entry_type)
    E2PROM_METADATA(E2PROM_ADD_ENTRY).encrypted_key = crypto_encrypt(E2PROM_MAIN_KEY_DECRYPTED, crypto_random32bytes())
end function



function E2PROM_SET_IDENTIFIER(index as byte, newIdentifier as string) as byte
    E2PROM_SET_IDENTIFIER = 0
    if E2PROM_LOCKED() then
        call E2PROM_SETERROR("UNLOCK_REQUIRED") : exit function
    end if
    if len(newIdentifier) > E2PROM_METADATA_IDENTIFIER_SIZE_LIMIT then
        call E2PROM_SETERROR("INVALID_IDENTIFIER") : exit function
    end if
    if index > STORAGE_ITEMS then
        call E2PROM_SETERROR("INVALID_INDEX") : exit function
    end if
    if asc(E2PROM_STORAGE_STATUS(index)) = E2PROM_ENTRY_EMPTY then
        call E2PROM_SETERROR("INVALID_INDEX") : exit function
    end if
    E2PROM_METADATA(index).identifier = newIdentifier
    E2PROM_SET_IDENTIFIER = 1
end function

function E2PROM_GETMETA(index as byte) as string
    E2PROM_GETMETA = ""
    if index < 1 or index > STORAGE_ITEMS then
        call E2PROM_SETERROR("INVALID_INDEX"): exit function
    end if
    if asc(E2PROM_STORAGE_STATUS(index)) = E2PROM_ENTRY_EMPTY then
        call E2PROM_SETERROR("INVALID_INDEX") : exit function
    end if
    select case asc(E2PROM_STORAGE_STATUS(index))
        case E2PROM_ENTRY_HOTP:
            E2PROM_GETMETA = "HOTP,"
        case E2PROM_ENTRY_PASSWORD:
            E2PROM_GETMETA = "PWD,"
        case else:
            call E2PROM_SETERROR("INVALID_ENTRY") : exit function
    end select
    private idstr as string
    idstr = E2PROM_METADATA(index).identifier
    E2PROM_GETMETA = E2PROM_GETMETA + str2hex(idstr)

end function
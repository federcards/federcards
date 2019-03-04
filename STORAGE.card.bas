' ******************************************************************************
' E2PROM storage management
'
' ******************************************************************************

const E2PROM_STATUS_UNINITIALIZED = &H00
const E2PROM_STATUS_INITIALIZED = &HF0

const E2PROM_ENTRY_EMPTY = 0
const E2PROM_ENTRY_PASSWORD = 1
const E2PROM_ENTRY_HOTP = 2




type E2PROM_TYPE_METADATA
    identifier as String*128    'unencrypted identifier for human
    encrypted_key as String*48  'decryption key, stored encrypted with main key
end type


Eeprom E2PROM_MAIN_KEY as String


' Following string contains, for each storage entry, a byte indicating which
' kind of data has been stored: empty, password, or HOTP secret.
Eeprom E2PROM_STORAGE_STATUS as String*STORAGE_ITEMS
' For each storage entry, an unencrypted identifier, as well as the key used for
' encryption, is stored in metadata array.
Eeprom E2PROM_METADATA(STORAGE_ITEMS) as E2PROM_TYPE_METADATA
' Actual storage, each item max. 224 bytes.
Eeprom E2PROM_DATA(STORAGE_ITEMS) as String*224


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


function E2PROM_UNLOCKED() as byte
    if E2PROM_MAIN_KEY_DECRYPTED = "" then
        E2PROM_UNLOCKED = 1
    else
        E2PROM_UNLOCKED = 0
    end if
end function


function E2PROM_UNLOCK(password as string) as byte
    ' Try to verify password and decrypt main key.
    ' - Returns 0 if failed, where main key must have been destroyed, or
    ' - Returns 1 if success.
    
    private derived_password as string
    private temp_main_key as string
    
    if E2PROM_MAIN_KEY = "" then
        ' if E2PROM has no main key, it needs to set one password first.
        E2PROM_UNLOCK = 0
        exit function
    end if
    
    temp_main_key = E2PROM_MAIN_KEY
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
        E2PROM_UNLOCK = 0
    end if
end function


sub E2PROM_LOCK()
    E2PROM_MAIN_KEY_DECRYPTED = ""
end sub


function E2PROM_SET_PASSWORD(password as string) as byte
    private main_key_decrypted as string
    private new_password_derived as string
    ' First, get the decrypted main key
    if E2PROM_UNLOCKED() then
        ' ... when E2PROM is unlocked, read from RAM
        main_key_decrypted = E2PROM_MAIN_KEY_DECRYPTED
    else
        ' ... or when E2PROM is locked
        if E2PROM_MAIN_KEY = "" then
            ' only do set password when MAIN_KEY is empty(destroyed) before.
            main_key_decrypted = crypto_random32bytes()
        else
            E2PROM_SET_PASSWORD = 0
            exit function
        end if
    end if
    
    new_password_derived = E2PROM_DERIVE_KEY_FROM_PASSWORD(password)
    E2PROM_MAIN_KEY = crypto_encrypt(new_password_derived, main_key_decrypted)
    E2PROM_SET_PASSWORD = 1
end function
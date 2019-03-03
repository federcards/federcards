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


Eeprom E2PROM_MAIN_STATUS as Byte = E2PROM_STATUS_UNINITIALIZED
Eeprom E2PROM_MAIN_KEY as String*32


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
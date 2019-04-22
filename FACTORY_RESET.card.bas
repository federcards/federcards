sub FACTORY_RESET(new_deathpassword as string)
    call E2PROM_RESET(new_deathpassword)
end sub

' ******************************************************************************

Eeprom FACTORY_DONE as byte = &HFF

sub ONE_TIME_INITIALIZATION()
    call FACTORY_RESET("killme")
end sub

sub CALL_ONE_TIME_INITIALIZATION()
    if &HFF = FACTORY_DONE then
        call ONE_TIME_INITIALIZATION()
        FACTORY_DONE = &H00
    end if
end sub




sub FACTORY_RESET()
    call SECMSG_FACTORY_RESET()
end sub

' ******************************************************************************

Eeprom FACTORY_DONE as byte = &HFF

sub ONE_TIME_INITIALIZATION()
    call FACTORY_RESET()
end sub

sub CALL_ONE_TIME_INITIALIZATION()
    if &HFF = FACTORY_DONE then
        call ONE_TIME_INITIALIZATION()
        FACTORY_DONE = &H00
    end if
end sub




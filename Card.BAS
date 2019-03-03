Rem BasicCard Sample Source Code Template
Rem ------------------------------------------------------------------
Rem Copyright (C) 2008 ZeitControl GmbH
Rem You have a royalty-free right to use, modify, reproduce and 
Rem distribute the Sample Application Files (and/or any modified 
Rem version) in any way you find useful, provided that you agree 
Rem that ZeitControl GmbH has no warranty, obligations or liability
Rem for any Sample Application Files.
Rem ------------------------------------------------------------------
Option Explicit

#include Card.def



' Since no input data is required, LC is set to 0
Command &H88 &H00 API_CARD_STATUS(LC=0, Data as String)
    call CALL_ONE_TIME_INITIALIZATION()
    Data = chr$(SECMSG_STATUS())
End Command

Command &H88 &H02 API_GET_CHALLENGE(LC=0, Data as String)
    call CALL_ONE_TIME_INITIALIZATION()
    Data = SECMSG_GET_CHALLENGE()
End Command

Command &H88 &H04 API_SET_ANSWER(Data as String)
    private result as Byte
    result = SECMSG_SET_ANSWER(Data)
    Data = chr$(result)
End Command



Command &H88 &H08 API_RANDOM32BYTES(LC=0, Data as String)
    Data = crypto_random_bytes(32)
End Command

Command &H88 &H10 API_ENCRYPT_TEST(LC=0, Data as string)
    private k as string = "012345678901234567890123456789ab"
    'Data = crypto_encrypt(k, "this is a secret.")
    Data = crypto_decrypt(k, crypto_encrypt(k, "this is a secret."))
End Command
Public BUFFER64(4) as String*64


'Following constants are used to allocate BUFFER64 usages during calculation of
'HMACs
const BUFFER64_HMAC_SHA1_KEY = 1
const BUFFER64_HMAC_I_PAD = 2
const BUFFER64_HMAC_O_PAD = 3
const BUFFER64_RANDOM_POOL = 4



Sub BUFFER64_CLEAR()
    'TODO clear all buffers
End Sub
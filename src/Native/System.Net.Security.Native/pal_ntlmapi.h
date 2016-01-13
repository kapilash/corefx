// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <stddef.h>
#include <time.h>
#include <assert.h>
#include "pal_types.h"
#include "heimntlm.h"
#include "openssl/hmac.h"
#include "openssl/evp.h"


enum NtlmFlags : int32_t
{
    PAL_NTLMSSP_NEGOTIATE_UNICODE = 0x1,
    PAL_NTLMSSP_REQUEST_TARGET = 0x4,
    PAL_NTLMSSP_NEGOTIATE_SIGN = 0x10,
    PAL_NTLMSSP_NEGOTIATE_SEAL = 0x20,
    PAL_NTLMSSP_NEGOTIATE_NTLM = 0x200,
    PAL_NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x8000,
    PAL_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x80000,
    PAL_NTLMSSP_NEGOTIATE_128 = 0x20000000,
    PAL_NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000,
};

/*
Shims heim_ntlm_free_buf method.
*/
extern "C" void HeimNtlmFreeBuf(ntlm_buf* data);

/*
Shims heim_ntlm_encode_type1 method.
*/
extern "C" int32_t HeimNtlmEncodeType1(uint32_t flags, ntlm_buf* data);

/*
Shims heim_ntlm_decode_type2 method.
*/
extern "C" int32_t HeimNtlmDecodeType2(uint8_t* data, int32_t offset, int32_t count, ntlm_type2** type2);

/*
Shims heim_ntlm_free_type2 method.
*/
extern "C" void HeimNtlmFreeType2(ntlm_type2* type2);

/*
Shims heim_ntlm_nt_key method.
*/
extern "C" int32_t HeimNtlmNtKey(char* password, ntlm_buf* key);

/*
Shims heim_ntlm_calculate_lm2/_ntlm2 methods.
*/
extern "C" int32_t HeimNtlmCalculateResponse(bool isLM, uint8_t * key, size_t keylen, ntlm_type2* type2, char* username, char* target, uint8_t* baseSessionKey, int32_t baseSessionKeyLen,  ntlm_buf* data);

/*
Implements Type3 msg proccessing logic
*/
extern "C" int32_t CreateType3Message(uint8_t* key, size_t keylen, ntlm_type2* type2, char* username, char* domain, uint32_t flags, ntlm_buf* lmResponse, ntlm_buf* ntlmResponse, uint8_t* baseSessionKey, int32_t baseSessionKeyLen, ntlm_buf* sessionKey, ntlm_buf* data);

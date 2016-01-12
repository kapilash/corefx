// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include "pal_ntlmapi.h"

static_assert(PAL_NTLMSSP_NEGOTIATE_UNICODE == NTLM_NEG_UNICODE, "");
static_assert(PAL_NTLMSSP_REQUEST_TARGET == NTLM_NEG_TARGET, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_SIGN == NTLM_NEG_SIGN, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_SEAL == NTLM_NEG_SEAL, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_NTLM == NTLM_NEG_NTLM, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLM_NEG_ALWAYS_SIGN, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY == NTLM_NEG_NTLM2_SESSION, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_128 == NTLM_ENC_128, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_KEY_EXCH == NTLM_NEG_KEYEX, "");

extern "C" void HeimNtlmFreeBuf(ntlm_buf* data)
{
     heim_ntlm_free_buf(data);
}

extern "C" int32_t HeimNtlmEncodeType1(uint32_t flags, ntlm_buf* data)
{
   
    ntlm_type1 type1 = { 0 };
    type1.flags = flags;
    return heim_ntlm_encode_type1(&type1, data);
         
}

extern "C" int32_t HeimNtlmEncodeType3(ntlm_type3* type3, ntlm_buf* data, size_t* size)
{
    return heim_ntlm_encode_type3(type3, data, size);
}

extern "C" int32_t HeimNtlmDecodeType2(ntlm_buf* data, ntlm_type2* type2)
{
    return heim_ntlm_decode_type2(data, type2);
}

extern "C" void HeimNtlmFreeType2(ntlm_type2* type2)
{
    heim_ntlm_free_type2(type2);
}

extern "C" int32_t HeimNtlmCalculateLm2(const void * key , size_t len, const char* username, const char* target, ntlm_type2* type2, unsigned char* ntlmv2 , ntlm_buf * data)
{
    return heim_ntlm_calculate_lm2(key, len, username, target, type2->challenge, ntlmv2, data);
}

extern "C" int32_t HeimNtlmCalculateNtlm1(void * key , size_t len, ntlm_type2* type2, ntlm_buf* data, const char* username, const char* target, unsigned char* ntlmv2)
{
    if (type2->targetinfo.length == 0)
    {
        return heim_ntlm_calculate_ntlm1(key, len, type2->challenge, data);
    }
    else 
    {
        return heim_ntlm_calculate_ntlm2(key, len, username, target, type2->challenge, &type2->targetinfo, ntlmv2, data);
    }
    
}

extern "C" int32_t HeimNtlmCalculateNtlm2(const void * key, size_t len, const char* username, const char* target, ntlm_type2* type2, unsigned char* ntlmv2, ntlm_buf* data)
{
    return heim_ntlm_calculate_ntlm2(key, len, username, target, type2->challenge, &type2->targetinfo, ntlmv2, data);
}

extern "C" int32_t HeimNtlmBuildNtlm1Master(void * key, size_t size, ntlm_buf* session, ntlm_buf* master)
{
    return heim_ntlm_build_ntlm1_master(key, size, session, master);
}

extern "C" int32_t HeimNtlmBuildNtlm2Master(void * key, size_t size, ntlm_buf* blob, ntlm_buf* session, ntlm_buf* master)
{
    return heim_ntlm_build_ntlm2_master(key, size, blob, session, master);
}

extern "C" int32_t ProcessType3Message(char* username, char* domain, uint32_t flags, ntlm_buf* lm, ntlm_buf* ntlm, ntlm_type2* type2, void * key, size_t size, ntlm_buf* ntResponse, ntlm_buf* session, ntlm_buf* master, void * baseSessionKey, size_t baseSessionKeyLen, ntlm_buf* outputData)
{
        char* ws = nullptr;
        ntlm_type3 type3 = { 0 };
        type3.username = username;
        type3.targetname = domain;
        type3.lm = *lm;
        type3.ntlm = *ntlm;
        type3.ws = ws;
        type3.flags = flags;

        int32_t status = 0;

        if (type2->targetinfo.length == 0)
        {
            ntlm_buf* masterKey = (ntlm_buf *)malloc(sizeof(ntlm_buf));
            status = heim_ntlm_build_ntlm1_master(key, size, session, masterKey);
            heim_ntlm_free_buf(masterKey);
            heim_ntlm_free_buf(session);
            if (status != 0)
                return status;
        }
        else
        {
            // Only first 16 bytes of the NTLMv2 response should be passed
            ntlm_buf blob = { 0 };
            blob.length = 16;
            blob.data = ntResponse->data;
            status = HeimNtlmBuildNtlm2Master(baseSessionKey, baseSessionKeyLen, &blob, session, master);
            if (status != 0)
                return status;
        }

        type3.sessionkey = *master;
        size_t micOffset = 0;
        status = heim_ntlm_encode_type3(&type3, outputData, &micOffset);
        if (status != 0)
            return status;

        return 0;
     }

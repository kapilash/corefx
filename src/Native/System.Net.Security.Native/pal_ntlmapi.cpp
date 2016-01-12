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

extern "C" int32_t HeimNtlmDecodeType2(uint8_t* data, int32_t offset, int32_t count, ntlm_type2* type2)
{
    ntlm_buf buffer { static_cast<size_t>count, (data + offset) };
    return heim_ntlm_decode_type2(buffer, type2);
}

extern "C" void HeimNtlmFreeType2(ntlm_type2* type2)
{
    heim_ntlm_free_type2(type2);
}

extern "C" int32_t HeimNtlmCalculateLm2(uint8_t * key, size_t len, char* username, char* target, ntlm_type2* type2, uint8_t* ntlmv2, ntlm_buf* data);
{
    return heim_ntlm_calculate_lm2(key, len, username, target, type2->challenge, ntlmv2, data);
}

extern "C" int32_t HeimNtlmCalculateNtlm2(uint8_t * key, size_t len, ntlm_type2* type2, ntlm_buf* data, char* username, char* target, uint8_t* ntlmv2);
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

static uint8_t* HMACDigest(uint8_t* key, int keylen, uint8_t* input, int inputlen, uint8_t* prefix, int prefixlen)
{
    HMAC_CTX* ctx = new HMAC_CTX();
    uint8_t* output = new uint8_t[16];

    HMAC_CTX_init(ctx);
    HMAC_Init_ex(ctx, key, keylen, EVP_md5(), NULL);
    if (prefixlen > 0)
    {
        HMAC_Update(ctx, prefix, prefixlen);
    }
    HMAC_Update(ctx, input, inputlen);
    {
        uint hashLength;
        HMAC_Final(ref ctx, output, out hashLength);
    }
    HMAC_CTX_cleanup(ctx);
    delete ctx;
    return output;
}

static uint8_t* EVPEncryptOrDecrypt(bool encrypt, uint8_t* key, int keylen, uint8_t* input, int inputlen)
{
    EVP_CIPHER_CTX ctx = new EVP_CIPHER_CTX();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, NULL, encrypt ? 1 : 0);

    uint8_t* output = new uint8_t[inputlen];
    EVP_Cipher(ctx, output, input, output.Length);

    EVP_CIPHER_CTX_cleanup(ctx);
    delete ctx;

    return output;
}

static void heim_ntlm_build_ntlm2_masterx(uint8_t*key, size_t len, ntlm_buf* blob, ntlm_buf* session, ntlm_buf* master)
{
    uint8_t* keyPtr = HMACDigest(key, (int)len, blob->data, (int)blob->length, NULL, 0);
    {
        {
            // TODO: replace 16 with length from HMACDigest
            int status = heim_ntlm_build_ntlm1_master(keyPtr, (size_t) 16, session, master);
            HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_build_ntlm1_master failed",
                    status);
        }

        uint8_t* exportKey = EVPEncryptOrDecrypt(true, keyPtr, exchangeKey.Length, (uint8_t*)session.Value.ToPointer(), (int)session.Length);
        delete[] keyPtr;
        master->length = 16; // repalce with length from encrypt
        master->data = exportKey;
        // TODO: how to free exportKey
    }
}

extern "C" int32_t CreateType3Message(char* username, char* domain, uint32_t flags, ntlm_buf* lm, ntlm_buf* ntlm, ntlm_type2* type2, uint8_t* key, size_t size, ntlm_buf* session, uint8_t* baseSessionKey, size_t baseSessionKeyLen, ntlm_buf* outputData)
{
        ntlm_type3 type3 = { 0 };
        type3.username = username;
        type3.targetname = domain;
        type3.lm = *lm;
        type3.ntlm = *ntlm;
        type3.ws = ""; // needs to be non-empty
        type3.flags = flags;

        int32_t status = 0;
        ntlm_buf masterKey = { 0 };
        if (type2->targetinfo.length == 0)
        {
            status = heim_ntlm_build_ntlm1_master(key, size, session, &masterKey);
        }
        else
        {
            // Only first 16 uint8_ts of the NTLMv2 response should be passed
            // TODO: Add an assert to ensure length at least 16
            ntlm_buf blob = { 16, ntlm->data };
            status = heim_ntlm_build_ntlm2_masterx(baseSessionKey, baseSessionKeyLen, &blob, session, &masterKey);
        }

        heim_ntlm_free_buf(&masterKey);
        if (status != 0)
        {
            return status;
        }

        type3.sessionkey = *master;
        size_t micOffset = 0;
        status = heim_ntlm_encode_type3(&type3, outputData, &micOffset);
        return status;
 }

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pal_ntlmapi.h"
#include <stddef.h>
#include <assert.h>
#include "pal_types.h"
#include "openssl/hmac.h"
#include "openssl/evp.h"
#include "pal_utilities.h"

static_assert(PAL_NTLMSSP_NEGOTIATE_UNICODE == NTLM_NEG_UNICODE, "");
static_assert(PAL_NTLMSSP_REQUEST_TARGET == NTLM_NEG_TARGET, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_SIGN == NTLM_NEG_SIGN, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_SEAL == NTLM_NEG_SEAL, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_NTLM == NTLM_NEG_NTLM, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLM_NEG_ALWAYS_SIGN, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY == NTLM_NEG_NTLM2_SESSION, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_128 == NTLM_ENC_128, "");
static_assert(PAL_NTLMSSP_NEGOTIATE_KEY_EXCH == NTLM_NEG_KEYEX, "");

const int32_t MD5_DIGEST_LENGTH = 16;

extern "C" void NetSecurity_HeimNtlmFreeBuf(ntlm_buf* data)
{
    assert(data != nullptr);
    heim_ntlm_free_buf(data);
}

extern "C" int32_t NetSecurity_HeimNtlmEncodeType1(uint32_t flags, ntlm_buf* data)
{
    assert(data != nullptr);
    ntlm_type1 type1;
    memset(&type1, 0, sizeof(ntlm_type1));
    type1.flags = flags;
    return heim_ntlm_encode_type1(&type1, data);
}

extern "C" int32_t NetSecurity_HeimNtlmDecodeType2(uint8_t* data, int32_t offset, int32_t count, ntlm_type2** type2)
{
    assert(data != nullptr);
    assert(offset >= 0);
    assert(type2 != nullptr);
    ntlm_buf buffer { .length = UnsignedCast(count), .data = data + offset };
    *type2 = new ntlm_type2();
    int32_t stat= heim_ntlm_decode_type2(&buffer, *type2);
    return stat;
}

extern "C" void NetSecurity_HeimNtlmFreeType2(ntlm_type2* type2)
{
    assert (type2 != nullptr);
    heim_ntlm_free_type2(type2);
    delete type2;
}

extern "C" int32_t NetSecurity_HeimNtlmNtKey(const char* password, ntlm_buf* key)
{
    return heim_ntlm_nt_key(password, key);
}

extern "C" int32_t NetSecurity_HeimNtlmCalculateResponse(int32_t isLM, ntlm_buf* key, ntlm_type2* type2, char* username, char* target, uint8_t* baseSessionKey, int32_t baseSessionKeyLen,  ntlm_buf* data)
{
    assert(baseSessionKeyLen == MD5_DIGEST_LENGTH);
    assert(isLM == 0 || isLM == 1);
    assert(type2 != nullptr);
    assert(key != nullptr);
    if (isLM)
    {
        return heim_ntlm_calculate_lm2(key->data, key->length, username, target, type2->challenge, baseSessionKey, data);
    }
    else
    {
        if (type2->targetinfo.length == 0)
        {
            return heim_ntlm_calculate_ntlm1(key->data, key->length, type2->challenge, data);
        }
        else 
        {
            return heim_ntlm_calculate_ntlm2(key->data, key->length, username, target, type2->challenge, &type2->targetinfo, baseSessionKey, data);
        }
    }
}

static uint8_t* NetSecurity_HMACDigest(uint8_t* key, int32_t keylen, void* input, size_t inputlen)
{
    HMAC_CTX ctx;
    uint8_t* output = new uint8_t[16];

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, keylen, EVP_md5(), nullptr);
    HMAC_Update(&ctx, static_cast<uint8_t*>(input), inputlen);
    uint32_t hashLength;
    HMAC_Final(&ctx, output, &hashLength);
    HMAC_CTX_cleanup(&ctx);
    return output;
}

static uint8_t* NetSecurity_EVPEncrypt(uint8_t* key, void* input, size_t inputlen)
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_rc4(), nullptr, key, nullptr, 1);

    uint8_t* output = new uint8_t[inputlen];
    EVP_Cipher(&ctx, output, static_cast<uint8_t*>(input), static_cast<uint32_t>(inputlen));

    EVP_CIPHER_CTX_cleanup(&ctx);
    return output;
}

static int32_t NetSecurity_build_ntlm2_masterx(uint8_t* key, int32_t keylen, ntlm_buf* blob, ntlm_buf* sessionKey, ntlm_buf* masterKey)
{
    uint8_t* ntlmv2hash = NetSecurity_HMACDigest(key, keylen, blob->data, blob->length);
    int32_t status = heim_ntlm_build_ntlm1_master(ntlmv2hash, UnsignedCast(keylen), sessionKey, masterKey);
    if (status)
    {
        delete[] ntlmv2hash;
        return status;
    }

    uint8_t* exportKey = NetSecurity_EVPEncrypt(ntlmv2hash, sessionKey->data, sessionKey->length);
    delete[] ntlmv2hash;
    masterKey->length = sessionKey->length;
    masterKey->data = exportKey;
    return status;
}

extern "C" int32_t NetSecurity_CreateType3Message(ntlm_buf* key, ntlm_type2* type2, char* username, char* domain, uint32_t flags, ntlm_buf* lmResponse, ntlm_buf* ntlmResponse, uint8_t* baseSessionKey, int32_t baseSessionKeyLen, ntlm_buf* sessionKey, ntlm_buf* data)
{
    assert(key != nullptr);
    assert(type2 != nullptr);
    assert(lmResponse != nullptr);
    assert(ntlmResponse != nullptr);
    static char* workstation = static_cast<char*>(calloc(1, sizeof(char))); // empty string
    ntlm_type3 type3;
    memset(&type3, 0, sizeof(ntlm_type3));
    type3.username = username;
    type3.targetname = domain;
    type3.lm = *lmResponse;
    type3.ntlm = *ntlmResponse;
    type3.ws = workstation;
    type3.flags = flags;

    int32_t status = 0;
    ntlm_buf masterKey = { .length = 0, .data = nullptr };

    if (type2->targetinfo.length == 0)
    {
        status = heim_ntlm_build_ntlm1_master(key->data, key->length, sessionKey, &masterKey);
    }
    else
    {
        // Only first 16 bytes of the NTLMv2 response should be passed
        assert(ntlmResponse->length >= MD5_DIGEST_LENGTH);
        ntlm_buf blob = { .length = MD5_DIGEST_LENGTH, .data = ntlmResponse->data };
        status = NetSecurity_build_ntlm2_masterx(baseSessionKey, baseSessionKeyLen, &blob, sessionKey, &masterKey);
        if (status != 0)
        {
            heim_ntlm_free_buf(sessionKey);
        }
    }

    if (status != 0)
    {
        return status;
    }

    type3.sessionkey = masterKey;
    status = heim_ntlm_encode_type3(&type3, data);
    if (status != 0)
    {
        heim_ntlm_free_buf(sessionKey);
    }

    if (type2->targetinfo.length == 0)
    {
        heim_ntlm_free_buf(&masterKey);
    }
    else
    {
        // in case of v2, masterKey.data is created by NetSecurity_build_ntlm2_masterx function and free_buf cannot be called.
        delete[] static_cast<uint8_t*>(masterKey.data);
    }
    return status;
 }

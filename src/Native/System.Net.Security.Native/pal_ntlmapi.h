// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <stddef.h>
#include <time.h>
#include "pal_types.h"
#include "heimdal/heimntlm.h"


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
Shims heim_ntlm_encode_type3 method.
*/
extern "C" int32_t HeimNtlmEncodeType3(ntlm_type3* type3, ntlm_buf* data, size_t* size);

/*
Shims heim_ntlm_decode_type2 method.
*/
extern "C" int32_t HeimNtlmDecodeType2(ntlm_buf* data, ntlm_type2* type2);

/*
Shims heim_ntlm_free_type2 method.
*/
extern "C" void HeimNtlmFreeType2(ntlm_type2* type2);

/*
Shims heim_ntlm_calculate_lm2 method.
*/
extern "C" int32_t HeimNtlmCalculateLm2(const void * key, size_t len, const char* username, const char* target, ntlm_type2* type2, unsigned char* ntlmv2, ntlm_buf * data);

/*
Shims heim_ntlm_calculate_ntlm1 method.
*/
extern "C" int32_t HeimNtlmCalculateNtlm1(void * key, size_t len, ntlm_type2* type2, ntlm_buf* data, const char* username, const char* target, unsigned char* ntlmv2);

/*
Shims the heim_ntlm_calculate_ntlm2 method.
*/
extern "C" int32_t HeimNtlmCalculateNtlm2(const void * key, size_t len, const char* username, const char* target, ntlm_type2* type2, unsigned char* ntlmv2, ntlm_buf* data);

/*
Shims heim_ntlm_build_ntlm1_master method.
*/
extern "C" int32_t HeimNtlmBuildNtlm1Master(void * key, size_t size, ntlm_buf* session, ntlm_buf* master);

/*
Shims heim_ntlm_build_ntlm2_master method.
*/
extern "C" int32_t HeimNtlmBuildNtlm2Master(void * key, size_t size, ntlm_buf* blob, ntlm_buf* session, ntlm_buf* master);

/*
Implements Typ3 msg proccessing logic
*/
extern "C" int32_t ProcessType3Message(char* username, char* domain, uint32_t flags, ntlm_buf* lm, ntlm_buf* ntlm, ntlm_type2* type2, void * key, size_t size, ntlm_buf* ntResponse, ntlm_buf* session, ntlm_buf* master, void * baseSessionKey, size_t baseSessionKeyLen, ntlm_buf* outputData);

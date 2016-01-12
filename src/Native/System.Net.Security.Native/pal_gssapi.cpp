// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "pal_gssapi.h"
#include <assert.h>
#include <string.h>

static_assert(PAL_GSS_COMPLETE == GSS_S_COMPLETE, "");
static_assert(PAL_GSS_CONTINUE_NEEDED == GSS_S_CONTINUE_NEEDED, "");

static char gss_mech_value[] = "\x2b\x06\x01\x05\x05\x02";

static gss_OID_desc gss_mech_spnego_OID_desc = { 6, static_cast<void*>(gss_mech_value) };

static gss_OID gss_mech_spnego_OID = &gss_mech_spnego_OID_desc;

static gss_OID_set_desc gss_mech_spnego_OID_set_desc = { 1, &gss_mech_spnego_OID_desc };

static gss_OID_set gss_mech_spnego_OID_set = &gss_mech_spnego_OID_set_desc;

extern "C" uint32_t GssAcceptSecContext(uint32_t* minorStatus, gss_ctx_id_t* contextHandle, gss_cred_id_t acceptorCredHandle,
    gss_buffer_t inputToken, gss_buffer_t outputToken, uint32_t* retFlags)
{
    return gss_accept_sec_context(minorStatus, contextHandle, acceptorCredHandle, inputToken, 0, NULL, NULL, outputToken, retFlags, NULL, NULL);
}

extern "C" uint32_t GssAcquireCredSpNego(uint32_t* minorStatus, gss_name_t desiredName, bool isInitiate, gss_cred_id_t* outputCredHandle)
{
    gss_cred_usage_t credUsage = isInitiate ? GSS_C_INITIATE : GSS_C_ACCEPT;
    return gss_acquire_cred(minorStatus, desiredName, 0, gss_mech_spnego_OID_set, credUsage, outputCredHandle, NULL, NULL);
}

extern "C" uint32_t GssDeleteSecContext(uint32_t* minorStatus, gss_ctx_id_t* contextHandle)
{
    return gss_delete_sec_context(minorStatus, contextHandle, 0);
}

extern "C" uint32_t GssDisplayName(uint32_t* minorStatus, gss_name_t inputName, gss_buffer_t outputNameBuffer)
{
    return gss_display_name(minorStatus, inputName, outputNameBuffer, NULL);
}

extern "C" uint32_t GssDisplayStatus(uint32_t* minorStatus, uint32_t statusValue, bool isGssMechCode, gss_buffer_t statusString)
{
    int statusType = isGssMechCode ? GSS_C_MECH_CODE : GSS_C_GSS_CODE;
    return gss_display_status(minorStatus, statusValue, statusType, 0, NULL, statusString);
}

extern "C" uint32_t GssImportNtUserName(uint32_t* minorStatus, char* inputName, gss_name_t* outputName)
{
    gss_buffer_desc inputNameBuffer {strlen(inputName), inputName};
    gss_OID nameType = isUser ? const_cast<gss_OID>(GSS_C_NT_USER_NAME) : const_cast<gss_OID>(GSS_KRB5_NT_PRINCIPAL_NAME);
    return gss_import_name(minorStatus, &inputNameBuffer, nameType, outputName);
}

extern "C" uint32_t GssInitSecContextSpNego(uint32_t* minorStatus, gss_cred_id_t claimantCredHandle, gss_ctx_id_t* contextHandle,
    gss_name_t targetName, uint32_t reqFlags, gss_buffer_t inputToken, gss_buffer_t outputToken, uint32_t* retFlags)
{
    return gss_init_sec_context(minorStatus, claimantCredHandle, contextHandle, targetName, gss_mech_spnego_OID, reqFlags,
        0, 0, inputToken, NULL, outputToken, retFlags, NULL);
}

extern "C" uint32_t GssInquireSourceName(uint32_t* minorStatus, gss_ctx_id_t contextHandle, gss_name_t* srcName)
{
    return gss_inquire_context(minorStatus, contextHandle, srcName, NULL, NULL, NULL, NULL, NULL, NULL);
}

extern "C" uint32_t GssReleaseCred(uint32_t* minorStatus, gss_cred_id_t* credHandle)
{
    return gss_release_cred(minorStatus, credHandle);
}

extern "C" uint32_t GssReleaseBuffer(uint32_t* minor_status, gss_buffer_t buffer)
{
    return gss_release_buffer(minor_status, buffer);
}

extern "C" uint32_t GssReleaseName(uint32_t* minorStatus, gss_name_t* inputName)
{
    return gss_release_name(minorStatus, inputName);
}

extern "C" uint32_t GssWrap(uint32_t* minorStatus, gss_ctx_id_t contextHandle, bool isEncrypt, gss_buffer_t inputMessageBuffer,
    gss_buffer_t outputMessageBuffer)
{
    int confState;
    int confReqFlag = isEncrypt ? 1 : 0;
    uint32_t retVal = gss_wrap(minorStatus, contextHandle, confReqFlag, GSS_C_QOP_DEFAULT, inputMessageBuffer, &confState, outputMessageBuffer);
    assert((confState == 0) == (confReqFlag == 0));
    return retVal;
}

extern "C" uint32_t GssUnwrap(uint32_t* minorStatus, gss_ctx_id_t contextHandle, gss_buffer_t inputMessageBuffer,
    gss_buffer_t outputMessageBuffer)
{
    return gss_unwrap(minorStatus, contextHandle, inputMessageBuffer, outputMessageBuffer, NULL, NULL);
}

extern "C" uint32_t GssAcquireCredWithPasswordSpNego(uint32_t* minorStatus, const gss_name_t desiredName, char* password, bool isInitiate,
    gss_cred_id_t* outputCredHandle)
{
    gss_cred_usage_t credUsage = isInitiate ? GSS_C_INITIATE : GSS_C_ACCEPT;
    gss_buffer_desc passwordBuffer{ strlen(password), password };
    return gss_acquire_cred_with_password(minorStatus, desiredName, &passwordBuffer, 0, gss_mech_spnego_OID_set,
        credUsage, outputCredHandle, NULL, NULL);
}


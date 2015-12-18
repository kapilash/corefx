// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#include "pal_types.h"

#ifdef  GSSFW
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi_ext.h>
#endif


enum GssStatus : uint32_t
{
    PAL_GSS_COMPLETE = 0,
    PAL_GSS_CONTINUE_NEEDED = 1
};

/*
Shims the gss_release_buffer method.
*/
extern "C" uint32_t GssReleaseBuffer(uint32_t* minor_status, gss_buffer_t buffer);

/*
Shims the gss_display_status method.
*/
extern "C" uint32_t GssDisplayStatus(uint32_t* minorStatus, uint32_t statusValue, bool isGssMechCode, gss_buffer_t statusString);

/*
Shims the gss_display_name method.
*/
extern "C" uint32_t GssDisplayName(uint32_t* minorStatus, gss_name_t inputName, gss_buffer_t outputNameBuffer);

/*
Shims the gss_import_name method.
This method will import NT type usernames only.
*/
extern "C" uint32_t GssImportNtUserName(uint32_t* minorStatus, char* inputName, gss_name_t* outputName);

/*
Shims the gss_release_name method.
*/
extern "C" uint32_t GssReleaseName(uint32_t* minorStatus, gss_name_t* inputName);

/*
Shims the gss_acquire_cred method with SPNEGO oids.
*/
extern "C" uint32_t GssAcquireCredSpNego(uint32_t* minorStatus, gss_name_t desiredName, bool isInitiate, gss_cred_id_t* outputCredHandle);

/*
Shims the gss_release_cred method.
*/
extern "C" uint32_t GssReleaseCred(uint32_t* minorStatus, gss_cred_id_t* credHandle);

/*
Shims the gss_init_sec_context method with SPNEGO oids.
*/
extern "C" uint32_t GssInitSecContextSpNego(uint32_t* minorStatus, gss_cred_id_t claimantCredHandle, gss_ctx_id_t* contextHandle,
                                            gss_name_t targetName, uint32_t reqFlags, gss_buffer_t inputToken, gss_buffer_t outputToken, uint32_t* retFlags);

/*
Shims the gss_accept_sec_context method.
*/
extern "C" uint32_t GssAcceptSecContext(uint32_t* minorStatus, gss_ctx_id_t* contextHandle, gss_cred_id_t acceptorCredHandle,
                                        gss_buffer_t inputToken, gss_buffer_t outputToken, uint32_t* retFlags);

/*
Shims the gss_delete_sec_context method.
*/
extern "C" uint32_t GssDeleteSecContext(uint32_t* minorStatus, gss_ctx_id_t* contextHandle);

/*
Shims the gss_wrap method.
*/
extern "C" uint32_t GssWrap(uint32_t* minorStatus, gss_ctx_id_t contextHandle, bool isEncrypt, gss_buffer_t inputMessageBuffer,
                            gss_buffer_t outputMessageBuffer);

/*
Shims the gss_unwrap method.
*/
extern "C" uint32_t GssUnwrap(uint32_t* minorStatus, gss_ctx_id_t contextHandle, gss_buffer_t inputMessageBuffer,
                              gss_buffer_t outputMessageBuffer);

/*
Shims the gss_inquire_context method.
*/
extern "C" uint32_t GssInquireSourceName(uint32_t* minorStatus, gss_ctx_id_t contextHandle, gss_name_t* srcName);


/*
Shims the gss_acquire_cred_with_password method.
*/
extern "C" uint32_t GssAcquireCredWithPasswordSpNego(uint32_t* minorStatus, const gss_name_t desiredName, char* password, bool isInitiate,
                                                     gss_cred_id_t* outputCredHandle);

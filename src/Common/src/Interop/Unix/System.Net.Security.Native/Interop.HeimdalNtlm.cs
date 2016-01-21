// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static class HeimdalNtlm
    {
        internal static byte[] CreateNegotiateMessage(uint flags)
        {
            using (SafeNtlmBufferHandle data = new SafeNtlmBufferHandle())
            {
                int status = NetSecurity.HeimNtlmEncodeType1(flags, data);
                NetSecurity.HeimdalNtlmException.AssertOrThrowIfError("HeimNtlmEncodeType1 failed", status);

                byte[] outputBuffer = new byte[(int)data.Length]; // Always return non-null
                if (outputBuffer.Length > 0)
                {
                    Marshal.Copy(data.Value, outputBuffer, 0, outputBuffer.Length);
                }

                return outputBuffer;
            }
        }

        internal static byte[] CreateAuthenticateMessage(uint flags, string username, string password, string domain,
            byte[] type2Data, int offset, int count, out SafeNtlmBufferHandle sessionKey)
        {
            using (SafeNtlmType3Handle challengeMessage = new SafeNtlmType3Handle(type2Data, offset, count))
            {
                using (
                        SafeNtlmBufferHandle outputData = challengeMessage.GetResponse(flags, username, password, domain,
                            out sessionKey))
                {
                    byte[] outputBuffer = new byte[(int) outputData.Length]; // Always return non-null
                    if (outputBuffer.Length > 0)
                    {
                        Marshal.Copy(outputData.Value, outputBuffer, 0, outputBuffer.Length);
                    }
                    return outputBuffer;
                }
            }
        }

        internal static void CreateKeys(SafeNtlmBufferHandle sessionKey, out SafeNtlmKeyHandle serverSignKey, out SafeNtlmKeyHandle serverSealKey, out SafeNtlmKeyHandle clientSignKey, out SafeNtlmKeyHandle clientSealKey)
        {
            serverSignKey = new SafeNtlmKeyHandle(sessionKey, false, false);
            serverSealKey = new SafeNtlmKeyHandle(sessionKey, false, true);
            clientSignKey = new SafeNtlmKeyHandle(sessionKey, true, false);
            clientSealKey = new SafeNtlmKeyHandle(sessionKey, true, true);
        }
    }
}


// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Net
{
    // Depending on PAL refactoring, this will either be part of a class that implements
    // SSPIInterfaceNego or Unix-specific files (eg. _NTAuthenticationPal.Unix.cs) will 
    // call into methods of this class
    internal static class NegotiateStreamPal
    {
        public static SecurityStatusPal AcquireCredentialsHandle(
            string moduleName,
            bool isInBoundCred,
            string username,
            string password,
            string domain,
            out SafeHandle outCredential)
        {
                MockUtils.MockLogging.PrintInfo("vijayko", "Enterd ACQUIRECRED " + moduleName + " " + username + " " + password + " " + domain);
            if (isInBoundCred || string.IsNullOrEmpty(username))
            {
                throw new ArgumentException();
            }
            else if (string.Equals(moduleName, "NTLM"))
            {
                outCredential = new SafeFreeNtlmCredentials(username, password, domain);
            }
            else
            {
                throw new ArgumentException();
            }
            return SecurityStatusPal.OK;
        }

        public static SecurityStatusPal AcquireDefaultCredential(string moduleName, bool isInBoundCred, out SafeHandle outCredential)
        {
            return AcquireCredentialsHandle(moduleName, isInBoundCred, string.Empty, string.Empty, string.Empty, out outCredential);
        }

        public static SecurityStatusPal InitializeSecurityContext(
            SafeHandle credential,
            ref SafeHandle context,
            string targetName,
            uint inFlags,
            uint endianNess,
            SecurityBuffer[] inputBuffers,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            // TODO (Issue #3718): The second buffer can contain a channel binding which is not yet supported
            if (inputBuffers.Length > 1)
            {
                throw new NotImplementedException("No support for channel binding on non-Windows");
            }

            if (IsNtlmClient(targetName, credential))
            {
                return InitializeNtlmSecurityContext((SafeFreeNtlmCredentials)credential, ref context, inFlags, inputBuffers[0], outputBuffer);
            }
            throw new NotImplementedException("No support for channel binding on non-Windows");
        }

        public static int Encrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            byte[] cipher = context.EncryptOrDecrypt(true, buffer, offset, count);
            byte[] signature = context.MakeSignature(true, buffer, offset, count);
            output = new byte[cipher.Length + signature.Length];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(cipher, 0, output, signature.Length, cipher.Length);
            return output.Length;
        }

        public static int Decrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            byte[] message = context.EncryptOrDecrypt(false, buffer, (offset + 16), (count - 16));
            Array.Copy(message, 0, buffer, (offset + 16), message.Length);
            return VerifySignature(securityContext, buffer, offset, count, out newOffset, sequenceNumber);
        }

        public static int MakeSignature(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeSignature(true, buffer, offset, count);
            output = new byte[signature.Length + count];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(buffer, offset, output, signature.Length, count);
            return output.Length;
        }

        public static int VerifySignature(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
            newOffset = offset + 16;
            count -= 16;
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeSignature(false, buffer, newOffset, count);
            for (int i = 0; i < signature.Length; i++)
            {
                if (buffer[offset + i] != signature[i]) throw new Exception("Invalid signature");
            }
            return count;
        }

        public static object QueryContextAttributes(object context, uint attribute, out SecurityStatusPal errorCode)
        {
            errorCode = SecurityStatusPal.OK;
            return null;
        }

        private static bool IsNtlmClient(string targetName, SafeHandle credential)
        {
            return string.IsNullOrEmpty(targetName) || (credential is SafeFreeNtlmCredentials);
        }

        private static SecurityStatusPal InitializeNtlmSecurityContext(
            SafeFreeNtlmCredentials credential,
            ref SafeHandle context,
            uint inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer)
        {
            SecurityStatusPal retVal;

            if (null == context)
            {
                context = new SafeDeleteNtlmContext(credential, inFlags);
                outputBuffer.token = Interop.HeimdalNtlm.CreateNegotiateMessage(inFlags);
                MockUtils.MockLogging.PrintInfo("vijayko", "Returned from CreateNEgo " + outputBuffer.token.Length);
                retVal = SecurityStatusPal.ContinueNeeded;
            }
            else
            {
                uint flags = ((SafeDeleteNtlmContext)context).Flags;
                byte[] sessionKey;
                outputBuffer.token = Interop.HeimdalNtlm.CreateAuthenticateMessage(flags, credential.UserName,
                    credential.Password, credential.Domain, inputBuffer.token, inputBuffer.offset, inputBuffer.size, out sessionKey);
                ((SafeDeleteNtlmContext)context).SetKeys(sessionKey);
                retVal = SecurityStatusPal.OK;
            }
            outputBuffer.size = outputBuffer.token.Length;
            return retVal;
        }

    }   
}


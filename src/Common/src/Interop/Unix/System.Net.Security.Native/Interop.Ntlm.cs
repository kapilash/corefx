// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class NetSecurity
    {
        public const int MD5DigestLength = 16;
        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmFreeBuf(ref ntlm_buf data);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmEncodeType1(uint flags, SafeNtlmBufferHandle data);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmDecodeType2(byte[] data, int offset, int count, out SafeNtlmType2Handle type2Handle);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmFreeType2(IntPtr type2Handle);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern int HeimNtlmNtKey(string password, SafeNtlmBufferHandle key);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern int HeimNtlmCalculateResponse(
            bool isLM,
            IntPtr key,
            size_t keylen,
            SafeNtlmType2Handle type2Handle,
            string username,
            string target,
            byte[] baseSessionKey,
            int baseSessionKeyLen,
            SafeNtlmBufferHandle answer);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern int CreateType3Message(
            IntPtr key,
            size_t keylen,
            SafeNtlmType2Handle type2Handle,
            string username,
            string domain,
            uint flags,
            SafeNtlmBufferHandle lmResponse,
            SafeNtlmBufferHandle ntlmResponse,
            byte [] baseSessionKey,
            int baseSessionKeyLen,
            SafeNtlmBufferHandle sessionKey,
            SafeNtlmBufferHandle data
            );

        internal partial class NtlmFlags
        {
            internal const uint NTLMSSP_NEGOTIATE_UNICODE = 0x1;
            internal const uint NTLMSSP_REQUEST_TARGET = 0x4;
            internal const uint NTLMSSP_NEGOTIATE_SIGN = 0x10;
            internal const uint NTLMSSP_NEGOTIATE_SEAL = 0x20;
            internal const uint NTLMSSP_NEGOTIATE_NTLM = 0x200;
            internal const uint NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x8000;
            internal const uint NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x80000;
            internal const uint NTLMSSP_NEGOTIATE_128 = 0x20000000;
            internal const uint NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ntlm_buf
        {
            internal size_t length;
            internal IntPtr data;
        }
        
        internal static byte[] EVPDigest(SafeNtlmBufferHandle key, byte[] input, int inputlen, out uint outputlen)
        {
            byte[] output = new byte[Interop.Crypto.EVP_MAX_MD_SIZE];
            outputlen = 0;
            using (SafeEvpMdCtxHandle ctx = Interop.Crypto.EvpMdCtxCreate(Interop.Crypto.EvpMd5()))
            unsafe {
                Check(Interop.Crypto.EvpDigestUpdate(ctx, (byte*)key.Value.ToPointer(), key.Length));
                fixed (byte* inPtr = input)
                {
                    Check(Interop.Crypto.EvpDigestUpdate(ctx, inPtr, inputlen));
                }
                fixed (byte* outPtr = output)
                {
                    Check(Interop.Crypto.EvpDigestFinalEx(ctx, outPtr, ref outputlen));
                }
            }
            return output;
        }

        internal static unsafe byte[] HMACDigest(byte* key, int keylen, byte* input, int inputlen, byte* prefix, int prefixlen)
        {
            
            byte[] output = new byte[Interop.Crypto.EVP_MAX_MD_SIZE];
            using (SafeHmacCtxHandle ctx = Interop.Crypto.HmacCreate(key, keylen, Interop.Crypto.EvpMd5()))
            {
                if (prefixlen > 0)
                {
                    Check(Interop.Crypto.HmacUpdate(ctx, prefix, prefixlen));
                }
                Check(Interop.Crypto.HmacUpdate(ctx, input, inputlen));
                fixed (byte* hashPtr = output)
                {
                    int hashLength = 0;
                    Check(Interop.Crypto.HmacFinal(ctx, hashPtr, ref hashLength));
                }
            }
            return output;
        }

        private static void Check(int result)
        {
            const int Success = 1;
            if (result != Success)
            {
                Debug.Assert(result == 0);
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }
    }

}

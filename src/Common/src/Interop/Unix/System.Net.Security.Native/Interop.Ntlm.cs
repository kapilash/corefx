// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using size_t = System.IntPtr;
using Crypto = Interop.Crypto;

internal static partial class Interop
{
    internal static partial class libheimntlm
    {
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

        internal static unsafe byte[] EVPDigest(SafeNtlmBufferHandle key, int keylen, byte[] input, int inputlen, out uint outputlen)
        {
            byte[] output = new byte[Crypto.EVP_MAX_MD_SIZE];
            outputlen = 0;
            using (SafeEvpMdCtxHandle ctx = Crypto.EvpMdCtxCreate(Crypto.EvpMd5()))
            {
                Crypto.EvpDigestUpdate(ctx, (byte*)key.Value.ToPointer(), keylen);
                fixed (byte* inPtr = input)
                {
                    Crypto.EvpDigestUpdate(ctx, inPtr, inputlen);
                }
                fixed (byte* outPtr = output)
                {
                    Crypto.EvpDigestFinalEx(ctx, outPtr, ref outputlen);
                }
            }
            return output;
        }

        internal static unsafe byte[] EVPEncryptOrDecrypt(SafeEvpCipherCtxHandle ctx, byte* input, int inputlen)
        {
            byte[] output = new byte[inputlen];

            Crypto.EvpCipher(ctx, output, input, output.Length);
            return output;
        }

        internal static unsafe byte[] HMACDigest(byte* key, int keylen, byte* input, int inputlen, byte* prefix, int prefixlen)
        {
            
            byte[] output = new byte[Crypto.EVP_MAX_MD_SIZE];
            using (SafeHmacCtxHandle ctx = Crypto.HmacCreate(key, keylen, Crypto.EvpMd5()))
            {
                if (prefixlen > 0)
                {
                    Crypto.HmacUpdate(ctx, prefix, prefixlen);
                }
                Crypto.HmacUpdate(ctx, input, inputlen);
                fixed (byte* hashPtr = output)
                {
                    int hashLength = 0;
                    Crypto.HmacFinal(ctx, hashPtr, ref hashLength);
                }
            }
            return output;
        }
    }

}

namespace Microsoft.Win32.SafeHandles
{
    /// <summary>
    /// Wrapper around a ntlm_buf*
    /// </summary>
    internal sealed class SafeNtlmBufferHandle : SafeHandle
    {
        private readonly GCHandle _gch;

        // Return the buffer size
        public size_t Length
        {
            get
            {
                if (IsInvalid)
                {
                    return (size_t) 0;
                }
                return ((Interop.libheimntlm.ntlm_buf) _gch.Target).length;
            }
        }

        // Return a pointer to where data resides
        public IntPtr Value
        {
            get
            {
                if (IsInvalid)
                {
                    return IntPtr.Zero;
                }
                return ((Interop.libheimntlm.ntlm_buf) _gch.Target).data;
            }
        }

        public SafeNtlmBufferHandle()
            : base(IntPtr.Zero, true)
        {
            Interop.libheimntlm.ntlm_buf buffer = new Interop.libheimntlm.ntlm_buf
            {
                length = (size_t)0,
                data = IntPtr.Zero,
            };
            _gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            handle = _gch.AddrOfPinnedObject();
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        // Note that _value should never be freed directly. For input
        // buffer, it is owned by the caller and for output buffer,
        // it is a by-product of some other allocation
        protected override bool ReleaseHandle()
        {
            Interop.libheimntlm.ntlm_buf buffer = (Interop.libheimntlm.ntlm_buf) _gch.Target;
            Interop.libheimntlm.HeimNtlmFreeBuf(ref buffer);
            _gch.Free();
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    /// <summary>
    /// Wrapper around a session key used for signing
    /// </summary>
    internal sealed class SafeNtlmKeyHandle : SafeHandle
    {
        private GCHandle _gch;
        private uint _digestLength;
        private uint _sequenceNumber;
        private bool _isSealingKey;
        private SafeEvpCipherCtxHandle _cipherContext;

        // From MS_NLMP SIGNKEY at https://msdn.microsoft.com/en-us/library/cc236711.aspx
        private const string s_keyMagic = "session key to {0}-to-{1} {2} key magic constant\0";
        private const string s_client = "client";
        private const string s_server = "server";
        private const string s_signing = "signing";
        private const string s_sealing = "sealing";

        public SafeNtlmKeyHandle(SafeNtlmBufferHandle key, bool isClient, bool isSealingKey)
            : base(IntPtr.Zero, true)
        {
            string keyMagic = string.Format(s_keyMagic, isClient ? s_client : s_server,
                    isClient ? s_server : s_client, isSealingKey ? s_sealing : s_signing);

            byte[] magic = Encoding.UTF8.GetBytes(keyMagic);

            byte[] digest = Interop.libheimntlm.EVPDigest(key, (int) key.Length, magic, magic.Length, out _digestLength);
            _isSealingKey = isSealingKey;
            if (_isSealingKey)
            {
                _cipherContext = Crypto.EvpCipherCreate(Crypto.EvpRc4(), digest, null, 1);
            }
            _gch = GCHandle.Alloc(digest, GCHandleType.Pinned);
            handle = _gch.AddrOfPinnedObject();
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && (null != _cipherContext))
            {
                _cipherContext.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            _gch.Free();
            SetHandle(IntPtr.Zero);
            return true;
        }

        public byte[] Sign(SafeNtlmKeyHandle sealingKey, byte[] buffer, int offset, int count)
        {
            Debug.Assert(!_isSealingKey, "Cannot sign with sealing key");
            byte[] output = new byte[16];
            Array.Clear(output, 0, output.Length);
            byte[] hash;
            unsafe
            {
                fixed (byte* outPtr = output)
                    fixed (byte* bytePtr = buffer)
                    {
                        MarshalUint(outPtr, 0x00000001); // version
                        MarshalUint(outPtr + 12, _sequenceNumber);
                        hash = Interop.libheimntlm.HMACDigest((byte*) handle.ToPointer(), (int)_digestLength, (bytePtr + offset), count,
                                outPtr + 12, 4);
                        _sequenceNumber++;
                    }
            }
            if ((sealingKey == null) || sealingKey.IsInvalid)
            {
                Array.Copy(hash, 0, output, 4, 8);
            }
            else
            {
                byte[] cipher = sealingKey.SealOrUnseal(true, hash, 0, 8);
                Array.Copy(cipher, 0, output, 4, cipher.Length);
            }
            return output;
        }

        public byte[] SealOrUnseal(bool seal, byte[] buffer, int offset, int count)
        {
            Debug.Assert(_isSealingKey, "Cannot seal or unseal with signing key");
            unsafe
            {
                fixed (byte* bytePtr = buffer)
                {
                    // Since RC4 is XOR-based, encrypt or decrypt is relative to input data
                    byte[] output = new byte[count];

                    Crypto.EvpCipher(_cipherContext, output, (bytePtr + offset), count);
                    return  output;

                }
            }
        }

        private static unsafe void MarshalUint(byte* ptr, uint num)
        {
            for (int i = 0; i < 4; i++)
            {
                ptr[i] = (byte) (num & 0xff);
                num >>= 8;
            }
        }
    }

    /// <summary>
    /// Wrapper around a ntlm_type2*
    /// </summary>
    internal sealed class SafeNtlmType2Handle : SafeHandle
    {
        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.libheimntlm.HeimNtlmFreeType2(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        private SafeNtlmType2Handle() : base(IntPtr.Zero, true)
        {
        }
    }

    /// <summary>
    /// Wrapper around a ntlm_type3*
    /// </summary>
    internal sealed class SafeNtlmType3Handle : SafeHandle
    {
        private readonly SafeNtlmType2Handle _type2Handle;
        public SafeNtlmType3Handle(byte[] type2Data, int offset, int count) : base(IntPtr.Zero, true)
        {
            int status = Interop.libheimntlm.HeimNtlmDecodeType2(type2Data, offset, count, out _type2Handle);
            Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_decode_type2 failed", status);
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        public SafeNtlmBufferHandle GetResponse(uint flags, string username, string password, string domain,
                out SafeNtlmBufferHandle sessionKey)
        {
            sessionKey = null;

            using (SafeNtlmBufferHandle key = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle lmResponse = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle ntResponse = new SafeNtlmBufferHandle())
            {
                int status = Interop.libheimntlm.HeimNtlmNtKey(password, key);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_nt_key failed", status);

                byte[] baseSessionKey = new byte[16];
                status = Interop.libheimntlm.HeimNtlmCalculateResponse(true, key.Value, key.Length, _type2Handle, username, domain,
                        baseSessionKey, baseSessionKey.Length, lmResponse);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_lm2 failed",status);

                status = Interop.libheimntlm.HeimNtlmCalculateResponse(false, key.Value, key.Length, _type2Handle, username, domain,
                        baseSessionKey, baseSessionKey.Length, ntResponse);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_ntlm2 failed", status);

                sessionKey = new SafeNtlmBufferHandle(); // Should not be disposed on success
                SafeNtlmBufferHandle outputData = new SafeNtlmBufferHandle(); // Should not be disposed on success
                try
                {
                    status = Interop.libheimntlm.CreateType3Message(key.Value, key.Length, _type2Handle, username, domain, flags, lmResponse, ntResponse,
                            baseSessionKey, baseSessionKey.Length, sessionKey, outputData);
                    Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError(
                            "heim_ntlm_build_ntlm1_master failed", status);
                }
                catch
                {
                    sessionKey.Dispose();
                    outputData.Dispose();
                }

                return outputData;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _type2Handle.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            Interop.libheimntlm.HeimNtlmFreeType2(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}

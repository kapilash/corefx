// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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
                return ((Interop.NetSecurity.ntlm_buf) _gch.Target).length;
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
                return ((Interop.NetSecurity.ntlm_buf) _gch.Target).data;
            }
        }

        public SafeNtlmBufferHandle()
           : base(IntPtr.Zero, true)
        {
            Interop.NetSecurity.ntlm_buf buffer = new Interop.NetSecurity.ntlm_buf
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
            Interop.NetSecurity.ntlm_buf buffer = (Interop.NetSecurity.ntlm_buf) _gch.Target;
            Interop.NetSecurity.HeimNtlmFreeBuf(ref buffer);
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

            byte[] digest = Interop.NetSecurity.EVPDigest(key, (int) key.Length, magic, magic.Length, out _digestLength);
            _isSealingKey = isSealingKey;
            if (_isSealingKey)
            {
                _cipherContext = Interop.Crypto.EvpCipherCreate(Interop.Crypto.EvpRc4(), digest, null, 1);
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
                _cipherContext = null;
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
            Debug.Assert(offset > 0 && offset < buffer.Length, "Cannot sign with invalid offset " + offset);
            Debug.Assert((count + offset) < buffer.Length, "Cannot sign with invalid count " + count);

            // reference for signing a message: https://msdn.microsoft.com/en-us/library/cc236702.aspx
            const uint Version = 0x00000001;
            const int ChecksumOffset = 4;
            const int SequenceNumberOffset = 12;
            const int HMacDigestLength = 8;

            
            byte[] output = new byte[Interop.NetSecurity.MD5DigestLength];
            Array.Clear(output, 0, output.Length);
            byte[] hash;
            unsafe
            {

                fixed (byte* outPtr = output)
                fixed (byte* bytePtr = buffer)
                {
                    MarshalUint(outPtr, Version); // version
                    MarshalUint(outPtr + SequenceNumberOffset, _sequenceNumber);
                    int hashLength;
                    hash = Interop.NetSecurity.HMACDigest((byte*) handle.ToPointer(), (int)_digestLength, (bytePtr + offset), count,
                                                          outPtr + SequenceNumberOffset, ChecksumOffset, out hashLengt);
                    Debug.Assert(hash != null && hashLength >= HMacDigestLength, "HMACDigest has a length of at least " + HMacDigestLength);
                    _sequenceNumber++;
                }
            }

            if ((sealingKey == null) || sealingKey.IsInvalid)
            {
                Array.Copy(hash, 0, output, ChecksumOffset, HMacDigestLength);
            }
            else
            {
                byte[] cipher = sealingKey.SealOrUnseal(true, hash, 0, HMacDigestLength);
                Array.Copy(cipher, 0, output, ChecksumOffset, cipher.Length);
            }

            return output;
        }

        public byte[] SealOrUnseal(bool seal, byte[] buffer, int offset, int count)
        {
            //Message Confidentiality. Reference: https://msdn.microsoft.com/en-us/library/cc236707.aspx
            Debug.Assert(_isSealingKey, "Cannot seal or unseal with signing key");
            Debug.Assert(offset > 0 && offset < buffer.Length, "Cannot sign with invalid offset " + offset);
            Debug.Assert((count + offset) < buffer.Length, "Cannot sign with invalid count " + count);

            unsafe
            {
                fixed (byte* bytePtr = buffer)
                {
                    // Since RC4 is XOR-based, encrypt or decrypt is relative to input data
                    // reference: https://msdn.microsoft.com/en-us/library/cc236707.aspx
                    byte[] output = new byte[count];

                    Interop.Crypto.EvpCipher(_cipherContext, output, (bytePtr + offset), count);
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
            Interop.NetSecurity.HeimNtlmFreeType2(handle);
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
            int status = Interop.NetSecurity.HeimNtlmDecodeType2(type2Data, offset, count, out _type2Handle);
            Interop.NetSecurity.HeimdalNtlmException.AssertOrThrowIfError("HeimNtlmDecodeType2 failed", status);
        }

        public override bool IsInvalid
        {
            get { return (null != _type2Handle) && !_type2Handle.IsInvalid; }
        }

        public SafeNtlmBufferHandle GetResponse(uint flags, string username, string password, string domain,
                out SafeNtlmBufferHandle sessionKey)
        {
            sessionKey = null;
            // reference for NTLM response: https://msdn.microsoft.com/en-us/library/cc236700.aspx

            using (SafeNtlmBufferHandle key = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle lmResponse = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle ntResponse = new SafeNtlmBufferHandle())
            {
                int status = Interop.NetSecurity.HeimNtlmNtKey(password, key);
                Interop.NetSecurity.HeimdalNtlmException.AssertOrThrowIfError("HeimNtlmKey failed", status);

                byte[] baseSessionKey = new byte[Interop.NetSecurity.MD5DigestLength];
                status = Interop.NetSecurity.HeimNtlmCalculateResponse(true, key.Value, key.Length, _type2Handle, username, domain,
                        baseSessionKey, baseSessionKey.Length, lmResponse);
                Interop.NetSecurity.HeimdalNtlmException.AssertOrThrowIfError("HeimNtlmCalculateResponse lm1 failed",status);

                status = Interop.NetSecurity.HeimNtlmCalculateResponse(false, key.Value, key.Length, _type2Handle, username, domain,
                        baseSessionKey, baseSessionKey.Length, ntResponse);
                Interop.NetSecurity.HeimdalNtlmException.AssertOrThrowIfError("HeimNtlmCalculateResponse lm2 failed", status);

                sessionKey = new SafeNtlmBufferHandle(); // Should not be disposed on success
                SafeNtlmBufferHandle outputData = new SafeNtlmBufferHandle(); // Should not be disposed on success
                try
                {
                    status = Interop.NetSecurity.CreateType3Message(key.Value, key.Length, _type2Handle, username, domain, flags, lmResponse, ntResponse,
                            baseSessionKey, baseSessionKey.Length, sessionKey, outputData);
                    Interop.NetSecurity.HeimdalNtlmException.AssertOrThrowIfError(
                            "CreateType3Message failed", status);
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
                _type2Handle = null;
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
 
    internal sealed class SafeFreeNtlmCredentials : SafeHandle
    {
        private readonly string _username;
        private readonly string _password;
        private readonly string _domain;

        public string UserName
        {
            get { return _username; }
        }

        public string Password
        {
            get { return _password; }
        }

        public string Domain
        {
            get { return _domain; }
        }

        public SafeFreeNtlmCredentials(string username, string password, string domain)
            : base(IntPtr.Zero, false)
        {
            _username = username;
            _password = password;
            _domain = domain;
        }

        public override bool IsInvalid
        {
            get { return false; }
        }

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }

    internal sealed class SafeDeleteNtlmContext : SafeHandle
    {
        private readonly SafeFreeNtlmCredentials _credential;
        private readonly uint _flags;
        private SafeNtlmKeyHandle _serverSignKey;
        private SafeNtlmKeyHandle _serverSealKey;
        private SafeNtlmKeyHandle _clientSignKey;
        private SafeNtlmKeyHandle _clientSealKey;

        public uint Flags
        {
            get { return _flags;  }
        }

        public SafeDeleteNtlmContext(SafeFreeNtlmCredentials credential, uint flags)
            : base(IntPtr.Zero, true)
        {
            bool ignore = false;
            credential.DangerousAddRef(ref ignore);
            _credential = credential;
            _flags = flags;
        }

        public override bool IsInvalid
        {
            get { return (null == _credential) || _credential.IsInvalid; }
        }

        public void SetKeys(SafeNtlmBufferHandle sessionKey)
        {
            Interop.HeimdalNtlm.CreateKeys(sessionKey, out _serverSignKey, out _serverSealKey, out _clientSignKey, out _clientSealKey);
        }

        public byte[] MakeSignature(bool isSend, byte[] buffer, int offset, int count)
        {
            if (isSend)
            {
                return _clientSignKey.Sign(_clientSealKey, buffer, offset, count);
            }
            else
            {
                return _serverSignKey.Sign(_serverSealKey, buffer, offset, count);
            }
        }

        public byte[] EncryptOrDecrypt(bool isEncrypt, byte[] buffer, int offset, int count)
        {
            if (isEncrypt)
            {
                return _clientSealKey.SealOrUnseal(true, buffer, offset, count);
            }
            else
            {
                return _serverSealKey.SealOrUnseal(false, buffer, offset, count);
            }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            if ((null != _clientSignKey) && !_clientSignKey.IsInvalid)
            {
                _clientSignKey.Dispose();
            }
            if ((null != _clientSealKey) && !_clientSealKey.IsInvalid)
            {
                _clientSealKey.Dispose();
            }
            if ((null != _serverSignKey) && !_serverSignKey.IsInvalid)
            {
                _serverSignKey.Dispose();
            }
            if ((null != _serverSealKey) && !_serverSealKey.IsInvalid)
            {
                _serverSealKey.Dispose();
            }
            return true;
        }
    }
}

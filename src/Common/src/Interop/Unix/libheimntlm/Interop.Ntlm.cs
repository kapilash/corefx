// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libheimntlm
    {
        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmFreeBuf(ntlm_buf data);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmEncodeType1(uint flags, SafeNtlmBufferHandle data);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmDecodeType2(SafeNtlmBufferHandle data, SafeNtlmType2Handle type2);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern int HeimNtlmFreeType2(IntPtr type2);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern unsafe int HeimNtlmNtKey(string password, SafeNtlmBufferHandle key);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern unsafe int HeimNtlmCalculateLm2(
            IntPtr key,
            size_t len,
            string username,
            string target,
            SafeNtlmType2Handle type2,
            byte[] ntlmv2,
            SafeNtlmBufferHandle answer);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern unsafe int HeimNtlmCalculateNtlm1(
                  IntPtr key,
                  size_t len,
                  SafeNtlmType2Handle type2,
                  SafeNtlmBufferHandle answer,
                  string username,
                  string target,
                  byte[] ntlmv2
                  );


        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern unsafe int HeimNtlmCalculateNtlm2(
            IntPtr key,
            size_t len,
            string username,
            string target,
            byte* serverchallenge,
            SafeNtlmBufferHandle infotarget,
            byte [] ntlmv2,
            SafeNtlmBufferHandle answer);

        //[DllImport(Interop.Libraries.SecurityNative)]
        //internal static extern int HeimNtlmEncodeType3(ref ntlm_type3 type3, SafeNtlmBufferHandle data,
        //    ref size_t mic_offset);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern unsafe int HeimNtlmBuildNtlm1Master(
            byte* key,
            size_t len,
            SafeNtlmBufferHandle session,
            SafeNtlmBufferHandle master);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern unsafe void HeimNtlmBuildNtlm2Master(
            byte* key,
            size_t len,
            SafeNtlmBufferHandle blob,
            SafeNtlmBufferHandle session,
            out SafeNtlmBufferHandle master);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern unsafe void ProcessType3Message(
         IntPtr username,
         IntPtr domian,
         uint flags,
         SafeNtlmBufferHandle lm,
         SafeNtlmBufferHandle ntlm,
         SafeNtlmType2Handle type2Handle,
         IntPtr key,
         size_t len,
         SafeNtlmBufferHandle ntResponse,
         SafeNtlmBufferHandle session,
         out SafeNtlmBufferHandle master,
         byte [] baseSessionKey,
         uint baseSeesionKeyLen,
         SafeNtlmBufferHandle outputData
         );

        [DllImport(Interop.Libraries.CryptoNative)]
        internal static extern IntPtr EvpMdCtxDestroy(SafeEvpMdCtxHandle ctx);

        [DllImport(Interop.Libraries.CryptoNative)]
        private static extern void HmacDestroy(SafeHmacCtxHandle ctx);
      
        [DllImport(Interop.Libraries.CryptoNative)]
        private static unsafe extern void RC4SetKey(ref RC4_KEY key, int len, byte[] data);

        [DllImport(Interop.Libraries.CryptoNative)]
        private static unsafe extern void Rc4(ref RC4_KEY key, ulong len, byte* indata, byte* outdata);

        [DllImport(Interop.Libraries.CryptoNative)]
        public static extern IntPtr EvpRc4();

        [DllImport(Interop.Libraries.CryptoNative)]
        private static extern int EvpCipherDestroy(SafeEvpCipherCtxHandle ctx);

        [DllImport(Interop.Libraries.CryptoNative)]
        public static unsafe extern int EvpCipher(ref SafeEvpCipherCtxHandle ctx, byte[] output, byte* input, int inl);

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


        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct RC4_KEY
        {
            public int x;
            public int y;
            public fixed int data[256];
        }
    

    internal static unsafe byte[] EVPDigest(SafeNtlmBufferHandle key, int keylen, byte[] input, int inputlen, out uint outputlen)
        {
            byte[] output = new byte[Interop.Crypto.EVP_MAX_MD_SIZE];
            outputlen = 0;
            SafeEvpMdCtxHandle ctx = Interop.Crypto.EvpMdCtxCreate(Crypto.EvpMd5());
            try
            {
                Interop.Crypto.EvpDigestUpdate(ctx, (byte*)key.Value.ToPointer(), keylen);
                fixed (byte* inPtr = input)
                {
                    Interop.Crypto.EvpDigestUpdate(ctx, inPtr, inputlen);
                }
                fixed (byte* outPtr = output)
                {
                    Interop.Crypto.EvpDigestFinalEx(ctx, outPtr, ref outputlen);
                }
            }
            finally
            {
                EvpMdCtxDestroy(ctx);
            }
            return output;
        }

        internal static unsafe byte[] EVPEncryptOrDecrypt(int x, bool encrypt, byte[] key, int keylen, byte* input, int inputlen)
        {
            if (x > 0)
            {
                SafeEvpCipherCtxHandle ctx = Interop.Crypto.EvpCipherCreate(EvpRc4(), key, null, encrypt? 1: 0);
                try
                {
                    byte[] output = new byte[inputlen];
                    EvpCipher(ref ctx, output, input, output.Length);
                    return output;
                }
                finally
                {
                    EVPFreeContext(ctx);
                }
            }
            else
            {
                byte[] output = new byte[inputlen];
                RC4_KEY k = new RC4_KEY();
                RC4SetKey(ref k, keylen, key);
                fixed (byte* outPtr = output)
                {
                    Rc4(ref k, (ulong)inputlen, input, outPtr);
                }
                return output;
            }
        }

        internal static void EVPFreeContext(SafeEvpCipherCtxHandle ctx)
        {
           EvpCipherDestroy(ctx);
        }
      
        internal static unsafe byte[] EVPEncryptOrDecrypt(SafeEvpCipherCtxHandle ctx, byte* input, int inputlen)
        {
            byte[] output = new byte[inputlen];

          EvpCipher(ref ctx, output, input, output.Length);
          return output;
        }

        internal static unsafe byte[] HMACDigest(byte* key, int keylen, byte* input, int inputlen, byte* prefix, int prefixlen)
        {
            
            SafeHmacCtxHandle ctx = null;
            byte[] output = new byte[Interop.Crypto.EVP_MAX_MD_SIZE];
            try
            {
                ctx = Interop.Crypto.HmacCreate(key, keylen, Crypto.EvpMd5());
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
            finally
            {
                HmacDestroy(ctx);
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
        private readonly bool _isOutputBuffer;
        private readonly GCHandle _gch;
        private readonly GCHandle _arrayGcHandle = new GCHandle();

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
            : this(0, IntPtr.Zero)
        {
            _isOutputBuffer = true;
        }

        public SafeNtlmBufferHandle(byte[] data) : this(data, 0, (data == null) ? 0 : data.Length)
        {
        }

        public SafeNtlmBufferHandle(byte[] data, int offset, int count) : this(count, IntPtr.Zero)
        {
            if (data != null)
            {
                _arrayGcHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
                IntPtr address = new IntPtr(_arrayGcHandle.AddrOfPinnedObject().ToInt64() + offset);
                Marshal.WriteIntPtr(handle, (int) Marshal.OffsetOf<Interop.libheimntlm.ntlm_buf>("data"), address);
            }
        }

        public SafeNtlmBufferHandle(int length, IntPtr value)
            : base(IntPtr.Zero, true)
        {
            Interop.libheimntlm.ntlm_buf buffer = new Interop.libheimntlm.ntlm_buf
            {
                length = (size_t) length,
                data = value,
            };
            _gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            handle = _gch.AddrOfPinnedObject();
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        //public Interop.libheimntlm.ntlm_buf ToBuffer()
        //{
        //    return (Interop.libheimntlm.ntlm_buf) _gch.Target;
        //}

        // Note that _value should never be freed directly. For input
        // buffer, it is owned by the caller and for output buffer,
        // it is a by-product of some other allocation
        protected override bool ReleaseHandle()
        {
            Interop.libheimntlm.ntlm_buf buffer = (Interop.libheimntlm.ntlm_buf) _gch.Target;

            if (_isOutputBuffer && (buffer.data != IntPtr.Zero))
            {
                buffer.data = IntPtr.Zero;
            }

            if (_arrayGcHandle.IsAllocated)
            {
                _arrayGcHandle.Free();
            }
            else
            {
                Interop.libheimntlm.HeimNtlmFreeBuf(buffer);
            }
           
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
                _cipherContext = Interop.Crypto.EvpCipherCreate(Interop.libheimntlm.EvpRc4(), digest, null, 1);
            }
            _gch = GCHandle.Alloc(digest, GCHandleType.Pinned);
            handle = _gch.AddrOfPinnedObject();
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
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
                  
                        Interop.libheimntlm.EvpCipher(ref _cipherContext, output, (bytePtr + offset), count);
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
        public SafeNtlmType2Handle() : base(IntPtr.Zero, true)
        {
            //do something
        }

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
    }

    /// <summary>
        /// Wrapper around a ntlm_type3*
        /// </summary>
        internal sealed class SafeNtlmType3Handle : SafeHandle
        {
        SafeNtlmType2Handle type2handle = new SafeNtlmType2Handle();
        public SafeNtlmType3Handle(SafeNtlmBufferHandle type2Data) : base(IntPtr.Zero, true)
        {
            Console.WriteLine("inside SafeNtlmType3Handle");
            int status = Interop.libheimntlm.HeimNtlmDecodeType2(type2Data, type2handle);
            Console.WriteLine("status: "+ status);
            Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_decode_type2 failed", status);
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        public SafeNtlmBufferHandle GetResponse(uint flags, string username, string password, string domain,
            out SafeNtlmBufferHandle sessionKey)
        {
            SafeNtlmBufferHandle outputData = new SafeNtlmBufferHandle();
            sessionKey = null;
          //  Interop.libheimntlm.ntlm_type2 type2Message = (Interop.libheimntlm.ntlm_type2) _gch.Target;

            using (SafeNtlmBufferHandle key = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle lmResponse = new SafeNtlmBufferHandle())
            using (SafeNtlmBufferHandle ntResponse = new SafeNtlmBufferHandle())
            {
                int status = Interop.libheimntlm.HeimNtlmNtKey(password, key);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_nt_key failed", status);
                byte[] baseSessionKey = new byte[16];
                status = Interop.libheimntlm.HeimNtlmCalculateLm2(key.Value, key.Length, username, domain,type2handle,baseSessionKey, lmResponse);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_lm2 failed",status);

                status = Interop.libheimntlm.HeimNtlmCalculateNtlm1(key.Value, key.Length, type2handle, ntResponse,
                    username, domain, baseSessionKey);
                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_ntlm1 failed", status);
                SafeNtlmBufferHandle masterKey = null;
                Interop.libheimntlm.ProcessType3Message(Marshal.StringToHGlobalAnsi(username),
                    Marshal.StringToHGlobalAnsi(domain),
                    flags,
                    lmResponse,
                    ntResponse,
                    type2handle,
                    key.Value,
                    key.Length,
                    ntResponse,
                    sessionKey, //TODO check who is setting this
                    out masterKey,
                    baseSessionKey,
                    (uint) baseSessionKey.Length,
                    outputData
                    );


                Interop.libheimntlm.HeimdalNtlmException.AssertOrThrowIfError(
                    "heim_ntlm_build_ntlm1_master failed", status);

                return outputData;
            }
        }
        

            protected override bool ReleaseHandle()
        {
            Interop.libheimntlm.HeimNtlmFreeType2(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}






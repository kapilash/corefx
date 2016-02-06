// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
 
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
        private Interop.HeimdalNtlm.SigningKey _serverSignKey;
        private Interop.HeimdalNtlm.SealingKey _serverSealKey;
        private Interop.HeimdalNtlm.SigningKey _clientSignKey;
        private Interop.HeimdalNtlm.SealingKey _clientSealKey;

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

        public void SetKeys(byte[] sessionKey)
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
                return _clientSealKey.SealOrUnseal(buffer, offset, count);
            }
            else
            {
                return _serverSealKey.SealOrUnseal(buffer, offset, count);
            }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            if (null != _clientSealKey)
            {
                _clientSealKey.Dispose();
            }
            if (null != _serverSealKey)
            {
                _serverSealKey.Dispose();
            }
            return true;
        }
    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security
{


    internal sealed class SafeFreeGssCredentials :SafeGssCredHandle
    {
        public SafeFreeGssCredentials(string username, string password, string domain) 
        {
           Create(username, password, domain);
        }
    }

    internal sealed class SafeDeleteGssContext : SafeHandle
    {
        private readonly SafeGssNameHandle _targetName;
        private SafeFreeGssCredentials _credential;
        private SafeGssContextHandle _context;
        private bool _encryptAndSign;

        public SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public bool NeedsEncryption
        {
            get { return _encryptAndSign; }
        }

        public SafeDeleteGssContext(string targetName, uint flags) : base(IntPtr.Zero, true)
        {
            // In server case, targetName can be null or empty
            if (!String.IsNullOrEmpty(targetName))
            {
             _targetName = SafeGssNameHandle.Create(targetName);
            }

            _encryptAndSign = (flags & (uint)Interop.libgssapi.GssFlags.GSS_C_CONF_FLAG) != 0;
        }

        public override bool IsInvalid
        {
            get { return (null == _context) || _context.IsInvalid; }
        }

        public void SetHandle(SafeFreeGssCredentials credential, SafeGssContextHandle context)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteGssContext");
            _context = context;

            // After context establishment is initiated, callers expect SafeDeleteGssContext
            // to bump up the ref count.
            // NOTE: When using default credentials, the credential handle may be invalid
            if ((null != credential) && !credential.IsInvalid)
            {
                bool ignore = false;
                _credential = credential;
                _credential.DangerousAddRef(ref ignore);
            }
        }

        protected override bool ReleaseHandle()
        {
            if ((null != _credential) && !_credential.IsInvalid)
            {
                _credential.DangerousRelease();
            }
            _context.Dispose();
            if (_targetName != null)
            {
                _targetName.Dispose();
            }
            return true;
        }
    }

}

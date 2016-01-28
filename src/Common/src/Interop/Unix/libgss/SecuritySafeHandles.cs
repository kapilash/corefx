using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
#if DEBUG
    internal class SafeFreeGssCredentials : DebugSafeHandle
    {
#else
    internal class SafeFreeGssCredentials : SafeHandle
    {
#endif
        private readonly SafeGssCredHandle _credential;
        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }
        public SafeFreeGssCredentials(string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _credential = SafeGssCredHandle.Create(username, password, domain);
            bool ignore = false;
            _credential.DangerousAddRef(ref ignore);
            handle = _credential.DangerousGetHandle();
        }

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _credential.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            return true;
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

        public SafeDeleteGssContext(string targetName, Interop.libgssapi.GssFlags flags) : base(IntPtr.Zero, true)
        {
            // In server case, targetName can be null or empty
            if (!String.IsNullOrEmpty(targetName))
            {
                _targetName = SafeGssNameHandle.Create(targetName, false);
            }

            _encryptAndSign = (flags & Interop.libgssapi.GssFlags.GSS_C_CONF_FLAG) != 0;
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
                _credential = null;
            }
            // TODO: Fix up Dispose logic
            _context.Dispose();
            if (_targetName != null)
            {
                _targetName.Dispose();
            }
            return true;
        }
    }

}

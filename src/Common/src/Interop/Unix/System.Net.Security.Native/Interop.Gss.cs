// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libgssapi
    {
        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssReleaseBuffer(
            out Status minorStatus,
            ref gss_buffer_desc buffer);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssDisplayStatus(
            out Status minorStatus,
            Status statusValue,
            bool isGssMechCode,
            SafeGssBufferHandle statusString);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern Status GssImportNtUserName(
            out Status minorStatus,
            string inputName,
            out SafeGssNameHandle outputName);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssReleaseName(
            out Status minorStatus,
            ref IntPtr inputName);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssAcquireCredSpNego(
            out Status minorStatus,
            SafeGssNameHandle desiredName,
            bool isInitiate,
            out SafeGssCredHandle outputCredHandle);

        [DllImport(Interop.Libraries.SecurityNative, CharSet = CharSet.Ansi)]
        internal static extern Status GssAcquireCredWithPasswordSpNego(
            out Status minorStatus,
            SafeGssNameHandle desiredName,
            string password,
            bool isInitiate,
            out SafeGssCredHandle outputCredHandle);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssReleaseCred(
            out Status minorStatus,
            ref IntPtr credHandle);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssInitSecContextSpNego(
            out Status minorStatus,
            SafeGssCredHandle initiatorCredHandle,
            ref SafeGssContextHandle contextHandle,
            SafeGssNameHandle targetName,
            uint reqFlags,
            SafeGssBufferHandle inputToken,
            SafeGssBufferHandle outputToken,
            out uint retFlags);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssAcceptSecContext(
            out Status minorStatus,
            ref SafeGssContextHandle contextHandle,
            SafeGssCredHandle initiatorCredHandle,
            SafeGssBufferHandle inputToken,
            SafeGssBufferHandle outputToken,
            out uint retFlags);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssDeleteSecContext(
            out Status minorStatus,
            ref IntPtr contextHandle);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssWrap(
            out Status minorStatus,
            SafeGssContextHandle contextHandle,
            bool isEncrypt,
            SafeGssBufferHandle inputMessageBuffer,
            SafeGssBufferHandle outputMessageBuffer);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssUnwrap(
            out Status minorStatus,
            SafeGssContextHandle contextHandle,
            SafeGssBufferHandle inputMessageBuffer,
            SafeGssBufferHandle outputMessageBuffer);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssInquireSourceName(
            out Status minorStatus,
            SafeGssContextHandle contextHandle,
            out SafeGssNameHandle srcName);

        [DllImport(Interop.Libraries.SecurityNative)]
        internal static extern Status GssDisplayName(
            out Status minorStatus,
            SafeGssNameHandle inputName,
            SafeGssBufferHandle outputNameBuffer);

        [StructLayout(LayoutKind.Sequential)]
        internal struct gss_buffer_desc
        {
            internal size_t length;
            internal IntPtr value;
        }

        internal enum Status : uint
        {
            GSS_S_COMPLETE = 0,
            GSS_S_CONTINUE_NEEDED = 1
        }
    }
}

namespace Microsoft.Win32.SafeHandles
{
    /// <summary>
    /// Wrapper around a gss_buffer_desc*
    /// </summary>
    internal sealed class SafeGssBufferHandle : SafeHandle
    {
        private GCHandle _gch;
        private GCHandle _arrayGcHandle = new GCHandle();

        // Return the buffer size
        public int Length
        {
            get
            {
                if (IsInvalid)
                {
                    return 0;
                }
                return (int)((Interop.libgssapi.gss_buffer_desc)_gch.Target).length;
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
                return ((Interop.libgssapi.gss_buffer_desc)_gch.Target).value;
            }
        }

        public SafeGssBufferHandle()
            : this(0, IntPtr.Zero)
        {
        }

        public SafeGssBufferHandle(byte[] data)
            : this(data, 0, (data == null) ? 0 : data.Length)
        {
        }

        public SafeGssBufferHandle(byte[] data, int offset, int count)
            : this(count, IntPtr.Zero)
        {
            if (data == null) return;
            _arrayGcHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr address = new IntPtr(_arrayGcHandle.AddrOfPinnedObject().ToInt64() + offset);
            Marshal.WriteIntPtr(handle, (int)Marshal.OffsetOf<Interop.libgssapi.gss_buffer_desc>("value"), address);
        }

        private SafeGssBufferHandle(int length, IntPtr ptrValue)
            : base(IntPtr.Zero, true)
        {
            Interop.libgssapi.gss_buffer_desc buffer = new Interop.libgssapi.gss_buffer_desc
            {
                length = (size_t)length,
                value = ptrValue,
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
        // it is owned by libgssapi
        protected override bool ReleaseHandle()
        {
            Interop.libgssapi.gss_buffer_desc buffer = (Interop.libgssapi.gss_buffer_desc) _gch.Target;
            if (buffer.value != IntPtr.Zero)
            {
                if (_arrayGcHandle.IsAllocated)
                {
                    _arrayGcHandle.Free();
                }
                else
                {
                    Interop.libgssapi.Status minorStatus;
                    Interop.libgssapi.Status status = Interop.libgssapi.GssReleaseBuffer(out minorStatus, ref buffer);
                    Interop.libgssapi.GssApiException.AssertOrThrowIfError("GssReleaseBuffer failed", status, minorStatus);
                }
            }
            _gch.Free();
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    /// <summary>
    /// Wrapper around a gss_name_t_desc*
    /// </summary>
    internal sealed class SafeGssNameHandle : SafeHandle
    {
        public static SafeGssNameHandle Create(string name)
        {
            Debug.Assert(!String.IsNullOrEmpty(name), "Invalid name passed to SafeGssNameHandle create");
            SafeGssNameHandle retHandle;
            Interop.libgssapi.Status minorStatus;
            Interop.libgssapi.Status status = Interop.libgssapi.GssImportNtUserName(out minorStatus, name, out retHandle);
            if (status != Interop.libgssapi.Status.GSS_S_COMPLETE)
            {
                throw Interop.libgssapi.GssApiException.Create(status, minorStatus);
            }

            return retHandle;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.libgssapi.Status minorStatus;
            Interop.libgssapi.Status status = Interop.libgssapi.GssReleaseName(out minorStatus, ref handle);
            Interop.libgssapi.GssApiException.AssertOrThrowIfError("GssReleaseName failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }

        private SafeGssNameHandle()
            : base(IntPtr.Zero, true)
        {
        }
    }

    /// <summary>
    /// Wrapper around a gss_cred_id_t_desc_struct*
    /// </summary>
    internal class SafeGssCredHandle : SafeHandle
    {
        public static SafeGssCredHandle Create(string username, string password, string domain)
        {
            SafeGssCredHandle retHandle = null;

            // Empty username is OK if Kerberos ticket was already obtained
            if (!String.IsNullOrEmpty(username))
            {
                using (SafeGssNameHandle userHandle = SafeGssNameHandle.Create(username))
                {
                    Interop.libgssapi.Status status;
                    Interop.libgssapi.Status minorStatus;
                    if (String.IsNullOrEmpty(password))
                    {
                        status = Interop.libgssapi.GssAcquireCredSpNego(out minorStatus, userHandle, true, out retHandle);
                    }
                    else
                    {
                        status = Interop.libgssapi.GssAcquireCredWithPasswordSpNego(out minorStatus, userHandle, password, true, out retHandle);
                    }

                    if (status != Interop.libgssapi.Status.GSS_S_COMPLETE)
                    {
                        throw Interop.libgssapi.GssApiException.Create(status, minorStatus);
                    }
                }
            }

            return retHandle;
        }

        private SafeGssCredHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.libgssapi.Status minorStatus;
            Interop.libgssapi.Status status = Interop.libgssapi.GssReleaseCred(out minorStatus, ref handle);
            Interop.libgssapi.GssApiException.AssertOrThrowIfError("GssReleaseCred failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    internal sealed class SafeGssContextHandle : SafeHandle
    {
        public SafeGssContextHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.libgssapi.Status minorStatus;
            Interop.libgssapi.Status status = Interop.libgssapi.GssDeleteSecContext(out minorStatus, ref handle);
            Interop.libgssapi.GssApiException.AssertOrThrowIfError("GssDeleteSecContext failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}

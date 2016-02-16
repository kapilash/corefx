using System;
using System.IO;
using System.Security.Authentication;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    internal class UnixGssFakeNegotiateStream : NegotiateStream
    {
        private static Action<object> s_serverLoop = ServerLoop;
        private readonly UnixGssFakeStreamFramer _framer;
        private SafeGssContextHandle _context;

        public UnixGssFakeNegotiateStream(Stream innerStream) : base(innerStream)
        {
            _framer = new UnixGssFakeStreamFramer(innerStream);
        }

        public override Task AuthenticateAsServerAsync()
        {
            return Task.Factory.StartNew(s_serverLoop, (object)this);
        }

        public static void GetDefaultKerberosCredentials(string username, string password)
        {
            // Fetch a Kerberos TGT which gets saved in the default cache
            using (SafeGssCredHandle cred = SafeGssCredHandle.Create(username, password, string.Empty))
            {
                return;
            }

        }

        private static void ServerLoop(object state)
        {
            UnixGssFakeNegotiateStream thisRef = (UnixGssFakeNegotiateStream)state;
            var header = new byte[5];
            bool done = false;
            do
            {
                byte[] inBuf = thisRef._framer.ReadFrame();
                byte[] outBuf = null;
                try
                {
                    done = EstablishSecurityContext(ref thisRef._context, inBuf, out outBuf);
                    thisRef._framer.WriteFrame(outBuf, 0, outBuf.Length);
                }
                catch (Interop.NetSecurityNative.GssApiException e)
                {
                    thisRef._framer.WriteFrame(e);
                    done = true;
                }
            }
            while (!done);
        }

        private static bool EstablishSecurityContext(
            ref SafeGssContextHandle context,
            byte[] buffer,
            out byte[] outputBuffer)
        {
            outputBuffer = null;

            // EstablishSecurityContext is called multiple times in a session.
            // In each call, we need to pass the context handle from the previous call.
            // For the first call, the context handle will be null.
            if (context == null)
            {
                context = new SafeGssContextHandle();
            }

            Interop.NetSecurityNative.GssBuffer token = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.AcceptSecContext(out minorStatus,
                                                          ref context,
                                                          buffer,
                                                          (buffer == null) ? 0 : buffer.Length,
                                                          ref token);

                if ((status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE) && (status != Interop.NetSecurityNative.Status.GSS_S_CONTINUE_NEEDED))
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                outputBuffer = token.ToByteArray();
            }
            finally
            {
                token.Dispose();
            }

            return status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE;
        }
    }
}

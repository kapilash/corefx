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
        private volatile int _dataMsgCount;

        public UnixGssFakeNegotiateStream(Stream innerStream, int dataMessages = 0) : base(innerStream)
        {
            _framer = new UnixGssFakeStreamFramer(innerStream);
            _dataMsgCount = dataMessages;
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
            bool handshakeDone = false;
            do
            {
                if (!handshakeDone)
                {
                    byte[] inBuf = thisRef._framer.ReadHandshakeFrame();
                    byte[] outBuf = null;
                    try
                    {
                        handshakeDone = EstablishSecurityContext(ref thisRef._context, inBuf, out outBuf);
                        thisRef._framer.WriteHandshakeFrame(outBuf, 0, outBuf.Length);
                    }
                    catch (Interop.NetSecurityNative.GssApiException e)
                    {
                        thisRef._framer.WriteHandshakeFrame(e);
                        handshakeDone = true;
                    }
                }
                else if (thisRef._dataMsgCount > 0)
                {
                    byte[] inBuf = thisRef._framer.ReadDataFrame();
                    byte[] unwrapped = UnwrapMessage(thisRef._context, inBuf);
                    byte[] outMsg = WrapMessage(thisRef._context, unwrapped);
                    thisRef._framer.WriteDataFrame(outMsg, 0, outMsg.Length);
                    thisRef._dataMsgCount--;
                }
            }
            while (!handshakeDone || thisRef._dataMsgCount > 0);
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

        private static byte[] UnwrapMessage(SafeGssContextHandle context, byte[] message)
        {
            Interop.NetSecurityNative.GssBuffer unwrapped = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.Unwrap(out minorStatus,
                                                          context,
                                                          message,
                                                          0,
                                                          message.Length,
                                                          ref unwrapped);
                if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                return unwrapped.ToByteArray();
            }
            finally
            {
                unwrapped.Dispose();
            }
        }

        private static byte[] WrapMessage(SafeGssContextHandle context, byte[] message)
        {
            Interop.NetSecurityNative.GssBuffer wrapped = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.Wrap(out minorStatus,
                                                        context,
                                                        false,
                                                        message,
                                                        0,
                                                        message.Length,
                                                        ref wrapped);
                if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                return wrapped.ToByteArray();
            }
            finally
            {
                wrapped.Dispose();
            }
        }
    }
}

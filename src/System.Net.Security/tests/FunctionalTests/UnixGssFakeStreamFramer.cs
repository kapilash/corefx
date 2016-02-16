using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    internal class UnixGssFakeStreamFramer
    {
        public const byte HandshakeDoneId = 20;
        public const byte HandshakeErrId = 21;
        public const byte DefaultMajorV = 1;
        public const byte DefaultMinorV = 0;

        private readonly Stream _innerStream;
        private readonly byte[] _header = new byte[5];
        private static readonly byte[] ErrorBuffer = new byte[] { 0, 0, 0, 0, 0x80, 0x09, 0x03, 0x0C }; // return LOGON_DENIED

        public UnixGssFakeStreamFramer(Stream innerStream)
        {
            _innerStream = innerStream;
        }

        public void WriteFrame(byte[] buffer, int offset, int count)
        {
            WriteFrameHeader(count, isError:false);
            if (count > 0)
            {
                _innerStream.Write(buffer, offset, count);
            }
        }

        public void WriteFrame(Interop.NetSecurityNative.GssApiException e)
        {
            WriteFrameHeader(ErrorBuffer.Length, isError:true);
            _innerStream.Write(ErrorBuffer, 0, ErrorBuffer.Length);
        }

        public byte[] ReadFrame()
        {
            _innerStream.Read(_header, 0, _header.Length);
            byte[] inBuf = new byte[(_header[3] << 8) + _header[4]];
            _innerStream.Read(inBuf, 0, inBuf.Length);
            return inBuf;
        }

        private void WriteFrameHeader(int count, bool isError)
        {
            _header[0] = isError ? HandshakeErrId : HandshakeDoneId;
            _header[1] = DefaultMajorV;
            _header[2] = DefaultMinorV;
            _header[3] = (byte)((count >> 8) & 0xff);
            _header[4] = (byte)(count & 0xff);
            _innerStream.Write(_header, 0, _header.Length);
        }
    }
}

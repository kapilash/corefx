using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Principal;

namespace NegoClient
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 5) throw new Exception("dnx run <server> <target> <user> <password> <domain>");
#if true
            //vijayko using (var socket = new Socket(SocketType.Stream, ProtocolType.Tcp))
            using (var stream = new NegotiateStream(new MockUtils.ClientStream(args[0], 4433)))
            {
                //vijayko socket.Connect(args[0], 4433);
                Console.WriteLine("Connected to server: {0}", args[0]);
                //vijayko using (var stream = new NegotiateStream(new NetworkStream(socket)))
#else
            using (var socket = new Socket(SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Connect(args[0], 4433);
                Console.WriteLine("Connected to server: {0}", args[0]);
                using (var stream = new NegotiateStream(new NetworkStream(socket)))
#endif
                {
                    var target = string.Equals(args[1], "ntlm", StringComparison.OrdinalIgnoreCase) ? string.Empty : args[1];
                    var domain = string.Equals(args[4], "empty", StringComparison.OrdinalIgnoreCase) ? string.Empty : args[4];
                    var prot = string.Equals(args[1], "ntlm", StringComparison.OrdinalIgnoreCase) ? ProtectionLevel.None : ProtectionLevel.EncryptAndSign;
                    var cred = string.Equals(args[2], "default", StringComparison.OrdinalIgnoreCase) ? CredentialCache.DefaultNetworkCredentials
                        : new NetworkCredential {UserName = args[2], Password = args[3], Domain = domain};
                    stream.AuthenticateAsClientAsync(cred, target, prot, TokenImpersonationLevel.Identification).Wait();
                    Console.WriteLine("Connected to {0} protocol={1}", stream.RemoteIdentity.Name, stream.RemoteIdentity.AuthenticationType);
                    var buf = new byte[] {0x68, 0x65, 0x6C , 0x6C, 0x6F, 0 }; // "hello"
                    stream.Write(buf, 0, buf.Length);
                    var read = stream.Read(buf, 0, buf.Length);
                    Console.WriteLine("Read {0} bytes", read);
                }
            }
        }
    }
}

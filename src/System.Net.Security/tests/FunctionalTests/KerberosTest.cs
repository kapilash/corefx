// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

using Xunit;

namespace System.Net.Security.Tests
{
    public class KDCSetup
    {
        private const string Krb5ConfigFile = "/etc/krb5.conf";
        private const string KDestroyCmd = "kdestroy";

        public KDCSetup()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = true;
            startInfo.FileName = "./setup-kdc.sh";
            Process kdcSetup = new Process();
            kdcSetup.StartInfo = startInfo;
            kdcSetup.Start();
            kdcSetup.WaitForExit();
            Assert.Equal(0, kdcSetup.ExitCode);
        }

        // checks for avilability of Kerberos related infrastructure
        // on the host. Returns true available, false otherwise
        public static bool CheckAndInitializeKerberos()
        {
            if (File.Exists(Krb5ConfigFile))
            {
                // Clear the credentials
                var startInfo = new ProcessStartInfo(KDestroyCmd);
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                startInfo.Arguments = "-A";
                Process clearCreds = Process.Start(startInfo);
                clearCreds.WaitForExit();
                return (clearCreds.ExitCode == 0);
            }
            return false;
        }
    }

    public class KerberosTest : IDisposable, IClassFixture<KDCSetup>
    {
        private readonly byte[] _sampleMsg = Encoding.UTF8.GetBytes("Sample Test Message");
        private readonly bool _isKrbAvailable; // tests are no-op if kerberos is not available on the host machine
        private readonly KDCSetup _fixture;

        public KerberosTest(KDCSetup fixture)
        {
            _fixture = fixture;
            _isKrbAvailable = KDCSetup.CheckAndInitializeKerberos();
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthentication_Success()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            using (var server = new UnixGssFakeNegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);

                Task[] auth = new Task[2];
                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}", TestConfiguration.HostTarget, TestConfiguration.Realm);
                NetworkCredential credential = new NetworkCredential(user, TestConfiguration.Password);
                auth[0] = client.AuthenticateAsClientAsync(credential, target);
                auth[1] = server.AuthenticateAsServerAsync();

                bool finished = Task.WaitAll(auth, TestConfiguration.PassingTestTimeoutMilliseconds);
                Assert.True(finished, "Handshake completed in the allotted time");

                // Expected Client property values:
                Assert.True(client.IsAuthenticated);
                Assert.Equal(TokenImpersonationLevel.Identification, client.ImpersonationLevel);
                Assert.True(client.IsEncrypted);
                Assert.True(client.IsMutuallyAuthenticated);
                Assert.False(client.IsServer);
                Assert.True(client.IsSigned);
                Assert.False(client.LeaveInnerStreamOpen);

                IIdentity serverIdentity = client.RemoteIdentity;
                Assert.Equal("Kerberos", serverIdentity.AuthenticationType);
                Assert.True(serverIdentity.IsAuthenticated);
                IdentityValidator.AssertHasName(serverIdentity, target);
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_AuthToHttpTarget_Success()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            using (var server = new UnixGssFakeNegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);

                Task[] auth = new Task[2];
                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}",TestConfiguration.HttpTarget, TestConfiguration.Realm);
                NetworkCredential credential = new NetworkCredential(user, TestConfiguration.Password);
                auth[0] = client.AuthenticateAsClientAsync(credential, target);
                auth[1] = server.AuthenticateAsServerAsync();

                bool finished = Task.WaitAll(auth, TestConfiguration.PassingTestTimeoutMilliseconds);
                Assert.True(finished, "Handshake completed in the allotted time");

                // Expected Client property values:
                Assert.True(client.IsAuthenticated);
                Assert.Equal(TokenImpersonationLevel.Identification, client.ImpersonationLevel);
                Assert.True(client.IsEncrypted);
                Assert.True(client.IsMutuallyAuthenticated);
                Assert.False(client.IsServer);
                Assert.True(client.IsSigned);
                Assert.False(client.LeaveInnerStreamOpen);

                IIdentity serverIdentity = client.RemoteIdentity;
                Assert.Equal("Kerberos", serverIdentity.AuthenticationType);
                Assert.True(serverIdentity.IsAuthenticated);
                IdentityValidator.AssertHasName(serverIdentity, target);
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthWithoutRealm_Success()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            using (var server = new UnixGssFakeNegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);

                Task[] auth = new Task[2];
                NetworkCredential credential = new NetworkCredential(TestConfiguration.KerberosUser, TestConfiguration.Password);
                auth[0] = client.AuthenticateAsClientAsync(credential, TestConfiguration.HostTarget);
                auth[1] = server.AuthenticateAsServerAsync();

                bool finished = Task.WaitAll(auth, TestConfiguration.PassingTestTimeoutMilliseconds);
                Assert.True(finished, "Handshake completed in the allotted time");

                // Expected Client property values:
                Assert.True(client.IsAuthenticated);
                Assert.Equal(TokenImpersonationLevel.Identification, client.ImpersonationLevel);
                Assert.True(client.IsEncrypted);
                Assert.True(client.IsMutuallyAuthenticated);
                Assert.False(client.IsServer);
                Assert.True(client.IsSigned);
                Assert.False(client.LeaveInnerStreamOpen);

                IIdentity serverIdentity = client.RemoteIdentity;
                Assert.Equal("Kerberos", serverIdentity.AuthenticationType);
                Assert.True(serverIdentity.IsAuthenticated);
                IdentityValidator.AssertHasName(serverIdentity, TestConfiguration.HostTarget);
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthDefaultCredentials_Success()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            using (var server = new UnixGssFakeNegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);

                Task[] auth = new Task[2];
                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}", TestConfiguration.HostTarget, TestConfiguration.Realm);
                // Seed the default Kerberos cache with the TGT
                UnixGssFakeNegotiateStream.GetDefaultKerberosCredentials(user, TestConfiguration.Password);
                auth[0] = client.AuthenticateAsClientAsync(CredentialCache.DefaultNetworkCredentials, target);
                auth[1] = server.AuthenticateAsServerAsync();

                bool finished = Task.WaitAll(auth, TestConfiguration.PassingTestTimeoutMilliseconds);
                Assert.True(finished, "Handshake completed in the allotted time");

                // Expected Client property values:
                Assert.True(client.IsAuthenticated);
                Assert.Equal(TokenImpersonationLevel.Identification, client.ImpersonationLevel);
                Assert.True(client.IsEncrypted);
                Assert.True(client.IsMutuallyAuthenticated);
                Assert.False(client.IsServer);
                Assert.True(client.IsSigned);
                Assert.False(client.LeaveInnerStreamOpen);

                IIdentity serverIdentity = client.RemoteIdentity;
                Assert.Equal("Kerberos", serverIdentity.AuthenticationType);
                Assert.True(serverIdentity.IsAuthenticated);
                IdentityValidator.AssertHasName(serverIdentity, target);
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthInvalidUser_Failure()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            {
                Assert.False(client.IsAuthenticated);

                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}", TestConfiguration.HostTarget, TestConfiguration.Realm);
                NetworkCredential credential = new NetworkCredential(user.Substring(1), TestConfiguration.Password);
                Assert.Throws<AuthenticationException>(() =>
                {
                    client.AuthenticateAsClientAsync(credential, target);
                });
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthInvalidPassword_Failure()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            {
                Assert.False(client.IsAuthenticated);

                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}", TestConfiguration.HostTarget, TestConfiguration.Realm);
                NetworkCredential credential = new NetworkCredential(user, TestConfiguration.Password.Substring(1));
                Assert.Throws<AuthenticationException>(() =>
                {
                    client.AuthenticateAsClientAsync(credential, target);
                });
            }
        }

        [Fact, OuterLoop]
        [PlatformSpecific(PlatformID.Linux | PlatformID.OSX)]
        [ActiveIssue(6114, PlatformID.Linux | PlatformID.OSX)]
        public void NegotiateStream_StreamToStream_KerberosAuthInvalidTarget_Failure()
        {
            if (!_isKrbAvailable)
            {
                return;
            }

            VirtualNetwork network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var client = new UnixGssFakeNegotiateStream(clientStream))
            {
                Assert.False(client.IsAuthenticated);

                string user = string.Format("{0}@{1}", TestConfiguration.KerberosUser, TestConfiguration.Realm);
                string target = string.Format("{0}@{1}", TestConfiguration.HostTarget, TestConfiguration.Realm);
                NetworkCredential credential = new NetworkCredential(user, TestConfiguration.Password);
                Assert.Throws<AuthenticationException>(() =>
                {
                    client.AuthenticateAsClientAsync(credential, target.Substring(1));
                });
            }
        }

        public void Dispose()
        {
            try
            {
                KDCSetup.CheckAndInitializeKerberos();
            }
            catch
            {
            }
        }
    }
}

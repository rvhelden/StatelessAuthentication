using Funq;
using ServiceStack;
using StatelessAuthentication.Server;

namespace StatelessAuthentication.Tests.Support
{
    public class ServiceHost : AppHostHttpListenerBase
    {
        public ServiceHost() : base("Validation Tests", typeof(AuthenticationServices).Assembly) { }

        public override void Configure(Container container)
        {
            SetConfig(new HostConfig { DebugMode = true });
        }
    }
}

using System.Threading;
using ServiceStack;
using StatelessAuthentication.Models.Messages;
using StatelessAuthentication.Models.Utilities;

namespace StatelessAuthentication.Client
{
    class Program
    {
        private const string ListeningOn = "http://localhost:8088";

        static void Main(string[] args)
        {
            var client = new JsonServiceClient(ListeningOn);
            var saltResponse = client.Get(new SaltRequest { Username = "User" });
            var loginResponse = client.Post(new LoginRequest { Username = "User", Password = HashUtility.Hash("welcome", saltResponse.Salt) });

            client.Headers["token"] = loginResponse.Result;
            var limitedResponse = client.Get(new LimitedAccessRequest());
        }
    }
}

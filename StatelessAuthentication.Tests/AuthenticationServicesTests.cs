using System.Net;
using Funq;
using NUnit.Framework;
using Raven.Client;
using Raven.Client.Embedded;
using Raven.Client.Indexes;
using ServiceStack;
using StatelessAuthentication.Models.Indexes;
using StatelessAuthentication.Models.Messages;
using StatelessAuthentication.Models.Models;
using StatelessAuthentication.Models.Utilities;
using StatelessAuthentication.Tests.Support;

namespace StatelessAuthentication.Tests
{
    [TestFixture]
    public class AuthenticationServicesTests
    {
        private const string ListeningOn = "http://localhost:8088/";
        private ServiceHost _appHost;

        private const string Username = "User";
        private const string Salt = "/QEbkHkkpM+031q0KerO1A==";
        private const string PasswordHash = "hVvF3Z8/WtZNtDbSofrbnOUqg5tHXHGBPBuR5NlpVXpeRM/V+DABLXy9FGwd5TcQG7d4RJVVhwStR/PGOI7WSw==";
        private const string Password = "welcome";

        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
            _appHost = new ServiceHost();
            _appHost.Init().Start(ListeningOn);

            var store = new EmbeddableDocumentStore { DataDirectory = "Data" }.Initialize();

            _appHost.Container.Register(store);
            _appHost.Container.Register(c => c.Resolve<IDocumentStore>().OpenSession()).ReusedWithin(ReuseScope.Request);

            IndexCreation.CreateIndexes(typeof(UsersByUsername).Assembly, _appHost.Container.Resolve<IDocumentStore>());

            SetupDemoUser();
        }

        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
            _appHost.Container.Resolve<IDocumentStore>().Dispose();
            _appHost.Dispose();
        }

        private void SetupDemoUser()
        {
            using (var session = _appHost.Container.Resolve<IDocumentStore>().OpenSession())
            {
                session.Store(new User { Username = Username, Salt = Salt, Password = PasswordHash });
                session.SaveChanges();
            }
        }

        [Test]
        public void Salt_ThrowsException_When_InvalidUsername()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                client.Get(new SaltRequest { Username = "NonExistent" });

                Assert.Fail("Shouldn't come here");
            }
            catch (WebServiceException webEx)
            {
                Assert.That((HttpStatusCode)webEx.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            }
        }

        [Test]
        public void Salt_Succeed_When_CorrectName()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                var response = client.Get(new SaltRequest { Username = Username });

                Assert.That(response.Salt, Is.EqualTo(Salt));
            }
            catch (WebServiceException webEx)
            {
                Assert.Fail("Shouldn't come here");
            }
        }

        [Test]
        public void Login_ThrowsException_When_InvalidUsername()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                client.Post(new LoginRequest { Username = "NonExistent" });

                Assert.Fail("Shouldn't come here");
            }
            catch (WebServiceException webEx)
            {
                Assert.That((HttpStatusCode)webEx.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            }
        }

        [Test]
        public void Login_ThrowsException_When_InvalidPassword()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                var saltResponse = client.Get(new SaltRequest { Username = Username });
                client.Post(new LoginRequest { Username = Username, Password = HashUtility.Hash("Wrong", saltResponse.Salt) });

                Assert.Fail("Shouldn't come here");
            }
            catch (WebServiceException webEx)
            {
                Assert.That((HttpStatusCode)webEx.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            }
        }

        [Test]
        public void Login_Succeed_When_CorrectCredentials()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                var saltResponse = client.Get(new SaltRequest { Username = Username });
                var loginResponse = client.Post(new LoginRequest { Username = Username, Password = HashUtility.Hash(Password, saltResponse.Salt) });

                Assert.That(loginResponse.Result, Is.Not.Empty);
            }
            catch (WebServiceException webEx)
            {
                Assert.Fail("Shouldn't come here");
            }
        }

        [Test]
        public void LimitedAccess_Succeed_When_LoggedIn()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                var saltResponse = client.Get(new SaltRequest { Username = Username });
                var loginResponse = client.Post(new LoginRequest { Username = Username, Password = HashUtility.Hash(Password, saltResponse.Salt) });

                client.Headers["token"] = loginResponse.Result;
                var limitedResponse = client.Get(new LimitedAccessRequest());

                Assert.That(limitedResponse.Message, Is.Not.Empty);
            }
            catch (WebServiceException webEx)
            {
                Assert.Fail("Shouldn't come here");
            }
        }


        [Test]
        public void LimitedAccess_ThrowsException_When_NotLoggedIn()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                client.Get(new LimitedAccessRequest());

                Assert.Fail("Shouldn't come here");
            }
            catch (WebServiceException webEx)
            {
                Assert.That((HttpStatusCode)webEx.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public void AdminAccess_ThrowsException_With_UserRole()
        {
            try
            {
                var client = new JsonServiceClient(ListeningOn);
                var saltResponse = client.Get(new SaltRequest { Username = Username });
                var loginResponse = client.Post(new LoginRequest { Username = Username, Password = HashUtility.Hash(Password, saltResponse.Salt) });

                client.Headers["token"] = loginResponse.Result;
                client.Get(new AdminAccessRequest());

                Assert.Fail("Shouldn't come here");
            }
            catch (WebServiceException webEx)
            {
                Assert.That((HttpStatusCode)webEx.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            }
        }
    }
}

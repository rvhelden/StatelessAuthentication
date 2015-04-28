using System.Reflection;
using Funq;
using Raven.Client;
using Raven.Client.Embedded;
using Raven.Client.Indexes;
using ServiceStack;
using StatelessAuthentication.Models.Indexes;
using StatelessAuthentication.Models.Models;

namespace StatelessAuthentication.Server
{
    public class AppHost : AppSelfHostBase
    {
        public AppHost() : base("StatelessAuthentication.Server", Assembly.GetExecutingAssembly())
        {
        }

        public override void Configure(Container container)
        {
            var store = new EmbeddableDocumentStore { DataDirectory = "Data" }.Initialize();

            container.Register(store);
            container.Register(c => c.Resolve<IDocumentStore>().OpenSession()).ReusedWithin(ReuseScope.Request);

            IndexCreation.CreateIndexes(typeof(UsersByUsername).Assembly, container.Resolve<IDocumentStore>());

            SetupDemoUser();
        }

        private void SetupDemoUser()
        {
            var session = Instance.Container.Resolve<IDocumentSession>();
            session.Store(new User
            {
                Username = "User", 
                Salt = "/QEbkHkkpM+031q0KerO1A==", 
                Password = "hVvF3Z8/WtZNtDbSofrbnOUqg5tHXHGBPBuR5NlpVXpeRM/V+DABLXy9FGwd5TcQG7d4RJVVhwStR/PGOI7WSw=="
            });
            session.SaveChanges();
        }
    }
}

## StatelessAuthentication

Stateless authentication means that the server doesn't maintains a state like a session to hold the private keys.
The reason for such a technique is so that a client can be redirected to any server without any interruption, because the client has a token that is completely self contained.
Another pro is that the password only has to be sent once over the network.

This is an example implementation of a true stateless authentication protocol.
This implementation uses the following technologies:

- RavenDB (http://ravendb.net/) The NoSQL implementation for .NET
- ServiceStack (https://servicestack.net/) A message based Web Service Framework
- Json Web Token (http://jwt.io/) A simple, clean and secure way to transfere information
- SCrypt (http://en.wikipedia.org/wiki/Scrypt) A password-based key derivation function that is slow and resource demanding

## The process

The process of letting a client login a secure way and obtain a token is done as followed:
1. The client sends the username to the server to obtain the salt associated with the account (Salt is not a secret, a salt is merly there to prevent a rainbowtable attack, and the salt itself isn't a password and thus should't be treated as one https://crackstation.net/hashing-security.htm)
2. The client uses the salt to hash the password provided by the user.
3. The client sends the username and hashed password to the server.
4. The server checks if the user + password exists
5. The server creates a token with username and rol and current date (to ensure a certain lifetime of the token)
6. The server signs the token with a private key
7. The server sends the token back to the client


For every request the client should send the token in the header so the server can verify the identity.
The signature generated with the serverside private key ensures that the token is not tempered with.

## Weakness

The weakness of the implementation is a man in the middle attack, this can be counteracted in 3 ways.
- Use https so a man in the middle attack cannot be executed.
- Limit the lifetime of the cookie
- Protect every major change in a setting like changing password, requires the password and not only the cookie.

## Project structure

### StatelessAuthentication.Client
The client used to communicate to the server, this is a simple project. the only logic in the project is contained in the Program.cs

```cs
var client = new JsonServiceClient(ListeningOn);
var saltResponse = client.Get(new SaltRequest { Username = "User" });

var hash = HashUtility.Hash("welcome", saltResponse.Salt);

var loginResponse = client.Post(new LoginRequest { Username = "User", Password = hash });

client.Headers["token"] = loginResponse.Result;
var limitedResponse = client.Get(new LimitedAccessRequest());
```

### StatelessAuthentication.Models
The models project contains all the requests and responses used for servicestack and some shared logic.

### StatelessAuthentication.Server
This is the servicestack project to serve the client.
For this sample we have created an AuthenticationServices class.

```cs
public class AuthenticationServices : Service
{
    private readonly IDocumentSession _session;

    public AuthenticationServices(IDocumentSession session)
    {
        _session = session;
    }

    public SaltResponse Get(SaltRequest request)
    {
        var projection = _session.Query<User, UsersByUsername>()
            .Where(x => x.Username == request.Username)
            .ProjectFromIndexFieldsInto<UsersByUsername.Projection>()
            .ToList()
            .FirstOrDefault();

        if (projection == null)
            throw HttpError.NotFound("Unknown username and password");

        return new SaltResponse { Salt = projection.Salt };
    }

    public object Post(LoginRequest request)
    {
        var user = _session.Query<User, UsersByUsername>()
						   .FirstOrDefault(u => u.Username == request.Username);

        if (user == null)
            throw HttpError.NotFound("Unknown username and password");

        if (!string.Equals(user.Password, request.Password))
            throw HttpError.NotFound("Unknown username and password");

        var token = JwtTokenUtility.GenerateToken(request.Username, Role.User);

        return new LoginResponse {Result = token};
    }

    [RestrictAccess(Role.User)]
    public object Any(LimitedAccessRequest request)
    {
        return new LimitedAccessResponse { Message = "Welcome" };
    }

    [RestrictAccess(Role.Administrator)]
    public object Any(AdminAccessRequest request)
    {
        return new AdminAccessResponse { Message = "Welcome" };
    }
}
```

The documentsession is injected by funq in the constructor, with an session the is automaticly scoped to the request.

```cs
public AuthenticationServices(IDocumentSession session)
{
    _session = session;
}
```

This is realized by this part in the AppHost.cs thanks to the ReuseWithin (a special extension made by servicestack)

```cs
public override void Configure(Container container)
{
    var store = new EmbeddableDocumentStore { DataDirectory = "Data" }.Initialize();

    container.Register(store);
    container.Register(c => c.Resolve<IDocumentStore>().OpenSession())
			 	.ReusedWithin(ReuseScope.Request);

    IndexCreation.CreateIndexes(typeof(UsersByUsername).Assembly, 
								container.Resolve<IDocumentStore>());

    SetupDemoUser();
}
```



An important class in this project is the RestrictAccessAttribute.
This class inherits from the RequestFilterAttribute, so before the request made by the client is sent to the AuthorizationServices it is first send to this class and gives us the opportunity to determine if the client should have access to the method or class.

```cs
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RestrictAccessAttribute : RequestFilterAttribute
{
    private readonly Role _roles;

    public RestrictAccessAttribute(Role roles)
    {
        _roles = roles;
    }

    public override void Execute(IRequest request, IResponse response, object requestDto)
    {
        var claims = JwtTokenUtility.Validate(request.GetHeader("token"));
        if (claims == null)
        {
            response.ReturnAuthRequired();
            return;
        }

        if (_roles == Role.None)
            return;

        var role = (Role) Enum.Parse(typeof (Role), claims.FindFirst(ClaimTypes.Role).Value);

        //If it doesn't contain the role needed the send AuthRequired
        if ((_roles & role) > 0)
            return;

        response.ReturnAuthRequired();
    }
}
```

The private key used is for demo purpose always generated at start in JwtTokenUtility in the static constructor.
For production this should be replaced with your own private key.

```cs
static JwtTokenUtility()
{
    //The private key used to secure the token, this should be a static shared key
    //And not an random key like this, but this is fine for demo purpose
	var randomKey = Convert.FromBase64String(HashUtility.GenerateRandomBytes(64));

    var symetricSecurityKey = new InMemorySymmetricSecurityKey(randomKey);
    Credentials = new SigningCredentials(symetricSecurityKey, 
										 "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", 
										 "http://www.w3.org/2001/04/xmlenc#sha256");
    ValidationParameters = new TokenValidationParameters 
	{ 
		IssuerSigningKey = symetricSecurityKey, 
		ValidateAudience = false, 
		ValidIssuer = "issuer" 
	};
}
```

### StatelessAuthentication.Tests
Here is demonstrated how it behaves.

```cs
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
            var loginResponse = client.Post(new LoginRequest 
			{ 
				Username = Username, 
				Password = HashUtility.Hash(Password, saltResponse.Salt) 
			});

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
            var loginResponse = client.Post(new LoginRequest 
			{ 
				Username = Username, 
				Password = HashUtility.Hash(Password, saltResponse.Salt) 
			});

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
            var loginResponse = client.Post(new LoginRequest 
			{ 
				Username = Username, 
				Password = HashUtility.Hash(Password, saltResponse.Salt) 
			});

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
```
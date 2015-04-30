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

### StatelessAuthentication.Models
The models project contains all the requests and responses used for servicestack and some shared logic.

### StatelessAuthentication.Server
This is the servicestack project to serve the client.
An important class in this project is the RestrictAccessAttribute.
This class inherits from the RequestFilterAttribute, so before the request made by the client is sent to the AuthorizationServices it is first send to this class and gives us the opportunity to determine if the client should have access to the method or class.

The private key used is for demo purpose always generated at start in JwtTokenUtility.
For production this should be replaced with an static private key.

### StatelessAuthentication.Tests
Here is demonstrated how it behaves.
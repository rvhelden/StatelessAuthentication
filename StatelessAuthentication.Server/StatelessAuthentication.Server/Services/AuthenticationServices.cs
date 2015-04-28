using System.Linq;
using Raven.Client;
using Raven.Client.Linq;
using ServiceStack;
using StatelessAuthentication.Models.Indexes;
using StatelessAuthentication.Models.Messages;
using StatelessAuthentication.Models.Models;
using StatelessAuthentication.Server.Attributes;
using StatelessAuthentication.Server.Common;
using StatelessAuthentication.Server.Utilities;

namespace StatelessAuthentication.Server.Services
{
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
            var user = _session.Query<User, UsersByUsername>().FirstOrDefault(u => u.Username == request.Username);

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
}
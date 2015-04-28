using System;
using System.Security.Claims;
using ServiceStack;
using ServiceStack.Web;
using StatelessAuthentication.Server.Common;
using StatelessAuthentication.Server.Utilities;

namespace StatelessAuthentication.Server.Attributes
{
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
}

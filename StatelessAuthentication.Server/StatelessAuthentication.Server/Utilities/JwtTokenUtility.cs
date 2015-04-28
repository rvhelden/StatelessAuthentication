using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using StatelessAuthentication.Models.Utilities;
using StatelessAuthentication.Server.Common;

namespace StatelessAuthentication.Server.Utilities
{
    public static class JwtTokenUtility
    {
        private static readonly InMemorySymmetricSecurityKey SymetricSecurityKey;
        private static readonly SigningCredentials Credentials;
        private static readonly TokenValidationParameters ValidationParameters;

        static JwtTokenUtility()
        {
            SymetricSecurityKey = new InMemorySymmetricSecurityKey(Convert.FromBase64String(HashUtility.GenerateRandomBytes(64)));
            Credentials = new SigningCredentials(SymetricSecurityKey, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://www.w3.org/2001/04/xmlenc#sha256");
            ValidationParameters = new TokenValidationParameters { IssuerSigningKey = SymetricSecurityKey, ValidateAudience = false, ValidIssuer = "issuer" };
        }

        /// <summary>
        /// Generates the token.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="role">The role.</param>
        /// <returns></returns>
        public static string GenerateToken(string username, Role role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Role, role.ToString()) }),
                TokenIssuerName = "issuer",
                Lifetime = new Lifetime(now, now.AddHours(1)),
                SigningCredentials = Credentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Validates the token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public static ClaimsPrincipal Validate(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            return tokenHandler.ValidateToken(token, ValidationParameters, out securityToken);
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Text;
using CryptSharp.Utility;

namespace StatelessAuthentication.Models.Utilities
{
    public static class HashUtility
    {
        /// <summary>
        /// Generate a RNG string of a certain length
        /// </summary>
        /// <param name="saltLength">The number of bytes to generate</param>
        /// <returns>A base64 encoded random bytes</returns>
        public static string GenerateRandomBytes(int saltLength)
        {
            var salt = new byte[saltLength];

            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            return Convert.ToBase64String(salt);
        }

        /// <summary>
        /// Hash a password with SCrypt
        /// </summary>
        /// <param name="password">Password to hash</param>
        /// <param name="salt">A base64 encoded salt to use for the hashing</param>
        /// <returns>A hashed password</returns>
        public static string Hash(string password, string salt)
        {
            var encodedPassword = Encoding.UTF8.GetBytes(password);
            var encodedSalt = Convert.FromBase64String(salt);

            var derivedKey = SCrypt.ComputeDerivedKey(encodedPassword, encodedSalt, (int)Math.Pow(2, 15), 8, 1, null, 64);
            return Convert.ToBase64String(derivedKey);
        }
    }
}

using System;

namespace StatelessAuthentication.Server.Common
{
    [Flags]
    public enum Role
    {
        None = 0,
        User = 1,
        Administrator = 2,
        SuperAdministrator = 4
    }
}

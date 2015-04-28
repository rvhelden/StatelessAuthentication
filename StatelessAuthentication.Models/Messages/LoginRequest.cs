using ServiceStack;

namespace StatelessAuthentication.Models.Messages
{
    [Route("/AuthorizationServices/Login", Verbs = "POST")]
    public class LoginRequest : IReturn<LoginResponse>
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class LoginResponse
    {
        public string Result { get; set; }
    }
}

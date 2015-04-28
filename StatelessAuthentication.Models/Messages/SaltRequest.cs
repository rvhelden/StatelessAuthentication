using ServiceStack;

namespace StatelessAuthentication.Models.Messages
{
    [Route("/AuthorizationServices/GetSalt/{Username}", Verbs = "GET")]
    public class SaltRequest : IReturn<SaltResponse>
    {
        public string Username { get; set; }
    }

    public class SaltResponse
    {
        public string Salt { get; set; }
    }
}

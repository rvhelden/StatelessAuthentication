using ServiceStack;

namespace StatelessAuthentication.Models.Messages
{
    [Route("/AuthorizationServices/LimitedAccess")]
    public class LimitedAccessRequest : IReturn<LimitedAccessResponse>
    {
    }

    public class LimitedAccessResponse
    {
        public string Message { get; set; }
    }
}

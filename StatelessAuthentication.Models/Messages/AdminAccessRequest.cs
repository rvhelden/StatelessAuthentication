using ServiceStack;

namespace StatelessAuthentication.Models.Messages
{
    [Route("/AuthorizationServices/AdminAccess")]
    public class AdminAccessRequest : IReturn<AdminAccessResponse>
    {
    }

    public class AdminAccessResponse
    {
        public string Message { get; set; }
    }
}

using System.Linq;
using Raven.Abstractions.Indexing;
using Raven.Client.Indexes;
using StatelessAuthentication.Models.Models;

namespace StatelessAuthentication.Models.Indexes
{
    public class UsersByUsername : AbstractIndexCreationTask<User>
    {
        public class Projection
        {
            public string Salt { get; set; }
        }

        public UsersByUsername()
        {
            Map = users => from user in users select new { user.Username };

            //Used to store the salt with the username index, this ensures that only 1 query is needed to query a username and retrieve the salt associated with the username
            Store(x => x.Salt, FieldStorage.Yes);
        }
    }
}

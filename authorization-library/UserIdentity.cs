using System.Security.Principal;

namespace authorization_library;

public class UserIdentity : IIdentity
{
    public UserIdentity(JwtBody user)
    {
        User = user;
    }
    public JwtBody User { get; }
    public string? AuthenticationType { get; }
    public bool IsAuthenticated { get; }
    public string? Name { get; }
}
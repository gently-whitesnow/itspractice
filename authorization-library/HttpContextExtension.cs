using Microsoft.AspNetCore.Http;

namespace authorization_library;

public static class HttpContextExtension
{
    public static JwtBody GetUser(this HttpContext requestContext)
    {
        var identity = requestContext.User.Identity as UserIdentity;
        return identity?.User;
    }
}
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;

namespace authorization_library;

[PublicAPI]
public sealed class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JwtManager _jwtManager;

    public AuthenticationMiddleware(RequestDelegate next, JwtManager jwtManager)
    {
        this._next = next;
        _jwtManager = jwtManager;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        await _jwtManager.ValidateAndUpdateTokenAsync(context);
        await _next.Invoke(context);
    }
}
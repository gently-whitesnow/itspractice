using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace authorization_library;

public sealed class CapAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JwtManager _jwtManager;

    public CapAuthenticationMiddleware(RequestDelegate next, JwtManager jwtManager)
    {
        this._next = next;
        _jwtManager = jwtManager;
    }
 
    public async Task InvokeAsync(HttpContext context)
    {
        await _jwtManager.CheckAndUpdateTokenAsync(context);
        await _next.Invoke(context);
    }
}
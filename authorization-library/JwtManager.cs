using System;
using System.Security.Principal;
using System.Threading.Tasks;
using ATI.Services.Common.Caching.Redis;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace authorization_library;

public sealed class JwtManager : JwtValidator
{
    private readonly RedisCache _redisClient;
    private readonly JwtOptions _jwtOptions;
    private readonly IAuthAdapter _authAdapter;

    public JwtManager(IOptions<JwtOptions> jwtOptions, RedisProvider redisProvider,
        IAuthAdapter authAdapter) : base(jwtOptions.Value)
    {
        _redisClient = redisProvider.GetCache("Default");
        _jwtOptions = jwtOptions.Value;
        _authAdapter = authAdapter;
    }

    public async Task CheckAndUpdateTokenAsync(HttpContext httpContext)
    {
        var rowToken = httpContext.Request.Cookies[_jwtOptions.AuthCookie];
        if (string.IsNullOrEmpty(rowToken))
            return;
        
        var token = ValidateToken(rowToken);
        if (token == null)
            return;

        var rawRealiseUnixDate = token.FindFirst("RealiseUnixDate");
        var userId = token.FindFirst("UserId");
        var refreshToken = token.FindFirst("RefreshToken");
        var accessToken = token.FindFirst("AccessToken");

        if (rawRealiseUnixDate == null || userId == null || refreshToken == null || accessToken == null
            || !long.TryParse(rawRealiseUnixDate.Value, out var realiseUnixDate))
            return;

        var getOperation = await _redisClient.GetAsync<string>(
            userId.Value + ":" + refreshToken.Value, "redis", TimeSpan.FromSeconds(3));
        if (!getOperation.Success || string.IsNullOrEmpty(getOperation.Value))
            return;
        
        var jwtBody = new JwtBody
        {
            UserId = int.Parse(userId.Value),
            RefreshToken = new Guid(refreshToken.Value),
            AccessToken = new Guid(accessToken.Value),
            RealiseUnixTime = realiseUnixDate
        };
        var nowUnixTimeSeconds = new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();
        
        if (realiseUnixDate + _jwtOptions.AccessTokenExpireMin * 60 > nowUnixTimeSeconds)
        {
            httpContext.User = new GenericPrincipal(new UserIdentity(jwtBody), Array.Empty<string>());
            return;
        }
        
        
        var deleteOperation = await _redisClient.DeleteAsync(jwtBody.UserId + ":" + jwtBody.RefreshToken, "redis",
            TimeSpan.FromSeconds(3));
        if (!deleteOperation.Success)
            return;
        
        jwtBody.RefreshToken = Guid.NewGuid();
        
        var updateOperation = await _authAdapter.UpdateTokenAsync(jwtBody);
        if (!updateOperation.Success)
            return;
        
        var insertOperation = await _redisClient.InsertAsync(jwtBody.AccessToken.ToString(),
            jwtBody.UserId + ":" + jwtBody.RefreshToken, TimeSpan.FromMinutes(_jwtOptions.JwtTokenExpireMin), "redis");
        if (!insertOperation.Success)
            return;
        
        httpContext.User = new GenericPrincipal(new UserIdentity(jwtBody), Array.Empty<string>());
        
        httpContext.Response.Cookies.Append(_jwtOptions.AuthCookie, updateOperation.Value.Token, new CookieOptions
        {
            Domain = httpContext.Request.Host.Host,
            Expires = DateTimeOffset.FromUnixTimeSeconds(updateOperation.Value.ExpiresAt),
        });
    }
}
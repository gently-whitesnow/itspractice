using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using ATI.Services.Common.Caching.Redis;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace authorization_library;

public sealed class JwtManager : JwtValidator
{
    private const string RedisMetricName = "Redis";
    private const string RedisCacheName = "Default";

    private readonly RedisCache _redisClient;
    private readonly JwtOptions _jwtOptions;
    private readonly IAuthAdapter _authAdapter;

    public JwtManager(IOptions<JwtOptions> jwtOptions, RedisProvider redisProvider,
        IAuthAdapter authAdapter) : base(jwtOptions.Value)
    {
        _redisClient = redisProvider.GetCache(RedisCacheName);
        _jwtOptions = jwtOptions.Value;
        _authAdapter = authAdapter;
    }

    public async Task ValidateAndUpdateTokenAsync(HttpContext httpContext)
    {
        var jwtBody = await ValidateTokenAsync(httpContext.Request.Cookies);
        if (jwtBody == null)
            return;

        var genericPrincipal = await UpdateTokenAsync(jwtBody);
        if (genericPrincipal == null)
            return;

        httpContext.User = genericPrincipal;
    }

    private async Task<JwtBody?> ValidateTokenAsync(IRequestCookieCollection cookieCollection)
    {
        var claimsPrincipal = GetClaimsPrincipal(cookieCollection);
        if (claimsPrincipal == null)
            return null;

        return await VerifyContentAsync(claimsPrincipal);
    }

    private ClaimsPrincipal? GetClaimsPrincipal(IRequestCookieCollection cookieCollection)
    {
        var rawToken = cookieCollection[_jwtOptions.AuthCookie];
        if (string.IsNullOrEmpty(rawToken))
            return null;

        return ValidateAndReadToken(rawToken);
    }

    private async Task<JwtBody?> VerifyContentAsync(ClaimsPrincipal claimsPrincipal)
    {
        var rawRealiseUnixDate = claimsPrincipal.FindFirst("RealiseUnixDate");
        var userId = claimsPrincipal.FindFirst("UserId");
        var refreshToken = claimsPrincipal.FindFirst("RefreshToken");
        var accessToken = claimsPrincipal.FindFirst("AccessToken");

        if (rawRealiseUnixDate == null || userId == null || refreshToken == null || accessToken == null
            || !long.TryParse(rawRealiseUnixDate.Value, out var realiseUnixDate))
            return null;

        var accessTokenOperation = await _redisClient.GetAsync<string>(
            userId.Value + ":" + refreshToken.Value, RedisMetricName, TimeSpan.FromSeconds(3));
        if (!accessTokenOperation.Success || string.IsNullOrEmpty(accessTokenOperation.Value)
                                          || accessTokenOperation.Value != accessToken.Value)
            return null;

        return new JwtBody
        {
            UserId = int.Parse(userId.Value),
            RefreshToken = new Guid(refreshToken.Value),
            AccessToken = new Guid(accessToken.Value),
            RealiseUnixTime = realiseUnixDate
        };
    }

    private async Task<GenericPrincipal?> UpdateTokenAsync(JwtBody jwtBody)
    {
        var nowUnixTimeSeconds = new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();

        if (jwtBody.RealiseUnixTime + _jwtOptions.AccessTokenExpireMin * 60 > nowUnixTimeSeconds)
        {
            return new GenericPrincipal(new UserIdentity(jwtBody), Array.Empty<string>());
        }

        // TODO удаления и добавление токена в редис происходит в сервисе авторизации
        // этот сервис также прикрепляет куки к запросу
        var freshJwtBodyOperation = await _authAdapter.UpdateTokenAsync(jwtBody);
        if (!freshJwtBodyOperation.Success)
            return null;

        return new GenericPrincipal(new UserIdentity(freshJwtBodyOperation.Value), Array.Empty<string>());
    }
}
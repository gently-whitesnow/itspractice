using ATI.Services.Common.Caching.Redis;
using ATI.Services.Common.Extensions;
using ATI.Services.Common.Initializers;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace authorization_library;

[PublicAPI]
public static class CapAuthenticationExtension
{
   
    public static void AddCapAuthentication(this IServiceCollection services)
    {
        
        services.ConfigureByName<CacheManagerOptions>();
        services.AddSingleton<RedisProvider>();
        services.AddTransient<RedisInitializer>();
        
        services.ConfigureByName<JwtOptions>();
        services.AddSingleton<JwtManager>();
    }
    
    public static void UseCapAuthentication(this IApplicationBuilder app)
    {
        app.UseCookiePolicy(new CookiePolicyOptions
        {
            MinimumSameSitePolicy = SameSiteMode.Strict,
            HttpOnly = HttpOnlyPolicy.Always,
            Secure = CookieSecurePolicy.Always
        });
        app.UseMiddleware<CapAuthenticationMiddleware>();
    }
}
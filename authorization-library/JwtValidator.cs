using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace authorization_library;

public class JwtValidator
{
    private JwtOptions _jwtOptions;
    protected JwtValidator(JwtOptions options)
    {
        _jwtOptions = options;
    }
    
    protected ClaimsPrincipal? ValidateToken(string token)
    {
        var publicKey = Convert.FromBase64String(_jwtOptions.PublicKey);
        
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _jwtOptions.Issuer,
            ValidAudience = _jwtOptions.Audience,
            IssuerSigningKey = new RsaSecurityKey(rsa),
            CryptoProviderFactory = new CryptoProviderFactory()
            {
                CacheSignatureProviders = false
            }
        };
        try
        {
            return new JwtSecurityTokenHandler()
                .ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }
}
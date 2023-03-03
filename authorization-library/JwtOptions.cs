namespace authorization_library;

public class JwtOptions
{
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int JwtTokenExpireMin { get; set; }
    
    public int AccessTokenExpireMin { get; set; }
    public string AuthCookie { get; set; }
    public string PublicKey { get; set; }
}
namespace authorization_library;

public class JwtBody : JwtRequest
{
    public long RealiseUnixTime { get; set; }
}
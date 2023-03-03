using System;
using System.ComponentModel.DataAnnotations;

namespace authorization_library;

public class JwtRequest
{
    [Required] public int UserId { get; set; }
    [Required] public Guid RefreshToken { get; set; }
    [Required] public Guid AccessToken { get; set; }
}
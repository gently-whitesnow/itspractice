using System.Threading.Tasks;
using ATI.Services.Common.Behaviors;

namespace authorization_library;

public interface IAuthAdapter
{
    public Task<OperationResult<JwtResponse>> UpdateTokenAsync(JwtRequest jwtRequest);
}
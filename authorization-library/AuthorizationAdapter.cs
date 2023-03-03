using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ATI.Services.Common.Behaviors;
using ATI.Services.Common.Serializers.SystemTextJsonSerialization;
using JetBrains.Annotations;

namespace authorization_library;

[PublicAPI]
public sealed class AuthorizationAdapter : IAuthAdapter, IDisposable
{
    private readonly JsonSerializerOptions _jsonSerializerOptions = new()
    {
        PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
    };

    private readonly HttpClient _httpClient;

    public AuthorizationAdapter(string authorizationServiceAddress)
    {
        _httpClient = new HttpClient {BaseAddress = new Uri(authorizationServiceAddress)};
    }

    public async Task<OperationResult<JwtResponse>> UpdateTokenAsync(JwtRequest jwtRequest)
    {
        try
        {
            const string urlTemplate = "_internal/update";

            var content = JsonSerializer.Serialize(jwtRequest, _jsonSerializerOptions);

            var response = await _httpClient.PostAsync(urlTemplate, new StringContent(content, Encoding.UTF8));

            if (!response.IsSuccessStatusCode)
            {
                return new OperationResult<JwtResponse>(response.StatusCode);
            }

            var taskResponse =
                JsonSerializer.Deserialize<JwtResponse>(await response.Content.ReadAsStringAsync(), _jsonSerializerOptions);
            return new OperationResult<JwtResponse>(taskResponse);
        }
        catch
        {
            return new OperationResult<JwtResponse>(ActionStatus.ExternalServerError);
        }
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}
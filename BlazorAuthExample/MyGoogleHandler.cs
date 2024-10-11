using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace BlazorAuthExample;

public class MyGoogleHandler : Microsoft.AspNetCore.Authentication.Google.GoogleHandler
{
    private readonly GoogleHandler GoogleHandler;

    public MyGoogleHandler(IOptionsMonitor<Microsoft.AspNetCore.Authentication.Google.GoogleOptions> options, ILoggerFactory logger, UrlEncoder encoder, GoogleHandler googleHandler) : base(options, logger, encoder)
    {
        GoogleHandler = googleHandler;
    }

    protected override Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        return base.CreateTicketAsync(identity, properties, tokens);
    }

    protected override Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
    {
        return base.ExchangeCodeAsync(context);
    }

    protected override void GenerateCorrelationId(AuthenticationProperties properties)
    {
        base.GenerateCorrelationId(properties);
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return base.HandleAuthenticateAsync();
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        return base.HandleChallengeAsync(properties);
    }

    protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        return base.HandleRemoteAuthenticateAsync();
    }

    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        return base.BuildChallengeUrl(properties, redirectUri);
    }

    protected override Task InitializeHandlerAsync()
    {
        return base.InitializeHandlerAsync();
    }

}

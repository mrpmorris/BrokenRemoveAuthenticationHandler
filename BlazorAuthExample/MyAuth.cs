using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace BlazorAuthExample;

public class MyAuthOptions : RemoteAuthenticationOptions
{
    public MyAuthOptions()
    {
        CallbackPath = new PathString("/signin-myauth");
    }
}

public class MyAuthHandler : RemoteAuthenticationHandler<MyAuthOptions>
{
    private readonly IDataProtectionProvider DataProtectionProvider;

    public MyAuthHandler(
        IOptionsMonitor<MyAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IDataProtectionProvider dataProtectionProvider) : base(options, logger, encoder)
    {
        DataProtectionProvider = dataProtectionProvider ?? throw new ArgumentNullException(nameof(dataProtectionProvider));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            if (properties.Items.TryGetValue(".redirect", out string? redirect))
                properties.RedirectUri = redirect;
            else
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }

        string challengeUrl = BuildChallengeUrl(properties);
        Context.Response.Redirect(challengeUrl);
        return Task.CompletedTask;
    }

    private string BuildChallengeUrl(AuthenticationProperties properties)
    {
        GenerateCorrelationId(properties);

        var stateDictionary = new Dictionary<string, string?>();

        if (properties.Items.TryGetValue("XsrfId", out string? xsrfId))
            stateDictionary["XsrfId"] = xsrfId;

        stateDictionary[".xsrf"] = properties.Items[".xsrf"];

        if (!properties.Items.TryGetValue(".redirect", out string? redirect))
            redirect = properties.RedirectUri;
        stateDictionary[".redirect"] = redirect;

        stateDictionary["LoginProvider"] = "MyAuth";

        string stateJsonProtected = ProtectState(stateDictionary);
        string endpoint = "/my-sign-in-page";
        string result = QueryHelpers.AddQueryString(endpoint, "state", stateJsonProtected);
        return result;
    }

    protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var nameIdentifierClaim = new Claim(ClaimTypes.NameIdentifier, "mrpmorris@gmail.com", ClaimTypes.NameIdentifier, "myauth", "myauth");
        var identity = new ClaimsIdentity([nameIdentifierClaim], "myauth");
        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(principal, "myauth");

        if (!Context.Request.Form.TryGetValue("State", out StringValues stateJsonProtected)
            || !UnprotectState(stateJsonProtected, out Dictionary<string, string?> stateDictionary))
        {
            return Task.FromResult(HandleRequestResult.Fail("State was missing or invalid."));
        }

        ticket.Properties.RedirectUri = stateDictionary[".redirect"];
        foreach (var kvp in stateDictionary)
            ticket.Properties.Items[kvp.Key] = kvp.Value;


        if (!ValidateCorrelationId(ticket.Properties))
            return Task.FromResult(HandleRequestResult.Fail("Correlation failed."));

        return Task.FromResult(HandleRequestResult.Success(ticket));
    }

    private bool UnprotectState(
        string? stateJsonProtected,
        [NotNullWhen(true)]
        out Dictionary<string, string?> state)
    {
        if (stateJsonProtected is null)
        {
            state = null;
            return false;
        }

        try
        {
            string stateJson = GetDataProtector().Unprotect(stateJsonProtected);
            state = JsonSerializer.Deserialize<Dictionary<string, string?>>(stateJson)!;
            return state is not null;
        }
        catch (CryptographicException)
        {
            state = null;
            return false;
        }
    }

    private IDataProtector GetDataProtector() =>
        DataProtectionProvider.CreateProtector("MyAuth");

    private string ProtectState(Dictionary<string, string?> stateDictionary)
    {
        string stateJson = JsonSerializer.Serialize(stateDictionary);
        string stateJsonProtected = GetDataProtector().Protect(stateJson);
        return stateJsonProtected;
    }


}

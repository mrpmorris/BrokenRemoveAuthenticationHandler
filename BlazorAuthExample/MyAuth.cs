using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;
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
        var stateDictionary = new Dictionary<string, string?>();

        if (properties.Items.TryGetValue("XsrfId", out string? xsrfId))
            stateDictionary["XsrfId"] = xsrfId;

        if (!properties.Items.TryGetValue(".redirect", out string? redirect))
            redirect = properties.RedirectUri;
        stateDictionary["MyAuth_Redirect"] = redirect;

        stateDictionary["LoginProvider"] = "MyAuth";

        string stateJson = JsonSerializer.Serialize(stateDictionary);
        string stateJsonProtected = GetDataProtector().Protect(stateJson);

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

        string stateJsonProtected = Context.Request.Form["state"]!;
        string stateJson = GetDataProtector().Unprotect(stateJsonProtected);
        var stateDictionary = JsonSerializer.Deserialize<Dictionary<string, string?>>(stateJson)!;

        ticket.Properties.RedirectUri = stateDictionary["MyAuth_Redirect"];
        foreach(var kvp in stateDictionary.Where(x => !x.Key.StartsWith("MyAuth_")))
            ticket.Properties.Items[kvp.Key] = kvp.Value;

        return Task.FromResult(HandleRequestResult.Success(ticket));
    }

    private IDataProtector GetDataProtector() =>
        DataProtectionProvider.CreateProtector("MyAuth");
}

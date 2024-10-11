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
            properties.RedirectUri = base.OriginalPathBase + base.OriginalPath + base.Request.QueryString;

        string challengeUrl = BuildChallengeUrl(properties);
        Context.Response.Redirect(challengeUrl);
        return Task.CompletedTask;
    }

    private string BuildChallengeUrl(AuthenticationProperties properties)
    {
        string endpoint = "/my-sign-in-page";
        var dictionary = new Dictionary<string, StringValues>();
        dictionary["RedirectUri"] = properties.RedirectUri ?? "";

        string itemsJson = JsonSerializer.Serialize(properties.Items);
        string itemsProtectedString = GetDataProtector().Protect(itemsJson);
        dictionary.Add("state", itemsProtectedString);

        string result = QueryHelpers.AddQueryString(endpoint, dictionary);
        return result;
    }

    protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var nameIdentifierClaim = new Claim(ClaimTypes.NameIdentifier, "mrpmorris@gmail.com", ClaimTypes.NameIdentifier, "myauth", "myauth");
        var identity = new ClaimsIdentity([nameIdentifierClaim], "myauth");
        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(principal, "myauth");

        string protectedState = Context.Request.Form["state"]!;
        string itemsJson = GetDataProtector().Unprotect(protectedState);
        var stateDictionary = JsonSerializer.Deserialize<Dictionary<string, string>>(itemsJson)!;
        foreach(var kvp in stateDictionary)
            ticket.Properties.Items[kvp.Key] = kvp.Value;

        return Task.FromResult(HandleRequestResult.Success(ticket));
    }

    private IDataProtector GetDataProtector() =>
        DataProtectionProvider.CreateProtector("MyAuth");
}

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

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
    public MyAuthHandler(
        IOptionsMonitor<MyAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var url = "/my-sign-in-page?RedirectUri=" + Uri.EscapeDataString(properties.RedirectUri ?? "");

        if (properties.Items.TryGetValue("XsrfId", out var xsrfId))
        {
            url += "&xsrfId=" + xsrfId;
        }

        Context.Response.Redirect(url);

        return Task.CompletedTask;
    }

    protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var nameIdentifierClaim = new Claim(ClaimTypes.NameIdentifier, "mrpmorris@gmail.com", ClaimTypes.NameIdentifier, "myauth", "myauth");
        var identity = new ClaimsIdentity([nameIdentifierClaim], "myauth");
        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(principal, "myauth");

        ticket.Properties.RedirectUri = Context.Request.Form["RedirectUri"];
        ticket.Properties.Items.Add("LoginProvider", "myauth");
        if (Context.Request.Form.TryGetValue("XsrfId", out var xsrfId))
        {
            ticket.Properties.Items.Add("XsrfId", xsrfId);
        }

        return Task.FromResult(HandleRequestResult.Success(ticket));
    }
}

using IdentityModel.HttpSigning;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Owin;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class HttpSignatureValidationMiddleware
    {
        private readonly Func<IDictionary<string, object>, Task> _next;
        private readonly HttpSignatureValidationOptions _options;
        private readonly ILogger _logger;

        public HttpSignatureValidationMiddleware(Func<IDictionary<string, object>, Task> next, IAppBuilder app, HttpSignatureValidationOptions options)
        {
            if (next == null) throw new ArgumentNullException("next");
            if (options == null) throw new ArgumentNullException("options");

            options.Validate();

            _next = next;
            _options = options;

            Logging.SetLogger(_logger = app.CreateLogger<HttpSignatureValidationMiddleware>());
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            var token = await _options.TokenProvider(env);
            if (token != null)
            {
                _logger.WriteVerbose("Token obtained from TokenProvider");

                var valid = await _options.SignatureValidator(env, _options.RequestValidationOptions, token);
                if (valid == false)
                {
                    _logger.WriteVerbose("SignatureValidator failed to validate token");

                    var ctx = new OwinContext(env);

                    ctx.Response.StatusCode = 401;
                    var value = HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme + " error=\"invalid_token\"";
                    ctx.Response.Headers.Add("WWW-Authenticate", new string[] { value });

                    return;
                }
                else
                {
                    _logger.WriteVerbose("SignatureValidator successfully validated token");
                }
            }
            else
            {
                _logger.WriteVerbose("No token obtained from TokenProvider");
            }

            await _next(env);
        }
    }
}

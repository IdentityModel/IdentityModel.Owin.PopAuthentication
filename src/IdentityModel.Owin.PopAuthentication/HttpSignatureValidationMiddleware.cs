using IdentityModel.HttpSigning;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class HttpSignatureValidationMiddleware
    {
        private readonly Func<IDictionary<string, object>, Task> _next;
        private readonly HttpSignatureValidationOptions _options;

        public HttpSignatureValidationMiddleware(Func<IDictionary<string, object>, Task> next, HttpSignatureValidationOptions options)
        {
            if (next == null) throw new ArgumentNullException("next");
            if (options == null) throw new ArgumentNullException("options");

            options.Validate();

            _next = next;
            _options = options;
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            var token = await _options.TokenProvider(env);
            if (token != null)
            {
                var valid = await _options.SignatureValidator(env, token);
                if (valid == false)
                {
                    var ctx = new OwinContext(env);

                    ctx.Response.StatusCode = 401;
                    var value = HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme + " error=\"invalid_token\"";
                    ctx.Response.Headers.Add("WWW-Authenticate", new string[] { value });

                    return;
                }
            }

            await _next(env);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using IdentityModel.Owin.PopAuthentication;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Testing;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class WebApiPipeline : OwinPipeline
    {
        public const string Endpoint = "https://api-server/test";

        public WebApiPipeline(HttpMessageHandler idSvrBackchannel)
        {
            AuthenticationOptions.BackchannelHttpHandler = idSvrBackchannel;
            AuthenticationOptions.IntrospectionHttpHandler = idSvrBackchannel;

            AuthenticationOptions.AuthenticationType = "PoP";
            AuthenticationOptions.Authority = IdentityServerPipeline.Authority;
            AuthenticationOptions.RequiredScopes = new string[] { "api1" };
            AuthenticationOptions.ClientId = "api1";
            AuthenticationOptions.ClientSecret = "secret";

            AuthenticationOptions.TokenProvider = new OAuthBearerAuthenticationProvider
            {
                OnRequestToken = async ctx =>
                {
                    if (AuthenticationOptions.AuthenticationType == "PoP")
                    {
                        ctx.Token = await DefaultPopTokenProvider.GetAccessTokenFromPopTokenAsync(ctx.OwinContext.Environment);
                    }
                }
            };

            OnConfiguration += WebApiPipeline_OnConfiguration;
        }

        public IdentityServerBearerTokenAuthenticationOptions AuthenticationOptions { get; set; } = new IdentityServerBearerTokenAuthenticationOptions();
        public HttpSignatureValidationOptions SignatureValidationOptions { get; set; } = new HttpSignatureValidationOptions();

        private void WebApiPipeline_OnConfiguration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            app.UseIdentityServerBearerTokenAuthentication(AuthenticationOptions);
            //app.Use(async (ctx, next) =>
            //{
            //    var pop = ctx.Request.Headers["Authorization"];

            //    await next();
            //});
            app.UseHttpSignatureValidation(SignatureValidationOptions);
            
            app.Run(ctx =>
            {
                if (ctx.Authentication.User != null &&
                    ctx.Authentication.User.Identity != null &&
                    ctx.Authentication.User.Identity.IsAuthenticated)
                {
                    ctx.Response.StatusCode = 200;
                }
                else
                {
                    ctx.Response.StatusCode = 403;
                }

                return Task.FromResult(0);
            });
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Testing;
using Owin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication.Tests.IntegrationTests
{
    public class JwtBearerTokenAuthenticationPipeline : OwinPipeline
    {
        public JwtBearerTokenAuthenticationPipeline()
        {
            OnStartup += JwtBearerTokenAuthenticationPipeline_OnStartup;
        }

        private void JwtBearerTokenAuthenticationPipeline_OnStartup(IAppBuilder app)
        {
            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions {
                AllowedAudiences = new string[] { "audience" },
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                {
                    new X509CertificateSecurityTokenProvider("issuer", SigningCertificate.Cert)
                },
                Provider = new OAuthBearerAuthenticationProvider
                {
                    OnRequestToken = async ctx =>
                    {
                        ctx.Token = await DefaultPopTokenProvider.GetAccessTokenFromPopTokenAsync(ctx.OwinContext.Environment);
                    }
                }
            });

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
                    ctx.Response.StatusCode = 401;
                }

                return Task.FromResult(0);
            });
        }
    }
}

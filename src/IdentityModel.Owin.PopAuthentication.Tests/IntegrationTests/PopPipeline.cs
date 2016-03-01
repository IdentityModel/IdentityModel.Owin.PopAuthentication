// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.Owin.Testing;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication.Tests.IntegrationTests
{
    public class PopPipeline : OwinPipeline
    {
        public PopPipeline(HttpSignatureValidationOptions options = null)
        {
            Options = options;
            OnStartup += PopPipeline_OnStartup;
        }

        public HttpSignatureValidationOptions Options { get; set; }

        private void PopPipeline_OnStartup(IAppBuilder app)
        {
            app.UseHttpSignatureValidation(Options);
            app.Run(ctx =>
            {
                ctx.Response.StatusCode = 200;
                return Task.FromResult(0);
            });
        }
    }
}

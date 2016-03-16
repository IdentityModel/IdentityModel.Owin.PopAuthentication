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

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class OwinPipeline : IDisposable
    {
        public TestServer Server { get; private set; }
        public HttpMessageHandler Handler { get; private set; }

        public void Dispose()
        {
            Server.Dispose();
        }

        public event Action<IAppBuilder> OnConfiguration = x => { };
        public event Func<IDictionary<string, object>, Task> OnPreProcessRequest = x => Task.FromResult(0);
        public event Func<IDictionary<string, object>, Task> OnPostProcessRequest = x => Task.FromResult(0);

        public virtual void Initialize()
        {
            Server = TestServer.Create(Configuration);
            Handler = Server.Handler;
        }

        public void Configuration(IAppBuilder app)
        {
            app.Use(async (ctx, next) =>
            {
                await OnPreProcessRequest(ctx.Environment);
                await next();
            });

            OnConfiguration(app);

            app.Use(async (ctx, next) =>
            {
                await OnPostProcessRequest(ctx.Environment);
                await next();
            });
        }
    }
}

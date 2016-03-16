// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.Core.ViewModels;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using Owin;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class IdentityServerPipeline : OwinPipeline
    {
        public const string Authority = "https://server";
        public const string LoginPage = "https://server/login";
        public const string PermissionsPage = "https://server/permissions";

        public const string DiscoveryEndpoint = "https://server/.well-known/openid-configuration";
        public const string DiscoveryKeysEndpoint = "https://server/.well-known/openid-configuration/jwks";
        public const string AuthorizeEndpoint = "https://server/connect/authorize";
        public const string TokenEndpoint = "https://server/connect/token";
        public const string RevocationEndpoint = "https://server/connect/revocation";
        public const string UserInfoEndpoint = "https://server/connect/userinfo";
        public const string IntrospectionEndpoint = "https://server/connect/introspect";
        public const string IdentityTokenValidationEndpoint = "https://server/connect/identityTokenValidation";
        public const string EndSessionEndpoint = "https://server/connect/endsession";
        public const string CheckSessionEndpoint = "https://server/connect/checksession";

        static IdentityServerPipeline()
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .WriteTo.Trace()
                .CreateLogger();
        }

        public IdentityServerPipeline()
        {
            var factory = new IdentityServerServiceFactory();
            factory.UseInMemoryClients(Clients);
            factory.UseInMemoryScopes(Scopes);
            factory.UseInMemoryUsers(Users);
            Options.Factory = factory;

            Options.SiteName = "Test";
            Options.SigningCertificate = LoadCert();

            Options.Endpoints = new EndpointOptions
            {
                EnableAccessTokenValidationEndpoint = false
            };

            this.OnConfiguration += IdentityServerPipeline_OnConfiguration;
        }

        public IdentityServerOptions Options { get; set; } = new IdentityServerOptions();
        public List<Client> Clients { get; set; } = new List<Client>();
        public List<Scope> Scopes { get; set; } = new List<Scope>();
        public List<InMemoryUser> Users { get; set; } = new List<InMemoryUser>();

        public BrowserClient BrowserClient { get; set; }
        public HttpClient Client { get; set; }

        public override void Initialize()
        {
            base.Initialize();

            BrowserClient = new BrowserClient(new BrowserHandler(Handler));
            Client = new HttpClient(Handler);
        }

        private void IdentityServerPipeline_OnConfiguration(IAppBuilder app)
        {
            app.UseIdentityServer(Options);
        }

        static X509Certificate2 _cert;
        static X509Certificate2 LoadCert()
        {
            if (_cert == null)
            {
                var name = "IdentityModel.Owin.PopAuthentication.Tests.IntegrationTests.IdSvr_Client_And_WebApi_Integration.idsvr.signing.pfx";
                var type = typeof(IdentityServerPipeline);
                var s = type.Assembly.GetManifestResourceStream(name);
                var bytes = new byte[s.Length];
                s.Read(bytes, 0, bytes.Length);
                _cert = new X509Certificate2(bytes, "cert_password");
            }
            return _cert;
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Client;
using IdentityServer3.Core.Models;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class ConnectivityTests
    {
        IdentityServerPipeline _idSvrPipeline;
        WebApiPipeline _webApiPipeline;

        const string ClientId = "client";
        const string ClientSecret = "secret";

        const string Username = "alice";
        const string Password = "alice";

        IdentityServer3.Core.Models.Client _client;

        public ConnectivityTests()
        {
            _idSvrPipeline = new IdentityServerPipeline();

            _idSvrPipeline.Clients.AddRange(new IdentityServer3.Core.Models.Client[] {
                _client = new IdentityServer3.Core.Models.Client
                {
                    ClientId = ClientId,
                    Flow = Flows.ResourceOwner,
                    ClientSecrets = new List<Secret>
                    {
                        new Secret(ClientSecret.Sha256())
                    },
                    AllowedScopes = new List<string>
                    {
                        "openid", "profile", "email", "roles", "api1"
                    }
                }
            });

            _idSvrPipeline.Scopes.AddRange(new IdentityServer3.Core.Models.Scope[] {
                IdentityServer3.Core.Models.StandardScopes.OpenId,
                IdentityServer3.Core.Models.StandardScopes.Profile,
                IdentityServer3.Core.Models.StandardScopes.Email,
                IdentityServer3.Core.Models.StandardScopes.Roles,
                new IdentityServer3.Core.Models.Scope
                {
                    Name = "api1",
                    Type = ScopeType.Resource,
                    ScopeSecrets = new List<IdentityServer3.Core.Models.Secret>
                    {
                        new IdentityServer3.Core.Models.Secret("secret".Sha256())
                    },
                    Claims = new List<IdentityServer3.Core.Models.ScopeClaim>
                    {
                        new IdentityServer3.Core.Models.ScopeClaim("role")
                    }
                }
            });

            _idSvrPipeline.Users.Add(new IdentityServer3.Core.Services.InMemory.InMemoryUser
            {
                Subject = "123",
                Username = Username,
                Password = Password,
                Claims = new Claim[] {
                    new Claim("email", "alice@foo.com"),
                    new Claim("role", "Admin")
                }
            });

            _idSvrPipeline.Initialize();

            _webApiPipeline = new WebApiPipeline(_idSvrPipeline.Handler);
            _webApiPipeline.Initialize();
        }

        [Fact]
        public async Task login_should_work()
        {
            await _idSvrPipeline.AssertLoginAsync(Username, Password);
        }

        [Fact]
        public async Task ropf_requesting_jwt_should_work()
        {
            _client.AccessTokenType = AccessTokenType.Jwt;
            _webApiPipeline.AuthenticationOptions.AuthenticationType = "Bearer";

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var response = await tokenClient.RequestResourceOwnerPasswordAsync(Username, Password, "api1");
            response.AccessToken.Should().NotBeNull();

            var client = new HttpClient(_webApiPipeline.Handler);
            client.SetBearerToken(response.AccessToken);

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task ropf_requesting_reference_token_should_work()
        {
            _client.AccessTokenType = AccessTokenType.Reference;
            _webApiPipeline.AuthenticationOptions.AuthenticationType = "Bearer";

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var response = await tokenClient.RequestResourceOwnerPasswordAsync(Username, Password, "api1");
            response.AccessToken.Should().NotBeNull();

            var client = new HttpClient(_webApiPipeline.Handler);
            client.SetBearerToken(response.AccessToken);

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}

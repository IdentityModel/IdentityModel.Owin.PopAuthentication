// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Client;
using IdentityModel.HttpSigning;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class PopTests
    {
        IdentityServerPipeline _idSvrPipeline;
        WebApiPipeline _webApiPipeline;

        const string ClientId = "native";
        const string ClientSecret = "secret";
        const string ClientRedirectUri = "oob://native/callback";

        const string Username = "alice";
        const string Password = "alice";

        IdentityServer3.Core.Models.Client _client;

        public PopTests()
        {
            _idSvrPipeline = new IdentityServerPipeline();

            _idSvrPipeline.Clients.AddRange(new IdentityServer3.Core.Models.Client[] {
                _client = new IdentityServer3.Core.Models.Client
                {
                    ClientId = ClientId,
                    ClientName = "Native Client",
                    Flow = IdentityServer3.Core.Models.Flows.Hybrid,
                    RequireConsent = false,
                    RedirectUris = new List<string>
                    {
                        ClientRedirectUri,
                    },
                    ClientSecrets = new List<IdentityServer3.Core.Models.Secret>
                    {
                        new IdentityServer3.Core.Models.Secret(IdentityServer3.Core.Models.HashExtensions.Sha256(ClientSecret))
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
                    ScopeSecrets = new List<IdentityServer3.Core.Models.Secret>
                    {
                        new IdentityServer3.Core.Models.Secret(IdentityServer3.Core.Models.HashExtensions.Sha256("secret"))
                    },
                    Type = IdentityServer3.Core.Models.ScopeType.Resource,
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

        async Task LoginAsync()
        {
            await _idSvrPipeline.AssertLoginAsync(Username, Password);
        }

        async Task<AuthorizeResponse> AssertLoginAndGetAuthorizeResponseAsync()
        {
            await LoginAsync();

            var response = await _idSvrPipeline.GetAuthorizeResponseAsync(ClientId, ClientRedirectUri, "code id_token", "openid api1");
            response.IsError.Should().BeFalse();
            response.IdentityToken.Should().NotBeNull();
            response.Code.Should().NotBeNull();

            return response;
        }

        [Fact]
        public async Task using_jwt_should_work()
        {
            _client.AccessTokenType = IdentityServer3.Core.Models.AccessTokenType.Jwt;

            var authResponse = await AssertLoginAndGetAuthorizeResponseAsync();

            var p = RsaPublicKeyJwk.CreateProvider();
            var key = p.ExportParameters(false);
            var jwk = RsaPublicKeyJwk.CreateJwk(key);
            var jwk64 = RsaPublicKeyJwk.CreateJwkString(jwk);

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var tokenResponse = await tokenClient.RequestAuthorizationCodePopAsync(
                authResponse.Code, ClientRedirectUri, key: jwk64, algorithm: jwk.alg);
            tokenResponse.IsError.Should().BeFalse();

            var signature = new RS256Signature(p);
            var signingOptions = new RequestSigningOptions();
            var signingHandler = new HttpSigningMessageHandler(signature, signingOptions, _webApiPipeline.Handler);

            var client = new HttpClient(signingHandler);
            client.SetToken("PoP", tokenResponse.AccessToken);

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task using_reference_token_should_work()
        {
            _client.AccessTokenType = IdentityServer3.Core.Models.AccessTokenType.Reference;

            var authResponse = await AssertLoginAndGetAuthorizeResponseAsync();

            var p = RsaPublicKeyJwk.CreateProvider();
            var key = p.ExportParameters(false);
            var jwk = RsaPublicKeyJwk.CreateJwk(key);
            var jwk64 = RsaPublicKeyJwk.CreateJwkString(jwk);

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var tokenResponse = await tokenClient.RequestAuthorizationCodePopAsync(
                authResponse.Code, ClientRedirectUri, key: jwk64, algorithm: jwk.alg);
            tokenResponse.IsError.Should().BeFalse();

            var signature = new RS256Signature(p);
            var signingOptions = new RequestSigningOptions();
            var signingHandler = new HttpSigningMessageHandler(signature, signingOptions, _webApiPipeline.Handler);

            var client = new HttpClient(signingHandler);
            client.SetToken("PoP", tokenResponse.AccessToken);

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task signing_options_should_work()
        {
            var authResponse = await AssertLoginAndGetAuthorizeResponseAsync();

            var p = RsaPublicKeyJwk.CreateProvider();
            var key = p.ExportParameters(false);
            var jwk = RsaPublicKeyJwk.CreateJwk(key);
            var jwk64 = RsaPublicKeyJwk.CreateJwkString(jwk);

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var tokenResponse = await tokenClient.RequestAuthorizationCodePopAsync(
                authResponse.Code, ClientRedirectUri, key: jwk64, algorithm: jwk.alg);
            tokenResponse.IsError.Should().BeFalse();

            var signature = new RS256Signature(p);
            var signingOptions = new RequestSigningOptions()
            {
                SignHost = true,
                SignMethod = true,
                SignPath = true,
                QueryParametersToSign = new string[] { "a", "b" },
                RequestHeadersToSign = new string[] { "foo", "bar" }
            };
            var signingHandler = new HttpSigningMessageHandler(signature, signingOptions, _webApiPipeline.Handler);

            _webApiPipeline.SignatureValidationOptions.RequestValidationOptions = new IdentityModel.Owin.PopAuthentication.OwinRequestValidationOptions
            {
                ValidateHost = true,
                ValidateMethod = true,
                ValidatePath = true,
                QueryParametersToValidate = new string[] { "b", "a" },
                RequestHeadersToValidate = new string[] {"bar", "foo"}
            };
            var client = new HttpClient(signingHandler);
            client.SetToken("PoP", tokenResponse.AccessToken);

            client.DefaultRequestHeaders.Add("bar", "barbar");
            client.DefaultRequestHeaders.Add("foo", "foofoo");
            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint + "?a=99&b=11");
            apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task server_signing_options_mismatch_should_not_work()
        {
            var authResponse = await AssertLoginAndGetAuthorizeResponseAsync();

            var p = RsaPublicKeyJwk.CreateProvider();
            var key = p.ExportParameters(false);
            var jwk = RsaPublicKeyJwk.CreateJwk(key);
            var jwk64 = RsaPublicKeyJwk.CreateJwkString(jwk);

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var tokenResponse = await tokenClient.RequestAuthorizationCodePopAsync(
                authResponse.Code, ClientRedirectUri, key: jwk64, algorithm: jwk.alg);
            tokenResponse.IsError.Should().BeFalse();

            var signature = new RS256Signature(p);
            var signingOptions = new RequestSigningOptions()
            {
                SignHost = true,
            };
            var signingHandler = new HttpSigningMessageHandler(signature, signingOptions, _webApiPipeline.Handler);

            _webApiPipeline.SignatureValidationOptions.RequestValidationOptions = new IdentityModel.Owin.PopAuthentication.OwinRequestValidationOptions
            {
                //ValidateHost = true,
            };
            var client = new HttpClient(signingHandler);
            client.SetToken("PoP", tokenResponse.AccessToken);

            client.DefaultRequestHeaders.Add("bar", "barbar");
            client.DefaultRequestHeaders.Add("foo", "foofoo");
            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint + "?a=99&b=11");
            apiResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task client_signing_options_mismatch_should_not_work()
        {
            var authResponse = await AssertLoginAndGetAuthorizeResponseAsync();

            var p = RsaPublicKeyJwk.CreateProvider();
            var key = p.ExportParameters(false);
            var jwk = RsaPublicKeyJwk.CreateJwk(key);
            var jwk64 = RsaPublicKeyJwk.CreateJwkString(jwk);

            var tokenClient = new TokenClient(IdentityServerPipeline.TokenEndpoint, ClientId, ClientSecret, _idSvrPipeline.Handler);
            var tokenResponse = await tokenClient.RequestAuthorizationCodePopAsync(
                authResponse.Code, ClientRedirectUri, key: jwk64, algorithm: jwk.alg);
            tokenResponse.IsError.Should().BeFalse();

            var signature = new RS256Signature(p);
            var signingOptions = new RequestSigningOptions()
            {
                //SignHost = true,
            };
            var signingHandler = new HttpSigningMessageHandler(signature, signingOptions, _webApiPipeline.Handler);

            _webApiPipeline.SignatureValidationOptions.RequestValidationOptions = new IdentityModel.Owin.PopAuthentication.OwinRequestValidationOptions
            {
                ValidateHost = true,
            };
            var client = new HttpClient(signingHandler);
            client.SetToken("PoP", tokenResponse.AccessToken);

            client.DefaultRequestHeaders.Add("bar", "barbar");
            client.DefaultRequestHeaders.Add("foo", "foofoo");
            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint + "?a=99&b=11");
            apiResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task absent_pop_token_should_call_through_to_api_as_anonymous()
        {
            var client = new HttpClient(_webApiPipeline.Handler);

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task invalid_pop_token_should_not_call_through_to_api()
        {
            var client = new HttpClient(_webApiPipeline.Handler);

            client.SetToken("PoP", "junk");

            var apiResponse = await client.GetAsync(WebApiPipeline.Endpoint);
            apiResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }


        // add post signing message handler to change headers/path/etc

    }
}

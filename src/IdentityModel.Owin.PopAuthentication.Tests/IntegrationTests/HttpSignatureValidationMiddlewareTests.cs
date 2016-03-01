﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Owin;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using System.Net.Http;
using IdentityModel.HttpSigning;
using System.Security.Claims;
using Newtonsoft.Json;
using System.Net;

namespace IdentityModel.Owin.PopAuthentication.Tests.IntegrationTests
{
    public class HttpSignatureValidationMiddlewareTests
    {
        static readonly byte[] _symmetricKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
        static string _cnfJson;
        static ClaimsIdentity _cnfIdentity;

        HttpSignatureValidationOptions _signatureValidationOptions = new HttpSignatureValidationOptions();
        RequestSigningOptions _requestSigningOptions = new RequestSigningOptions();
        StubAuthenticationManager _stubAuthenticationManager = new StubAuthenticationManager();

        PopPipeline _pipeline;
        HttpClient _client;
        Signature _signature = new HS256Signature(_symmetricKey);

        static HttpSignatureValidationMiddlewareTests()
        {
            var key = Base64Url.Encode(_symmetricKey);
            var jwk = new Jwk
            {
                kty = "oct",
                alg = "HS256",
                k = key
            };
            _cnfJson = JsonConvert.SerializeObject(jwk);
            var claims = new Claim[]
            {
                new Claim("cnf", _cnfJson)
            };
            _cnfIdentity = new ClaimsIdentity(claims, "PoP");
        }

        public HttpSignatureValidationMiddlewareTests()
        {
            _pipeline = new PopPipeline(_signatureValidationOptions);
            _pipeline.OnPreProcessRequest += env =>
            {
                _stubAuthenticationManager.Attach(env);
                return Task.FromResult(0);
            };
            _pipeline.Initialize();

            var signingHandler = new HttpSigningMessageHandler(_signature, _requestSigningOptions, _pipeline.Handler);
            _client = new HttpClient(signingHandler);
        }

        [Fact]
        public async Task access_token_and_no_user_should_fail_request()
        {
            _client.SetToken("PoP", "token");

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task no_access_token_with_user_should_allow_request_through()
        {
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task no_access_token_and_no_user_should_allow_request_through()
        {
            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task access_token_and_user_should_allow_request_through()
        {
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task path_not_signed_but_validation_requires_path_should_fail_request()
        {
            _signatureValidationOptions.ValidationOptions.ValidatePath = true;
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task path_signed_but_validation_does_not_validate_path_should_fail_request()
        {
            _signatureValidationOptions.ValidationOptions.ValidatePath = true;
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task path_signed_and_validation_validates_path_should_succeed()
        {
            _requestSigningOptions.SignPath = true;
            _signatureValidationOptions.ValidationOptions.ValidatePath = true;
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task query_not_signed_but_validation_requires_query_should_fail_request()
        {
            _signatureValidationOptions.ValidationOptions.QueryParametersToValidate = new string[] {
                "y", "x"
            };
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task query_signed_but_validation_does_not_include_query_should_fail_request()
        {
            _requestSigningOptions.SignAllQueryParameters = true;
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task query_signed_and_validation_includes_query_should_succeed()
        {
            _requestSigningOptions.SignAllQueryParameters = true;
            _signatureValidationOptions.ValidationOptions.QueryParametersToValidate = new string[] {
                "x", "y"
            };
            _client.SetToken("PoP", "token");
            _stubAuthenticationManager.Identity = _cnfIdentity;

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}

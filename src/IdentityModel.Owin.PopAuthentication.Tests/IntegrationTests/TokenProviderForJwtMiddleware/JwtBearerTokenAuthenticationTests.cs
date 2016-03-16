// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using System.Net.Http;
using IdentityModel.HttpSigning;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Net;
using System.IdentityModel.Tokens;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class JwtBearerTokenAuthenticationTests
    {
        static readonly byte[] _symmetricKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };

        JwtBearerTokenAuthenticationPipeline _pipeline;
        HttpClient _client;
        Signature _signature = new HS256Signature(_symmetricKey);

        public JwtBearerTokenAuthenticationTests()
        {
            _pipeline = new JwtBearerTokenAuthenticationPipeline();
            _pipeline.Initialize();
            _client = new HttpClient(_pipeline.Handler);
        }

        [Fact]
        public async Task access_token_in_pop_token_should_be_validated()
        {
            var claims = new Claim[] {
                new Claim("sub", "123")
            };
            var id = new ClaimsIdentity(claims, "password");
            var subject = new ClaimsPrincipal(id);

            var handler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(
                "issuer", "audience", 
                subject.Claims, 
                notBefore: DateTime.UtcNow.AddSeconds(-5),
                expires : DateTime.UtcNow.AddMinutes(5),
                signingCredentials: new X509SigningCredentials(SigningCertificate.Cert));
            var jwt = handler.WriteToken(token);

            var encodingParams = new EncodingParameters(jwt);
            var pop = _signature.Sign(encodingParams);
            _client.SetToken("PoP", pop);

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task invalid_pop_token_should_fail()
        {
            _client.SetToken("PoP", "junk");

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using System.Net;
using System.IdentityModel.Tokens;
using IdentityModel.Owin.PopAuthentication;
using IdentityModel;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public class JwtBearerAndHttpSignatureTests
    {
        static readonly byte[] _symmetricKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };

        HttpSignatureValidationOptions _signatureValidationOptions = new HttpSignatureValidationOptions();
        RequestSigningOptions _requestSigningOptions = new RequestSigningOptions();

        JwtBearerAndHttpSignaturePipeline _pipeline;
        HttpClient _client;
        Signature _signature = new HS256Signature(_symmetricKey);

        public JwtBearerAndHttpSignatureTests()
        {
            _pipeline = new JwtBearerAndHttpSignaturePipeline(_signatureValidationOptions);
            _pipeline.Initialize();

            var signingHandler = new HttpSigningMessageHandler(_signature, _requestSigningOptions, _pipeline.Handler);
            _client = new HttpClient(signingHandler);
        }

        string GetAccessToken()
        {
            var jwk = new Jwk
            {
                kty = "oct",
                alg = "HS256",
                k = Base64Url.Encode(_symmetricKey)
            };
            var cnf = new Cnf(jwk);
            var cnfJson = cnf.ToJson();

            var claims = new Claim[] {
                new Claim("sub", "123"),
                new Claim("cnf", cnfJson)
            };
            var id = new ClaimsIdentity(claims, "password");
            var subject = new ClaimsPrincipal(id);

            var handler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(
                "issuer", "audience",
                subject.Claims,
                notBefore: DateTime.UtcNow.AddSeconds(-5),
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: new X509SigningCredentials(SigningCertificate.Cert));
            var jwt = handler.WriteToken(token);

            return jwt;
        }

        [Fact]
        public async Task valid_pop_token_should_succeed()
        {
            _client.SetToken("PoP", GetAccessToken());

            var response = await _client.GetAsync("http://foo.com/path?x=1&y=2");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}

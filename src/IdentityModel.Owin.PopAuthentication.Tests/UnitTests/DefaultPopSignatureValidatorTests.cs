// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Microsoft.Owin;
using System.Security.Claims;
using IdentityModel.HttpSigning;
using Newtonsoft.Json;

namespace IdentityModel.Owin.PopAuthentication.Tests.UnitTests
{
    public class DefaultPopSignatureValidatorTests
    {
        static readonly byte[] _symmetricKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
        static Signature _signature = new HS256Signature(_symmetricKey);
        static string _cnfJson;

        static DefaultPopSignatureValidatorTests()
        {
            var key = Base64Url.Encode(_symmetricKey);
            var jwk = new Jwk
            {
                kty = "oct",
                alg = "HS256",
                k = key
            };
            _cnfJson = JsonConvert.SerializeObject(jwk);
        }

        OwinContext _context;
        StubOwinValidationOptions _stubOptions = new StubOwinValidationOptions();
        StubAuthenticationManager _stubAuthenticationManager;

        public DefaultPopSignatureValidatorTests()
        {
            _context = new OwinContext();
            _stubAuthenticationManager = new StubAuthenticationManager(_context.Environment);
        }

        [Fact]
        public async Task ValidateToken_should_throw_for_invalid_arguments()
        {
            var ctx = new OwinContext();

            await Assert.ThrowsAsync<ArgumentNullException>(async () => await DefaultPopSignatureValidator.ValidateTokenAsync(null, new OwinValidationOptions(), "token"));
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await DefaultPopSignatureValidator.ValidateTokenAsync(ctx.Environment, null, "token"));
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await DefaultPopSignatureValidator.ValidateTokenAsync(ctx.Environment, new OwinValidationOptions(), ""));
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await DefaultPopSignatureValidator.ValidateTokenAsync(ctx.Environment, new OwinValidationOptions(), ""));
        }

        [Fact]
        public async Task no_user_should_fail_validation()
        {
            {
                var result = await DefaultPopSignatureValidator.ValidateTokenAsync(new OwinContext().Environment, _stubOptions, "token");
                result.Should().BeFalse();
            }
            {
                var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, "token");
                result.Should().BeFalse();
            }
            {
                _stubAuthenticationManager.Identity = new ClaimsIdentity();
                var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, "token");
                result.Should().BeFalse();
            }
        }

        [Fact]
        public async Task user_without_cnf_claim_should_fail_validation()
        {
            var claims = new Claim[]
            {
                new Claim("not_cnf", "foo")
            };
            _stubAuthenticationManager.Identity = new ClaimsIdentity(claims, "PoP");

            var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, "token");

            result.Should().BeFalse();
        }

        [Fact]
        public async Task negative_timestamp_should_fail_validation()
        {
            var claims = new Claim[]
            {
                new Claim("cnf", _cnfJson)
            };
            _stubAuthenticationManager.Identity = new ClaimsIdentity(claims, "PoP");

            var token = new Dictionary<string, object>
            {
                { "at", "token" }
            };
            var payload = new EncodingParameters("token");
            payload.TimeStamp = DateTimeOffset.MinValue;
            var popToken = _signature.Sign(payload);

            var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, popToken);

            result.Should().BeFalse();
        }

        [Fact]
        public async Task too_old_timestamp_should_fail_validation()
        {
            _stubOptions.TimespanValidityWindow = TimeSpan.FromSeconds(300);

            var claims = new Claim[]
            {
                new Claim("cnf", _cnfJson)
            };
            _stubAuthenticationManager.Identity = new ClaimsIdentity(claims, "PoP");

            var token = new Dictionary<string, object>
            {
                { "at", "token" }
            };
            var payload = new EncodingParameters("token");
            payload.TimeStamp = DateTimeOffset.UtcNow.AddSeconds(-302);
            var popToken = _signature.Sign(payload);

            var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, popToken);

            result.Should().BeFalse();
        }

        [Fact]
        public async Task too_new_timestamp_should_fail_validation()
        {
            _stubOptions.TimespanValidityWindow = TimeSpan.FromSeconds(300);

            var claims = new Claim[]
            {
                new Claim("cnf", _cnfJson)
            };
            _stubAuthenticationManager.Identity = new ClaimsIdentity(claims, "PoP");

            var token = new Dictionary<string, object>
            {
                { "at", "token" }
            };
            var payload = new EncodingParameters("token");
            payload.TimeStamp = DateTimeOffset.UtcNow.AddSeconds(302);
            var popToken = _signature.Sign(payload);

            var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, popToken);

            result.Should().BeFalse();
        }

        [Fact]
        public async Task valid_claim_should_succeed_validation()
        {
            var claims = new Claim[]
            {
                new Claim("cnf", _cnfJson)
            };
            _stubAuthenticationManager.Identity = new ClaimsIdentity(claims, "PoP");

            var token = new Dictionary<string, object>
            {
                { "at", "token" }
            };
            var payload = new EncodingParameters("token");
            var popToken = _signature.Sign(payload);

            var result = await DefaultPopSignatureValidator.ValidateTokenAsync(_context.Environment, _stubOptions, popToken);

            result.Should().BeTrue();
        }
    }
}

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

namespace IdentityModel.Owin.PopAuthentication.Tests.UnitTests
{
    public class HttpSignatureValidationMiddlewareTests
    {
        HttpSignatureValidationMiddleware _subject;

        OwinContext _context = new OwinContext();
        StubMiddleware _stubNext = new StubMiddleware();
        HttpSignatureValidationOptions _options;
        StubTokenProvider _stubTokenProvider = new StubTokenProvider();
        StubSignatureValidator _stubSignatureValidator = new StubSignatureValidator();

        public HttpSignatureValidationMiddlewareTests()
        {
            _options = new HttpSignatureValidationOptions
            {
                TokenProvider = _stubTokenProvider.Invoke,
                SignatureValidator = _stubSignatureValidator.Invoke
            };
            _subject = new HttpSignatureValidationMiddleware(_stubNext.Invoke, _options);
        }

        [Fact]
        public void ctor_should_throw_for_invalid_arguments()
        {
            Assert.Throws<ArgumentNullException>(() => new HttpSignatureValidationMiddleware(null, new HttpSignatureValidationOptions()));

            Assert.Throws<ArgumentNullException>(() => new HttpSignatureValidationMiddleware(null, new HttpSignatureValidationOptions() { SignatureValidator = null }));
            Assert.Throws<ArgumentNullException>(() => new HttpSignatureValidationMiddleware(null, new HttpSignatureValidationOptions() { TokenProvider = null }));

            Func<IDictionary<string, object>, Task> a = (env) => { return Task.FromResult(0); };
            Assert.Throws<ArgumentNullException>(() => new HttpSignatureValidationMiddleware(a, null));
        }

        [Fact]
        public async Task no_token_should_invoke_next_middleware()
        {
            await _subject.Invoke(_context.Environment);

            _stubNext.InvokeWasCalled.Should().BeTrue();
            _stubSignatureValidator.InvokeWasCalled.Should().BeFalse();
        }

        [Fact]
        public async Task when_token_present_should_invoke_validator()
        {
            _stubTokenProvider.Token = "token";
            _stubSignatureValidator.Result = true;

            await _subject.Invoke(_context.Environment);

            _stubSignatureValidator.InvokeWasCalled.Should().BeTrue();
        }

        [Fact]
        public async Task token_validation_success_should_call_next_middleware()
        {
            _stubTokenProvider.Token = "token";
            _stubSignatureValidator.Result = true;

            await _subject.Invoke(_context.Environment);

            _stubNext.InvokeWasCalled.Should().BeTrue();
        }

        [Fact]
        public async Task token_validation_failure_should_fail_http_call()
        {
            _stubTokenProvider.Token = "token";
            _stubSignatureValidator.Result = false;
            await _subject.Invoke(_context.Environment);

            _stubNext.InvokeWasCalled.Should().BeFalse();

            _context.Response.StatusCode.Should().Be(401);
            var wwwAuth = _context.Response.Headers.Get("WWW-Authenticate");
            wwwAuth.Should().NotBeNull();
            wwwAuth.Should().StartWith("PoP");
            wwwAuth.Should().Contain("error=\"invalid_token\"");
        }
    }
}

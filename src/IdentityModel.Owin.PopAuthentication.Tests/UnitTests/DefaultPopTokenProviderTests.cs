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
using System.IO;
using Newtonsoft.Json;
using Jose;
using IdentityModel.Owin.PopAuthentication;

namespace IdentityModelOwinPopAuthentication.Tests.UnitTests
{
    public class DefaultPopTokenProviderTests
    {
        [Fact]
        public async Task when_no_params_GetPopTokenAsync_should_return_null()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "GET";
            ctx.Request.Path = new PathString("/hello");
            var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
            token.Should().BeNull();
        }

        [Fact]
        public async Task when_POST_body_has_no_token_GetPopTokenAsync_should_return_null()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "POST";
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            using (var ms = new MemoryStream())
            {
                var form = "foo=bar&baz=quux";
                var bytes = Encoding.UTF8.GetBytes(form);
                ms.Write(bytes, 0, bytes.Length);
                ms.Seek(0, SeekOrigin.Begin);
                ctx.Request.Body = ms;

                var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
                token.Should().BeNull();
            }
        }

        [Fact]
        public async Task when_query_has_no_token_GetPopTokenAsync_should_return_null()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "GET";
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.QueryString = new QueryString("x=1&y=2");

            var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
            token.Should().BeNull();
        }

        [Fact]
        public async Task GetPopTokenAsync_should_find_token_in_authorization_header()
        {
            var ctx = new OwinContext();
            ctx.Request.Headers.Add("Authorization", new string[] { "PoP token" });

            var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
            token.Should().Be("token");
        }

        [Fact]
        public async Task GetPopTokenAsync_should_find_token_in_POST_body()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "POST";
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            using (var ms = new MemoryStream())
            {
                var form = "foo=bar&pop_access_token=token&baz=quux";
                var bytes = Encoding.UTF8.GetBytes(form);
                ms.Write(bytes, 0, bytes.Length);
                ms.Seek(0, SeekOrigin.Begin);
                ctx.Request.Body = ms;

                var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
                token.Should().Be("token");
            }
        }

        [Fact]
        public async Task GetPopTokenAsync_should_find_token_in_query_string()
        {
            var ctx = new OwinContext();
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.QueryString = new QueryString("x=1&pop_access_token=token&y=2");

            var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
            token.Should().Be("token");
        }

        [Fact]
        public async Task when_multiple_tokens_sent_GetPopTokenAsync_should_find_authorization_header_first()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "POST";
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.Headers.Add("Authorization", new string[] { "PoP token1" });
            ctx.Request.QueryString = new QueryString("x=1&pop_access_token=token3&y=2");
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            using (var ms = new MemoryStream())
            {
                var form = "foo=bar&pop_access_token=token2&baz=quux";
                var bytes = Encoding.UTF8.GetBytes(form);
                ms.Write(bytes, 0, bytes.Length);
                ms.Seek(0, SeekOrigin.Begin);
                ctx.Request.Body = ms;

                var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
                token.Should().Be("token1");
            }
        }

        [Fact]
        public async Task when_multiple_tokens_sent_GetPopTokenAsync_should_find_POST_body_second()
        {
            var ctx = new OwinContext();
            ctx.Request.Method = "POST";
            ctx.Request.Path = new PathString("/hello");
            ctx.Request.QueryString = new QueryString("x=1&pop_access_token=token3&y=2");
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            using (var ms = new MemoryStream())
            {
                var form = "foo=bar&pop_access_token=token2&baz=quux";
                var bytes = Encoding.UTF8.GetBytes(form);
                ms.Write(bytes, 0, bytes.Length);
                ms.Seek(0, SeekOrigin.Begin);
                ctx.Request.Body = ms;

                var token = await DefaultPopTokenProvider.GetPopTokenAsync(ctx.Environment);
                token.Should().Be("token2");
            }
        }

        [Fact]
        public void empty_pop_token_passed_to_GetAccessTokenFromPopToken_should_return_no_access_token()
        {
            DefaultPopTokenProvider.GetAccessTokenFromPopToken(null).Should().BeNull();
            DefaultPopTokenProvider.GetAccessTokenFromPopToken("").Should().BeNull();
            DefaultPopTokenProvider.GetAccessTokenFromPopToken("    ").Should().BeNull();
        }

        [Fact]
        public void pop_token_passed_to_GetAccessTokenFromPopToken_should_return_access_token()
        {
            var pop = new
            {
                at = "token"
            };
            var token = JWT.Encode(pop, null, JwsAlgorithm.none);

            var access_token = DefaultPopTokenProvider.GetAccessTokenFromPopToken(token);
            access_token.Should().Be("token");
        }

        [Fact]
        public void invalid_at_in_pop_token_passed_to_GetAccessTokenFromPopToken_should_return_no_access_token()
        {
            var pop = new
            {
                at = 5
            };
            var token = JWT.Encode(pop, null, JwsAlgorithm.none);

            var access_token = DefaultPopTokenProvider.GetAccessTokenFromPopToken(token);
            access_token.Should().BeNull();
        }

        [Fact]
        public void pop_token_missing_at_passed_to_GetAccessTokenFromPopToken_should_return_no_access_token()
        {
            var pop = new
            {
            };
            var token = JWT.Encode(pop, null, JwsAlgorithm.none);

            var access_token = DefaultPopTokenProvider.GetAccessTokenFromPopToken(token);
            access_token.Should().BeNull();
        }
    }
}

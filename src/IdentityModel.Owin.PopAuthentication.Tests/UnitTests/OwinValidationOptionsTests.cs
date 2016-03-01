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
using IdentityModel.HttpSigning;

namespace IdentityModel.Owin.PopAuthentication.Tests.UnitTests
{
    public class OwinValidationOptionsTests
    {
        OwinValidationOptions _subject = new OwinValidationOptions();
        OwinContext _context = new OwinContext();

        [Fact]
        public async Task ReadBodyAsync_should_read_bytes()
        {
            _context.Request.Method = "POST";
            _context.Request.ContentType = "application/x-www-form-urlencoded";
            using (var ms = new MemoryStream())
            {
                var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
                ms.Write(bytes, 0, bytes.Length);
                ms.Seek(0, SeekOrigin.Begin);
                _context.Request.Body = ms;

                var result = await _subject.ReadBodyAsync(_context.Request);
                result.Should().ContainInOrder(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
            }
        }

        [Fact]
        public async Task no_body_ReadBodyAsync_should_return_null()
        {
            var ctx = new OwinContext();
            var result = await _subject.ReadBodyAsync(ctx.Request);
            result.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_minimal_values()
        {
            var pop = new EncodedParameters("token");

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.AccessToken.Should().Be("token");

            result.Host.Should().BeNull();
            result.Method.Should().BeNull();
            result.Path.Should().BeNull();
            result.QueryParameters.Should().BeNull();
            result.RequestHeaders.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_method()
        {
            _subject.ValidateMethod = true;

            var pop = new EncodedParameters("token");
            _context.Request.Method = "PUT";

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.Method.Should().Be("PUT");

            result.Host.Should().BeNull();
            result.Path.Should().BeNull();
            result.QueryParameters.Should().BeNull();
            result.RequestHeaders.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_path()
        {
            _subject.ValidatePath = true;

            var pop = new EncodedParameters("token");
            _context.Request.Scheme = "http";
            _context.Request.Host = new HostString("foo.com");
            _context.Request.PathBase = new PathString("/base");
            _context.Request.Path = new PathString("/path");

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.Path.Should().Be("/base/path");

            result.Host.Should().BeNull();
            result.Method.Should().BeNull();
            result.QueryParameters.Should().BeNull();
            result.RequestHeaders.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_host()
        {
            _subject.ValidateHost = true;

            var pop = new EncodedParameters("token");
            _context.Request.Host = new HostString("foo.com");

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.Host.Should().Be("foo.com");

            result.Method.Should().BeNull();
            result.Path.Should().BeNull();
            result.QueryParameters.Should().BeNull();
            result.RequestHeaders.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_body()
        {
            _subject.ValidateBody = true;

            var pop = new EncodedParameters("token");
            using (var ms = new MemoryStream())
            {
                var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
                ms.Write(data, 0, data.Length);

                ms.Seek(0, SeekOrigin.Begin);
                _context.Request.Body = ms;

                var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

                result.BodyHash.Should().Be("vnPfBFvKBXMv9S6m1FMSeSi1VLnnmqYXGr4xk9ImCp8");

                result.Host.Should().BeNull();
                result.Method.Should().BeNull();
                result.Path.Should().BeNull();
                result.QueryParameters.Should().BeNull();
                result.RequestHeaders.Should().BeNull();
            }
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_query()
        {
            _subject.QueryParametersToValidate = new string[] { "a", "b", "z" };
            var pop = new EncodedParameters("token");
            _context.Request.QueryString = new QueryString("a=apple&b=carrot&b=duck&b=banana&c=foo");

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.QueryParameters.Should().NotBeNull();
            result.QueryParameters.Keys.Should().ContainInOrder(new string[] { "a", "b", "b", "b" });
            result.QueryParameters.HashedValue.Should().Be("yo_hLZrWnia7ghdlOkEjUoW-dzfMIUW3hgJg1h3ZkfU");

            result.Host.Should().BeNull();
            result.Method.Should().BeNull();
            result.Path.Should().BeNull();
            result.RequestHeaders.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_query_in_same_order_as_pop_token()
        {
            _subject.QueryParametersToValidate = new string[] { "a", "b" };

            var pop = new EncodedParameters("token");
            pop.QueryParameters = new EncodedList(new string[] { "b", "b", "b", "a" }, "hash");
            _context.Request.QueryString = new QueryString("a=apple&b=carrot&b=duck&b=banana");

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.QueryParameters.Should().NotBeNull();
            result.QueryParameters.Keys.Should().ContainInOrder(new string[] { "b", "b", "b", "a" });
            result.QueryParameters.HashedValue.Should().Be("GCDxUdmJ6mfoSmV1oWnKKgx2Utrksk32XoDb3HtAMns");
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_headers()
        {
            _subject.RequestHeadersToValidate = new string[] { "a", "b", "z" };
            var pop = new EncodedParameters("token");
            _context.Request.Headers.Add("a", new string[] { "apple" });
            _context.Request.Headers.Add("b", new string[] { "carrot", "banana", "duck" });
            _context.Request.Headers.Add("c", new string[] { "foo" });

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.RequestHeaders.Should().NotBeNull();
            result.RequestHeaders.Keys.Should().ContainInOrder(new string[] { "a", "b", "b", "b" });
            result.RequestHeaders.HashedValue.Should().Be("DPgVz1VB3aU4gmnSYPl69woLEij0XlKVvYhZVTS5hd0");

            result.Host.Should().BeNull();
            result.Method.Should().BeNull();
            result.Path.Should().BeNull();
            result.QueryParameters.Should().BeNull();
            result.BodyHash.Should().BeNull();
        }

        [Fact]
        public async Task ReadEncodedParametersAsync_should_capture_headers_in_same_order_as_pop_token()
        {
            _subject.RequestHeadersToValidate = new string[] { "a", "b" };
            var pop = new EncodedParameters("token");
            pop.RequestHeaders = new EncodedList(new string[] { "b", "b", "b", "a" }, "hash");

            _context.Request.Headers.Add("a", new string[] { "apple" });
            _context.Request.Headers.Add("b", new string[] { "carrot", "banana", "duck" });

            var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);

            result.RequestHeaders.Should().NotBeNull();
            result.RequestHeaders.Keys.Should().ContainInOrder(new string[] { "b", "b", "b", "a" });
            result.RequestHeaders.HashedValue.Should().Be("LmIpLHakIGUwuRPeDqQGhT_2EWlm66qgf_7ekw-LC7U");
        }

        //[Fact]
        //public async Task ReadEncodedParametersAsync_should_capture_headers()
        //{
        //    var pop = new EncodedParameters("token");
        //    pop.BodyHash

        //    var result = await _subject.ReadEncodedParametersAsync(_context.Environment, pop);
        //    result.Host.Should().Be("foo.com");
        //}
    }
}

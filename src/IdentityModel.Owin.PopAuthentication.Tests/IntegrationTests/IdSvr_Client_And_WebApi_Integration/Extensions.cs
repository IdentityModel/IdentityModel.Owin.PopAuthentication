// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Client;
using IdentityServer3.Core.ViewModels;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public static class Extensions
    {
        public static async Task AssertLoginAsync(this IdentityServerPipeline idSvrPipeline, string username, string password)
        {
            var old = idSvrPipeline.BrowserClient.AllowAutoRedirect;
            try
            {
                var loginResponse = await idSvrPipeline.BrowserClient.GetAsync(IdentityServerPipeline.PermissionsPage);
                var html = await loginResponse.Content.ReadAsStringAsync();
                var model = await loginResponse.GetModelAsync<LoginViewModel>();

                var values = new Dictionary<string, string>();
                values.Add("username", username);
                values.Add("password", password);
                values.Add(model.AntiForgery.Name, model.AntiForgery.Value);

                var postResponse = await idSvrPipeline.BrowserClient.PostAsync(IdentityServerPipeline.Authority + model.LoginUrl, new FormUrlEncodedContent(values));
                postResponse.StatusCode.Should().Be(HttpStatusCode.OK);
                await postResponse.AssertPageAsync("permissions");
            }
            finally
            {
                idSvrPipeline.BrowserClient.AllowAutoRedirect = old;
            }
        }

        static async Task<T> GetModelAsync<T>(this HttpResponseMessage response)
        {
            var html = await response.Content.ReadAsStringAsync();
            var match = "<script id='modelJson' type='application/json'>";
            var start = html.IndexOf(match);
            var end = html.IndexOf("</script>", start);
            var content = html.Substring(start + match.Length, end - start - match.Length);
            var json = WebUtility.HtmlDecode(content);
            return JsonConvert.DeserializeObject<T>(json);
        }

        static async Task AssertPageAsync(this HttpResponseMessage response, string name)
        {
            var html = await response.Content.ReadAsStringAsync();
            var match = Regex.Match(html, "<div class='container page-(.*)' ng-cloak>");
            match.Groups[1].Value.Should().Be(name);
        }

        public static async Task<AuthorizeResponse> GetAuthorizeResponseAsync(this IdentityServerPipeline idSvrPipeline, string clientId, string redirectUri, string responseType, string scope, string state = "state", string nonce = "nonce")
        {
            var old = idSvrPipeline.BrowserClient.AllowAutoRedirect;
            try
            {
                idSvrPipeline.BrowserClient.AllowAutoRedirect = false;

                var authorization = new AuthorizeRequest(IdentityServerPipeline.AuthorizeEndpoint);
                var url = authorization.CreateAuthorizeUrl(clientId, responseType, scope, redirectUri, state, nonce);

                var authorizeResponse = await idSvrPipeline.BrowserClient.GetAsync(url);
                authorizeResponse.StatusCode.Should().Be(HttpStatusCode.Found);

                var location = authorizeResponse.Headers.Location.ToString();
                return new AuthorizeResponse(location);
            }
            finally
            {
                idSvrPipeline.BrowserClient.AllowAutoRedirect = old;
            }
        }
    }
}

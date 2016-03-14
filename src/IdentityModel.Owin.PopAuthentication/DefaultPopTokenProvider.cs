// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Microsoft.Owin;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class DefaultPopTokenProvider
    {
        public static async Task<string> GetPopTokenAsync(IDictionary<string, object> env)
        {
            if (env == null) throw new ArgumentNullException("env");

            var ctx = new OwinContext(env);
            
            if (ctx.Request.Headers.ContainsKey("Authorization"))
            {
                var authorizationHeader = ctx.Request.Headers.Get("Authorization");
                var scheme = HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme + " ";
                if (authorizationHeader.StartsWith(scheme))
                {
                    var token = authorizationHeader.Substring(scheme.Length);
                    return token;
                }

                return null;
            }

            if (ctx.Request.ContentType != null && 
                ctx.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                var form = await ctx.Request.ReadFormAsync();
                if (form != null)
                {
                    var token = form.Get(HttpSigningConstants.AccessTokenParameterNames.RequestParameterName);
                    return token;
                }

                return null;
            }

            if (ctx.Request.Query != null)
            {
                var token = ctx.Request.Query.Get(HttpSigningConstants.AccessTokenParameterNames.RequestParameterName);
                return token;
            }

            return null;
        }

        public static string GetAccessTokenFromPopToken(string token)
        {
            if (!String.IsNullOrWhiteSpace(token))
            {
                string json = null;

                try
                {
                    json = Jose.JWT.Payload(token);
                    if (json == null) return null;
                }
                catch
                {
                    return null;
                }

                var values = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                if (values.ContainsKey(HttpSigningConstants.SignedObjectParameterNames.AccessToken))
                {
                    return values[HttpSigningConstants.SignedObjectParameterNames.AccessToken] as string;
                }
            }

            return null;
        }

        public static async Task<string> GetAccessTokenFromPopTokenAsync(IDictionary<string, object> env)
        {
            return GetAccessTokenFromPopToken(await GetPopTokenAsync(env));
        }
    }
}

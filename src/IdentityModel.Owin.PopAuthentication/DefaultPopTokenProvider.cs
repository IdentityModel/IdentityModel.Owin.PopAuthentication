// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
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

            var logger = Logging.GetLogger();

            var ctx = new OwinContext(env);
            
            if (ctx.Request.Headers.ContainsKey("Authorization"))
            {
                var authorizationHeader = ctx.Request.Headers.Get("Authorization");
                var scheme = HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme + " ";
                if (authorizationHeader.StartsWith(scheme))
                {
                    logger.WriteVerbose("PoP token found in Authorization header");

                    var token = authorizationHeader.Substring(scheme.Length);
                    return token;
                }
                else
                {
                    logger.WriteVerbose("Authorization header present, but not PoP scheme");
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
                    if (token != null)
                    {
                        logger.WriteVerbose("PoP token found in form body");
                    }
                    else
                    {
                        logger.WriteVerbose("Form body present, but no PoP token found");
                    }

                    return token;
                }

                return null;
            }

            if (ctx.Request.Query != null)
            {
                var token = ctx.Request.Query.Get(HttpSigningConstants.AccessTokenParameterNames.RequestParameterName);
                if (token != null)
                {
                    logger.WriteVerbose("PoP token found in query string");
                }
                else
                {
                    logger.WriteVerbose("Query string present, but no PoP token found");
                }

                return token;
            }

            logger.WriteVerbose("No PoP token found");

            return null;
        }

        public static string GetAccessTokenFromPopToken(string token)
        {
            var logger = Logging.GetLogger();

            if (!String.IsNullOrWhiteSpace(token))
            {
                string json = null;

                try
                {
                    json = Jose.JWT.Payload(token);
                    if (json == null)
                    {
                        logger.WriteError("Failed to read JWT payload");
                        return null;
                    }
                }
                catch(Exception ex)
                {
                    logger.WriteError("Failed to read JWT payload", ex);
                    return null;
                }

                var values = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                if (values.ContainsKey(HttpSigningConstants.SignedObjectParameterNames.AccessToken))
                {
                    var value = values[HttpSigningConstants.SignedObjectParameterNames.AccessToken] as string;
                    if (value != null)
                    {
                        logger.WriteVerbose("Successfully extraced access token from PoP token");
                    }
                    else
                    {
                        logger.WriteError("'" + HttpSigningConstants.SignedObjectParameterNames.AccessToken + "' claim is not a string");
                    }

                    return value;
                }
                else
                {
                    logger.WriteError("Token does not contain '" + HttpSigningConstants.SignedObjectParameterNames.AccessToken + "' claim");
                }
            }
            else
            {
                logger.WriteVerbose("Token was empty");
            }

            return null;
        }

        public static async Task<string> GetAccessTokenFromPopTokenAsync(IDictionary<string, object> env)
        {
            return GetAccessTokenFromPopToken(await GetPopTokenAsync(env));
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class DefaultPopSignatureValidator
    {
        public static async Task<bool> ValidateTokenAsync(IDictionary<string, object> env, OwinValidationOptions options, string token)
        {
            if (env == null) throw new ArgumentNullException("env");
            if (options == null) throw new ArgumentNullException("options");
            if (String.IsNullOrWhiteSpace(token)) throw new ArgumentNullException("token");

            var ctx = new OwinContext(env);
            var auth = await ctx.Authentication.AuthenticateAsync(HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme);

            if (auth == null || 
                auth.Identity == null || 
                auth.Identity.IsAuthenticated == false)
            {
                return false;
            }

            var cnf = auth.Identity.FindFirst(HttpSigningConstants.Confirmation.ConfirmationProperty);
            if (cnf == null)
            {
                return false;
            }

            var jwk = CnfParser.Parse(cnf.Value);
            var key = jwk.ToPublicKey();
            var signature = key.ToSignature();
            var popValues = signature.Verify(token);

            if (popValues.TimeStamp == null || popValues.TimeStamp.Value <= 0)
            {
                return false;
            }

            var time = popValues.TimeStamp;
            var allowance = options.OldMessageRejectionAge.TotalSeconds;
            var now = DateTimeOffset.UtcNow.ToEpochTime();
            var low = now - allowance;
            var high = now + allowance;
            if (time < low || high < time)
            {
                return false;
            }

            var owinRequestEncoding = await options.ReadEncodedParametersAsync(env, popValues);
            return owinRequestEncoding.IsSame(popValues);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using IdentityModel.Jwt;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class DefaultPopSignatureValidator
    {
        public static async Task<bool> ValidateTokenAsync(IDictionary<string, object> env, OwinRequestValidationOptions options, string token)
        {
            if (env == null) throw new ArgumentNullException("env");
            if (options == null) throw new ArgumentNullException("options");
            if (String.IsNullOrWhiteSpace(token)) throw new ArgumentNullException("token");

            var logger = Logging.GetLogger();

            var ctx = new OwinContext(env);
            var auth = await ctx.Authentication.AuthenticateAsync(HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme);

            if (auth == null || 
                auth.Identity == null || 
                auth.Identity.IsAuthenticated == false)
            {
                logger.WriteError("Authentication failed for " + HttpSigningConstants.AccessTokenParameterNames.AuthorizationHeaderScheme + " scheme");
                return false;
            }

            var cnf = auth.Identity.FindFirst(HttpSigningConstants.Confirmation.ConfirmationProperty);
            if (cnf == null)
            {
                logger.WriteError(HttpSigningConstants.Confirmation.ConfirmationProperty + " claim not present in authenticated user's claims");
                return false;
            }

            var jwk = CnfParser.Parse(cnf.Value);
            if (jwk == null)
            {
                logger.WriteError("Failed to parse cnf claim");
                return false;
            }

            var key = jwk.ToPublicKey();
            var signature = key.ToSignature();

            var popValues = signature.Verify(token);
            if (popValues == null)
            {
                logger.WriteError("Failed to verify signature on PoP token");
                return false;
            }

            if (popValues.TimeStamp == null || popValues.TimeStamp.Value <= 0)
            {
                logger.WriteError("No timestamp present in PoP object");
                return false;
            }

            var time = popValues.TimeStamp;
            var now = DateTimeOffset.UtcNow.ToEpochTime();
            var allowance = options.TimespanValidityWindow.TotalSeconds;
            var low = now - allowance;
            var high = now + allowance;
            if (time < low || high < time)
            {
                logger.WriteError("Timestamp in PoP object is out of acceptable range");
                return false;
            }

            var owinRequestEncoding = await options.ReadEncodedParametersAsync(env, popValues);
            var result = owinRequestEncoding.IsSame(popValues);

            if (result == false)
            {
                logger.WriteError("Encoded values in PoP object do not match encoded values of current request");
            }
            else
            {
                logger.WriteInformation("PoP signature validation success");
            }

            return result;
        }
    }
}

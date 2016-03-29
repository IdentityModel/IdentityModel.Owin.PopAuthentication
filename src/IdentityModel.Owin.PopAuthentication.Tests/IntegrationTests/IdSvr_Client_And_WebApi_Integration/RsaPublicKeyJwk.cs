// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    public static class RsaPublicKeyJwkHelper
    {
        public static string ToJwkString(this IdentityModel.Jwt.JsonWebKey key)
        {
            var json = JsonConvert.SerializeObject(key);
            return Base64Url.Encode(Encoding.ASCII.GetBytes(json));
        }

        public static IdentityModel.Jwt.JsonWebKey ToJsonWebKey(this RSACryptoServiceProvider provider, string alg = "RS256", string kid = null)
        {
            var key = provider.ExportParameters(false);
            
            var n = Base64Url.Encode(key.Modulus);
            var e = Base64Url.Encode(key.Exponent);
            return new IdentityModel.Jwt.JsonWebKey()
            {
                N = n,
                E = e,
                Kid = kid ?? "id",
                Kty = "RSA",
                Alg = alg,
            };
        }

        public static RSACryptoServiceProvider CreateProvider(int keySize = 2048)
        {
            var csp = new CspParameters
            {
                Flags = CspProviderFlags.CreateEphemeralKey,
                KeyNumber = (int)KeyNumber.Signature
            };

            return new RSACryptoServiceProvider(keySize, csp);
        }
    }
}
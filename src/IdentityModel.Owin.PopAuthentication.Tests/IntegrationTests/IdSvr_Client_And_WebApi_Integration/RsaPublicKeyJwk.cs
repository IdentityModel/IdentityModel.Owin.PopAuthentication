// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace IdentityModelOwinPopAuthentication.Tests.IntegrationTests
{
    /// <summary>
    /// Models an RSA public key JWK
    /// </summary>
    public class RsaPublicKeyJwk
    {
        /// <summary>
        /// key type
        /// </summary>
        public string kty { get; set; }

        /// <summary>
        /// modulus
        /// </summary>
        public string n { get; set; }

        /// <summary>
        /// exponent
        /// </summary>
        public string e { get; set; }

        /// <summary>
        /// algorithm
        /// </summary>
        public string alg { get; set; }

        /// <summary>
        /// key identifier
        /// </summary>
        public string kid { get; set; }

        /// <summary>
        /// Initializes the JWK with a key id
        /// </summary>
        /// <param name="kid"></param>
        public RsaPublicKeyJwk(string kid)
        {
            alg = "RS256";
            this.kid = kid;
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

        public static RsaPublicKeyJwk CreateJwk(RSAParameters key)
        {
            var jwk = new RsaPublicKeyJwk("kid")
            {
                kty = "RSA",
                n = Base64Url.Encode(key.Modulus),
                e = Base64Url.Encode(key.Exponent)
            };
            return jwk;
        }

        public static string CreateJwkString(RsaPublicKeyJwk jwk)
        {
            var json = JsonConvert.SerializeObject(jwk);
            return Base64Url.Encode(Encoding.ASCII.GetBytes(json));
        }
    }
}
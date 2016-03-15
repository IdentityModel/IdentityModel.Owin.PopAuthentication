// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class HttpSignatureValidationOptions
    {
        public HttpSignatureValidationOptions()
        {
            TokenProvider = DefaultPopTokenProvider.GetPopTokenAsync;
            SignatureValidator = DefaultPopSignatureValidator.ValidateTokenAsync;
            RequestValidationOptions = new OwinRequestValidationOptions();
        }

        public Func<IDictionary<string, object>, Task<string>> TokenProvider { get; set; }
        public Func<IDictionary<string, object>, OwinRequestValidationOptions, string, Task<bool>> SignatureValidator { get; set; }
        public OwinRequestValidationOptions RequestValidationOptions { get; set; }

        internal void Validate()
        {
            if (TokenProvider == null) throw new ArgumentNullException("HttpSignatureValidationOptions.TokenProvider");
            if (SignatureValidator == null) throw new ArgumentNullException("HttpSignatureValidationOptions.SignatureValidator");
            if (RequestValidationOptions == null) throw new ArgumentNullException("HttpSignatureValidationOptions.RequestValidationOptions");
        }
    }
}

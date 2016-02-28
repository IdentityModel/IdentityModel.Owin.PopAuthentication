// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class HttpSignatureValidationOptions
    {
        public HttpSignatureValidationOptions()
        {
            TokenProvider = DefaultPopTokenProvider.GetPopTokenAsync;
            SignatureValidator = DefaultPopSignatureValidator.ValidateTokenAsync;
        }

        public Func<IDictionary<string, object>, Task<string>> TokenProvider { get; set; }
        public Func<IDictionary<string, object>, string, Task<bool>> SignatureValidator { get; set; }

        internal void Validate()
        {
            if (TokenProvider == null) throw new ArgumentNullException("HttpSignatureValidationOptions.TokenProvider");
            if (SignatureValidator == null) throw new ArgumentNullException("HttpSignatureValidationOptions.SignatureValidator");
        }
    }
}

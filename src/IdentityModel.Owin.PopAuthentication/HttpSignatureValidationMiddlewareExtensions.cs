// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using IdentityModel.Owin.PopAuthentication;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin
{
    public static class HttpSignatureValidationMiddlewareExtensions
    {
        public static void UseHttpSignatureValidation(this IAppBuilder app, HttpSignatureValidationOptions options)
        {
            app.Use<HttpSignatureValidationMiddleware>(options ?? new HttpSignatureValidationOptions());
        }

        public static void UseHttpSignatureValidation(this IAppBuilder app)
        {
            app.UseHttpSignatureValidation(null);
        }
    }
}

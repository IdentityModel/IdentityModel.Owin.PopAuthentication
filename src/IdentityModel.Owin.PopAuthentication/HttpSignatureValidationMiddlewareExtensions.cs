// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Owin.PopAuthentication;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using System;

namespace Owin
{
    public static class HttpSignatureValidationMiddlewareExtensions
    {
        public static void UseHttpSignatureValidation(this IAppBuilder app, HttpSignatureValidationOptions options)
        {
            app.Use(typeof(HttpSignatureValidationMiddleware), app, options ?? new HttpSignatureValidationOptions());
        }

        public static void UseHttpSignatureValidation(this IAppBuilder app, OwinRequestValidationOptions options)
        {
            if (options == null) throw new ArgumentNullException("options");

            app.Use(typeof(HttpSignatureValidationMiddleware), app, new HttpSignatureValidationOptions()
            {
                RequestValidationOptions = options
            });
        }

        public static void UseHttpSignatureValidation(this IAppBuilder app)
        {
            app.UseHttpSignatureValidation((HttpSignatureValidationOptions)null);
        }
    }
}

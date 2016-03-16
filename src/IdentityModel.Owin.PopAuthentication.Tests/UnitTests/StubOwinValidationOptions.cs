// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using IdentityModel.Owin.PopAuthentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModelOwinPopAuthentication.Tests.UnitTests
{
    public class StubOwinValidationOptions : OwinRequestValidationOptions
    {
        public EncodedParameters Result { get; set; }

        public override Task<EncodedParameters> ReadEncodedParametersAsync(IDictionary<string, object> env, EncodedParameters popValues)
        {
            var result = Result;

            if (result == null) result = popValues;

            return Task.FromResult(result);
        }
    }
}

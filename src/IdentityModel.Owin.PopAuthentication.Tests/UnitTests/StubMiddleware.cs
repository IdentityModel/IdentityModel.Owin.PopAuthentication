// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication.Tests.UnitTests
{
    public class StubMiddleware
    {
        public bool InvokeWasCalled { get; set; }

        public Task Invoke(IDictionary<string, object> env)
        {
            InvokeWasCalled = true;
            return Task.FromResult(0);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModelOwinPopAuthentication.Tests.UnitTests
{
    public class StubTokenProvider
    {
        public bool InvokeWasCalled { get; set; }
        public string Token { get; set; }

        public Task<string> Invoke(IDictionary<string, object> env)
        {
            InvokeWasCalled = true;
            return Task.FromResult(Token);
        }
    }
}

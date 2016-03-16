// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Principal;

namespace IdentityModelOwinPopAuthentication.Tests
{
    public class StubAuthenticationManager
    {
        public StubAuthenticationManager()
        {
        }

        public StubAuthenticationManager(IDictionary<string, object> env)
        {
            Attach(env);
        }

        public void Attach(IDictionary<string, object> env)
        {
            Func<string[], Action<IIdentity, IDictionary<string, string>, IDictionary<string, object>, object>, object, Task> f = this.Invoke;
            env.Add("security.Authenticate", f);
        }

        public ClaimsIdentity Identity { get; set; }

        public Task Invoke(string[] types, Action<IIdentity, IDictionary<string, string>, IDictionary<string, object>, object> callback, object state)
        {
            callback(Identity, new Dictionary<string, string>(), new Dictionary<string, object>(), state);
            return Task.FromResult(0);
        }
    }
}

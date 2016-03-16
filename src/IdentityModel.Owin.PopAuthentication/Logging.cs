// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.Owin.Logging;
using System;
using System.Diagnostics;

namespace IdentityModel.Owin.PopAuthentication
{
    internal static class Logging
    {
        static ILogger _logger;

        internal static void SetLogger(ILogger logger)
        {
            _logger = logger;
        }

        internal static ILogger GetLogger()
        {
            return _logger ?? (_logger = new NopLogger());
        }

        class NopLogger : ILogger
        {
            public bool WriteCore(TraceEventType eventType, int eventId, object state, Exception exception, Func<object, Exception, string> formatter)
            {
                return false;
            }
        }
    }
}

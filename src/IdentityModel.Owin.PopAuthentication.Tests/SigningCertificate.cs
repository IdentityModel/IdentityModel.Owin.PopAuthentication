// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication.Tests
{
    class SigningCertificate
    {
        public static X509Certificate2 Cert { get; set; }

        static SigningCertificate()
        {
            var assembly = typeof(SigningCertificate).Assembly;
            using (var stream = assembly.GetManifestResourceStream("IdentityModel.Owin.PopAuthentication.Tests.signing.test.pfx"))
            {
                Cert = new X509Certificate2(ReadStream(stream), "password");
            }
        }

        private static byte[] ReadStream(Stream input)
        {
            var buffer = new byte[16 * 1024];
            using (var ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.HttpSigning;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Owin.PopAuthentication
{
    public class OwinRequestValidationOptions
    {
        public TimeSpan TimespanValidityWindow { get; set; } = TimeSpan.FromMinutes(5);
        public bool ValidateMethod { get; set; }
        public bool ValidateHost { get; set; }
        public bool ValidatePath { get; set; }
        public IEnumerable<string> QueryParametersToValidate { get; set; }
        public IEnumerable<string> RequestHeadersToValidate { get; set; }
        public bool ValidateBody { get; set; }

        public virtual async Task<EncodedParameters> ReadEncodedParametersAsync(IDictionary<string, object> env, EncodedParameters popValues)
        {
            if (env == null) throw new ArgumentNullException("env");
            if (popValues == null) throw new ArgumentNullException("popValues");

            var logger = Logging.GetLogger();

            var ctx = new OwinContext(env);

            var parameters = new EncodingParameters(popValues.AccessToken);

            if (ValidateMethod)
            {
                logger.WriteVerbose("Validating method");
                parameters.Method = new HttpMethod(ctx.Request.Method);
            }

            if (ValidateHost)
            {
                logger.WriteVerbose("Validating host");
                parameters.Host = ctx.Request.Host.Value;
            }

            if (ValidatePath)
            {
                logger.WriteVerbose("Validating path");
                parameters.Path = ctx.Request.Uri.AbsolutePath;
            }

            var queryParamsToValidate = GetQueryParamsToValidate(ctx.Request.Query, popValues.QueryParameters?.Keys);
            foreach(var item in queryParamsToValidate)
            {
                logger.WriteVerbose("Validating query string parameter: " + item.Key);
                parameters.QueryParameters.Add(item);
            }

            var headersToValidate = GetRequestHeadersToValidate(ctx.Request.Headers, popValues.RequestHeaders?.Keys);
            foreach(var item in headersToValidate)
            {
                logger.WriteVerbose("Validating request header: " + item.Key);
                parameters.RequestHeaders.Add(item);
            }

            if (ValidateBody)
            {
                logger.WriteVerbose("Validating body");
                parameters.Body = await ReadBodyAsync(ctx.Request);
            }

            return parameters.Encode();
        }

        private IEnumerable<KeyValuePair<string, string>> GetQueryParamsToValidate(IEnumerable<KeyValuePair<string, string[]>> query, IEnumerable<string> expectedOrder)
        {
            if (QueryParametersToValidate == null || !QueryParametersToValidate.Any())
            {
                return Enumerable.Empty<KeyValuePair<string, string>>();
            }

            var list =
                (from q in query
                from v in q.Value
                where QueryParametersToValidate.Contains(q.Key)
                select new KeyValuePair<string, string>(q.Key, v)).ToList();

            if (expectedOrder != null && expectedOrder.Any())
            {
                var newList = new List<KeyValuePair<string, string>>();
                foreach(var key in expectedOrder)
                {
                    var item = list.Where(x => x.Key == key).OrderBy(x => x.Value, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
                    // check needed since it's a struct
                    if (item.Key == key)
                    {
                        list.Remove(item);
                        newList.Add(item);
                    }
                }
                return newList;
            }
            else
            {
                return list.OrderBy(x => x.Value, StringComparer.OrdinalIgnoreCase);
            }
        }

        private IEnumerable<KeyValuePair<string, string>> GetRequestHeadersToValidate(IEnumerable<KeyValuePair<string, string[]>> headers, IEnumerable<string> expectedOrder)
        {
            if (RequestHeadersToValidate == null || !RequestHeadersToValidate.Any())
            {
                return Enumerable.Empty<KeyValuePair<string, string>>();
            }

            var list =
                (from h in headers
                from v in h.Value
                where RequestHeadersToValidate.Contains(h.Key)
                select new KeyValuePair<string, string>(h.Key, v)).ToList();

            if (expectedOrder != null && expectedOrder.Any())
            {
                var newList = new List<KeyValuePair<string, string>>();
                foreach (var key in expectedOrder)
                {
                    var item = list.Where(x => x.Key == key).OrderBy(x => x.Value, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
                    // check needed since it's a struct
                    if (item.Key == key)
                    {
                        list.Remove(item);
                        newList.Add(item);
                    }
                }
                return newList;
            }
            else
            {
                return list.OrderBy(x => x.Value, StringComparer.OrdinalIgnoreCase);
            }
        }

        public async Task<byte[]> ReadBodyAsync(IOwinRequest request)
        {
            if (request == null) throw new ArgumentNullException("request");

            if (request.Body == null) return null;
            if (request.Body.CanRead == false) return null;

            if (!request.Body.CanSeek)
            {
                var copy = new MemoryStream();
                await request.Body.CopyToAsync(copy);
                copy.Seek(0L, SeekOrigin.Begin);
                request.Body = copy;
            }

            request.Body.Seek(0L, SeekOrigin.Begin);

            var bytes = new byte[request.Body.Length];
            await request.Body.ReadAsync(bytes, 0, bytes.Length);

            request.Body.Seek(0L, SeekOrigin.Begin);

            return bytes;
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Browser;
using System.Text.RegularExpressions;
using System.Threading;
using FlickrNet;

namespace DeanIS.Net
{
    /// <summary>
    /// Digest Authentication client for use in Windows Phone 7 Applications.
    /// </summary>
    public class DigestAuthenticationClient
    {
        private readonly string _userName;
        private readonly string _password;
        private string _realm;
        private string _nonce;
        private string _algorithm;
        private string _opaque;
        private string _qop;
        private string _cnonce;
        private int _nonceCount;
        private bool _authenticated;

        private HttpWebRequest _httpWebRequest;

        private AsyncCallback _asyncResultHandler;

        /// <summary>
        /// Initialize the digest authentication client with a username and password.
        /// </summary>
        /// <param name="userName">The username</param>
        /// <param name="password">The password</param>
        public DigestAuthenticationClient(string userName, string password)
        {
            _userName = userName;
            _password = password;
        }

        /// <summary>
        /// Get the response from the call to the given URL as a string.
        /// </summary>
        /// <param name="uri">The URI you're making a GET request to.</param>
        /// <param name="asyncResultHandler">the async callback called when complete.</param>
        public void GetResponseString(Uri uri, AsyncCallback asyncResultHandler)
        {
            GetResponseString(uri, asyncResultHandler, null);
        }

        /// <summary>
        /// Get the response from the call to the given URL as a string.
        /// </summary>
        /// <param name="uri">The URI you're making a GET request to.</param>
        /// <param name="asyncResultHandler">the async callback called when complete.</param>
        /// <param name="state">state to be included in the callback.</param>
        public void GetResponseString(Uri uri, AsyncCallback asyncResultHandler, object state)
        {
            _httpWebRequest = (HttpWebRequest)WebRequest.Create(uri);

            if (_authenticated)
            {
                _nonceCount++;
                _cnonce = GenerateNewCNonce();

                _httpWebRequest.Headers[HttpRequestHeader.Authorization] = GetAuthorizationHeader(uri);
            }


            _asyncResultHandler = asyncResultHandler;
            _httpWebRequest.BeginGetResponse(RequestCompleted, _httpWebRequest);
        }

        private string GetAuthorizationHeader(Uri uri)
        {
            var localPathAndQuery = GetLocalPathAndQuery(uri);

            var ha1 = MD5.GetMd5String(string.Format("{0}:{1}:{2}", _userName, _realm, _password));
            var ha2 = MD5.GetMd5String(string.Format("{0}:{1}", "GET", localPathAndQuery));
            var authResponse = MD5.GetMd5String(string.Format("{0}:{1}:{2:D8}:{3}:{4}:{5}", ha1, _nonce, _nonceCount, _cnonce, _qop, ha2));

            return "Digest username=\"" + _userName + "\"," +
                " realm=\"" + _realm + "\"," +
                " nonce=\"" + _nonce + "\"," +
                " uri=\"" + localPathAndQuery + "\"," +
                " algorithm=" + _algorithm + "," +
                " qop=" + _qop + "," +
                " nc=" + _nonceCount.ToString("D8") + "," +
                " cnonce=\"" + _cnonce + "\"," +
                " response=\"" + authResponse + "\"," +
                " opaque=\"" + _opaque + "\"";
        }

        private void RequestCompleted(IAsyncResult result)
        {
            var request = (HttpWebRequest)result.AsyncState;

            HttpWebResponse response;

            try
            {
                response = (HttpWebResponse)request.EndGetResponse(result);

                if (response == null) return;

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    _authenticated = true;
                    using (var streamReader = new StreamReader(response.GetResponseStream()))
                    {
                        var rawResponse = streamReader.ReadToEnd();
                        _asyncResultHandler(new DigestAuthenticationAsyncResult(rawResponse));
                    }
                }
                else
                {
                    _authenticated = false;
                    _asyncResultHandler(new DigestAuthenticationAsyncResult(null));
                }
            }
            catch (WebException e)
            {
                // probably failed to authenticate
                if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Unauthorized)
                {
                    var wwwAuthValue = (from object key in e.Response.Headers
                                        where (string)key == "WWW-Authenticate"
                                        select e.Response.Headers[(string)key]).FirstOrDefault();

                    if (string.IsNullOrEmpty(wwwAuthValue))
                    {
                        _asyncResultHandler(new DigestAuthenticationAsyncResult(null));
                    }
                    else
                    {
                        var authKeys = BuildParameterDictionary(wwwAuthValue);

                        _realm = authKeys["realm"];
                        _nonce = authKeys["nonce"];
                        _opaque = authKeys["opaque"];
                        _algorithm = authKeys["algorithm"];
                        _qop = authKeys["qop"];
                        _cnonce = GenerateNewCNonce();
                        _nonceCount = 1;

                        WebRequest.RegisterPrefix("http://", WebRequestCreator.ClientHttp);
                        var authenticatedRequest = (HttpWebRequest)WebRequest.Create(request.RequestUri);

                        authenticatedRequest.Headers[HttpRequestHeader.Authorization] =
                          GetAuthorizationHeader(request.RequestUri);

                        authenticatedRequest.BeginGetResponse(RequestCompleted, authenticatedRequest);

                    }
                }
            }
        }

        private static string GetLocalPathAndQuery(Uri uri)
        {
            return uri.LocalPath + uri.Query;
        }

        private static readonly Regex RegexNameValuePair = new Regex(@"(?<key>\w+)\s*=\s*((?<quote>\"")(?<value>[^\""]*)(\k<quote>)|(?<value>[^,]*))((,\s*)?)",
                                       RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.Singleline | RegexOptions.IgnoreCase);
        private static Dictionary<string, string> BuildParameterDictionary(string header)
        {
            header = header.Substring(7);

            var matches = RegexNameValuePair.Matches(header);

            return matches.Cast<Match>().ToDictionary(m => m.Groups["key"].Value, m => m.Groups["value"].Value);
        }

        private static string GenerateNewCNonce()
        {
            return Guid.NewGuid().ToString().Replace("-", string.Empty);
        }
    }

    internal class DigestAuthenticationAsyncResult : IAsyncResult
    {
        private readonly string _responseString;

        public DigestAuthenticationAsyncResult(string responseString)
        {
            _responseString = responseString;
        }

        public bool IsCompleted
        {
            get { return this.IsCompleted; }
        }

        public WaitHandle AsyncWaitHandle
        {
            get { return this.AsyncWaitHandle; }
        }

        public object AsyncState
        {
            get { return _responseString; }
        }

        public bool CompletedSynchronously
        {
            get { return this.CompletedSynchronously; }
        }
    }
}

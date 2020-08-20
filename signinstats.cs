using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Collections.Generic;
using System.Net.Http.Headers;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Linq;
using StackExchange.Redis;

namespace net.blomart.signinstats
{
    public class StreamSignin {
        public String TimeGenerated;
        public String UPN;
        public String Domain;
        public String Source;
        public String ClientAppUsed;
        public String AppDisplayName;
        public int Count;
    }

    // request in a batch query
    public class Request {
        public int Id;
        public string Method;
        public string Url;
    }

    // responses in batch query
    public class Response {
        public int Id;
        public int Status;
        public dynamic Body;
    }

    // requests from batch query
    public class BatchRequests {
        public List<Request> Requests;
        public int Add(HttpMethod method, string url) {
            var request = new Request();
            request.Id = Requests.Count;
            request.Method = method.Method;
            request.Url = url;
            Requests.Add(request);
            return request.Id;
        }

        public BatchRequests() {
            Requests = new List<Request>();
        }
    }

    // responses from batch query
    public class BatchResponses {
        public List<Response> Responses;
    }

    public static class SignInStats
    {
        
        const string loginUrl = "https://login.windows.net";
        const string resource = "https://graph.microsoft.com";
        const string getUserInfos = "/users/{0}?$select=userprincipalname,companyname";
        const string batchQuery = "{0}/beta/$batch";
        const int wait = 15;
        const int maxwait = 600;
        const string workspaceUrl = "https://{0}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01";
        static string token = "";
        static int waitfactor = 1;
        static DateTime tokenValidity = DateTime.Now;
        //static HttpClient cli;

        private static bool CheckThrottle(ILogger log, HttpStatusCode statusCode, string content) {
            if (statusCode != HttpStatusCode.TooManyRequests) {
                return false;
            }
            var curWait = getWait();
            waitfactor += 1;
            log.LogWarning($"request throttled. waiting {curWait}s ...");
            var timestamp = "";
            var requestId = "";
            if (!string.IsNullOrWhiteSpace(content)) {
                IDictionary<string,JToken> errorData = JObject.Parse(content);
                if (errorData.ContainsKey("error")) {
                    timestamp = (string)errorData["error"]["innerError"]["date"]; 
                    requestId = (string)errorData["error"]["innerError"]["request-id"];
                }
            }
            if (!string.IsNullOrWhiteSpace(timestamp) && !string.IsNullOrWhiteSpace(requestId)) {
                log.LogWarning($"throttled info: date={timestamp}; request-id={requestId};");
            }
            Thread.Sleep(getWait() * 1000);
            return true;
        }

        private static void CheckRestResp(HttpStatusCode statusCode, string content, ILogger log) {
            if (statusCode != HttpStatusCode.OK || string.IsNullOrWhiteSpace(content)) {
                var error = "unknown";
                if (!string.IsNullOrWhiteSpace(content)) {
                    try {
                        IDictionary<string,JToken> errorData = JObject.Parse(content);
                        if (errorData.ContainsKey("error")) {
                            var node = errorData["error"];
                            if (node is JValue) {
                                error =  ((JValue)node).ToString();
                            } else if (node is JObject) {
                                var obj = (JObject)node;
                                JToken value;
                                if (obj.TryGetValue("message",StringComparison.CurrentCultureIgnoreCase,out value)) {
                                    error = ((JValue)value).ToString();
                                }
                            }
                        }
                    } catch (Exception) {
                        log.LogError($"error parsing response: {content}");
                        throw;
                    }
                }
                throw new Exception($"request failed: {error}");
            }
            if (statusCode == HttpStatusCode.OK && waitfactor>1) {
                waitfactor = 1;
            }
        }

        private static int getWait() {
            return (wait * waitfactor * waitfactor > maxwait) ? maxwait : wait * waitfactor * waitfactor;
        }

        private static HttpClient GetHttpClient() {
            var handler = new HttpClientHandler();
            handler.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
            return new HttpClient(handler);
        }

        private static async Task Authenticate(ILogger log) {
            // get environment variable
            var clientId = System.Environment.GetEnvironmentVariable("ClientID", EnvironmentVariableTarget.Process);
            var clientSecret = System.Environment.GetEnvironmentVariable("ClientSecret", EnvironmentVariableTarget.Process);
            var tenant = System.Environment.GetEnvironmentVariable("Tenant", EnvironmentVariableTarget.Process);
            // TODO: check proper validity
            if (!string.IsNullOrWhiteSpace(token) && tokenValidity > DateTime.Now) {
                log.LogInformation($"Authenticated to {tenant}/{clientId} with valid token");
                return;
            }
            // get an http client
            var cli = GetHttpClient();
            // Authenticate
            log.LogInformation($"Authenticating to {tenant}/{clientId}");
            var data = new Dictionary<string,string>();
            data.Add("grant_type","client_credentials");
            data.Add("resource",resource);
            data.Add("client_id",clientId);
            data.Add("client_secret",clientSecret);
            var content = new FormUrlEncodedContent(data);
            var res = await cli.PostAsync($"{loginUrl}/{tenant}/oauth2/token",content);
            var respContent = await res.Content.ReadAsStringAsync();
            CheckRestResp(res.StatusCode,respContent,log);
            IDictionary<string,JToken> tokenData = JObject.Parse(respContent);
            if (tokenData.ContainsKey("access_token") && tokenData.ContainsKey("expires_in")) {
                token = (string)tokenData["access_token"];
                tokenValidity = DateTime.Now.AddSeconds((int)tokenData["expires_in"]);
            } else {
                throw new Exception("Token not found in response");
            }
        }

        public static string BuildSignature(string message, string secret)
		{
            var encoding = new System.Text.ASCIIEncoding();
			byte[] keyBytes = Convert.FromBase64String(secret);
			byte[] messageBytes = encoding.GetBytes(message);
			using (var hmacsha256 = new HMACSHA256(keyBytes))
			{
				byte[] hash = hmacsha256.ComputeHash(messageBytes);
				return Convert.ToBase64String(hash);
			}
		}

        // Submit stream stats to Log Analytics. Stream stat have a time generated field
        private static async Task StreamSubmit(ILogger log, List<StreamSignin> stats) {
            // get the informations to send to log analytics
            var workspaceId = System.Environment.GetEnvironmentVariable("WorkspaceId", EnvironmentVariableTarget.Process);
            var workspaceKey = System.Environment.GetEnvironmentVariable("WorkspaceKey", EnvironmentVariableTarget.Process);
            if (string.IsNullOrWhiteSpace(workspaceId) || string.IsNullOrWhiteSpace(workspaceKey)) {
                throw new Exception("workspace not properly set");
            }
            // get the http client
            var cli  = GetHttpClient();
            // submit values
            var payload = JsonConvert.SerializeObject(stats);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var d = DateTime.UtcNow;
            var date = d.ToString("r");
            //var isodate = generated.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var rawsignature = $"POST\n{payloadBytes.Length}\napplication/json\nx-ms-date:{date}\n/api/logs";
            var signature = BuildSignature(rawsignature,workspaceKey);
            var content = new StringContent(payload,Encoding.UTF8);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            // remove authorization
            cli.DefaultRequestHeaders.Remove("Authorization");
            // do the request
            var httpreq = new HttpRequestMessage();
            httpreq.Headers.Add("Authorization",$"SharedKey {workspaceId}:{signature}");
            httpreq.Headers.Add("Accept", "application/json");
            httpreq.Headers.Add("Log-Type","SigninStat");
            httpreq.Headers.Add("x-ms-date",date);
            httpreq.Headers.Add("time-generated-field","TimeGenerated");
            httpreq.Headers.Add("raw-signature",string.Join(',',rawsignature.Split("\n")));
            httpreq.Content = content;
            httpreq.Method = HttpMethod.Post;
            httpreq.RequestUri = new Uri(string.Format(workspaceUrl,workspaceId));
            var res = await cli.SendAsync(httpreq);
            log.LogInformation($"log url: {httpreq.RequestUri.ToString()}");
            // check send
            if (res.StatusCode != HttpStatusCode.OK) {
                log.LogWarning($"error response: {await res.Content.ReadAsStringAsync()}");
                throw new Exception($"Data not sent to log analytics: {res.StatusCode}");
            } 
        }

        [FunctionName("ProcessSigninStream")]
        public static async Task<IActionResult> ProcessSigninStream(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log) {
            log.LogInformation($"Stream Signin logs");
            var val = await req.ReadAsStringAsync();
            var stats = JsonConvert.DeserializeObject<List<StreamSignin>>(val);
            log.LogInformation($"Recieved {stats.Count} signin stats");
            // get unique upns
            var upns = stats.Select(x => x.UPN.ToLowerInvariant()).Distinct().ToList();
            // Setup http client 
            var cli = GetHttpClient();
            // initiate client
            await Authenticate(log);
            // Set the authentication header
            cli.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", token);
            cli.DefaultRequestHeaders.Add("Accept", "application/json");
            // configure redis cache
            var connString = System.Environment.GetEnvironmentVariable("redis", EnvironmentVariableTarget.Process);
            var redis = ConnectionMultiplexer.Connect(connString);
            IDatabase db = redis.GetDatabase();
            var usersCompany = new Dictionary<string,string>();
            // store companies in dictionary
            var toResolve = new List<string>();
            foreach(var upn in upns) {
                var company = await db.StringGetAsync(upn);
                if (company.HasValue) {
                    usersCompany.Add(upn,company);
                } else {
                    toResolve.Add(upn);
                }
            }
            log.LogInformation($"recieving domain details of {toResolve.Count} users");
            // collect upns company information
            // prepare requests
            var requests = new BatchRequests();
            foreach(var upn in toResolve) {
                requests.Add(HttpMethod.Get,string.Format(getUserInfos,upn));
            }
            log.LogInformation("starting batch query for companies");
            var j = 0;
            do {
                var batch = requests.Requests.Skip(j++*20).Take(20).ToList();
                if (batch.Count() == 0) {
                    break;
                }
                var batchreq = new BatchRequests();
                batchreq.Requests.AddRange(batch);
                var batchJson = JsonConvert.SerializeObject(batchreq);
                var content = new StringContent(batchJson,Encoding.UTF8);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                var res = await cli.PostAsync(string.Format(batchQuery,resource),content);
                var respContent = await res.Content.ReadAsStringAsync();
                if (CheckThrottle(log,res.StatusCode,respContent)) {
                    continue;
                }
                try {
                    CheckRestResp(res.StatusCode, respContent, log);
                } catch (Exception e) {
                    log.LogError(e.Message);
                    return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                }
                var batchResp = JsonConvert.DeserializeObject<BatchResponses>(respContent);
                var succesresp = batchResp.Responses.Where(x => x.Status == 200);
                foreach(var resp in succesresp) {
                    var upn = (string)resp?.Body?.userPrincipalName;
                    var company = (string)resp?.Body?.companyName;
                    if (!string.IsNullOrWhiteSpace(company) && !string.IsNullOrWhiteSpace(upn)) {
                        var stdupn = upn.ToLowerInvariant();
                        await db.StringSetAsync(stdupn,company,TimeSpan.FromHours(4));
                        usersCompany[stdupn] = company;
                        toResolve.Remove(stdupn);
                    }
                }
            } while (j*20 <= upns.Count);
            log.LogInformation($"Collected {usersCompany.Count} users companies");
            // set the rest of upns to "Cloud"
            foreach(var upn in toResolve) {
                log.LogInformation($"unresolved company for {upn} [Cloud]");
                await db.StringSetAsync(upn,"Cloud",TimeSpan.FromHours(4));
                usersCompany[upn] = "Cloud";
            }
            // update stats with company and time
            foreach(var stat in stats) {
                var stdupn = stat.UPN.ToLowerInvariant();
                stat.Source = usersCompany[stdupn];
                var mailaddr = new MailAddress(stdupn);
                stat.Domain = mailaddr.Host;
            }
            log.LogInformation("Enriched stats information with companies");
            // check for empty client types
            var okstats = stats.Where(s => !string.IsNullOrWhiteSpace(s.ClientAppUsed)).ToList();
            var nokstats = stats.Where(s => string.IsNullOrWhiteSpace(s.ClientAppUsed)).ToList();
            if (nokstats.Count > 0) {
                log.LogCritical($"invalid stat: {nokstats.Count}");
            }
            await StreamSubmit(log,okstats);
            return new OkResult();
        }
    }
}

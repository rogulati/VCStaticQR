using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using System.Xml.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Web;
using Microsoft.Extensions.DependencyInjection;
using Polly;
using Azure.Core;

namespace VCStaticIssuance
{
    public class VCissuanceFunction
    {
        //private readonly HttpClient _httpClient;
        private readonly IHttpClientFactory _factory;

        private ILogger _log;

        public VCissuanceFunction(IHttpClientFactory factory)
        {
            this._factory = factory;
        }

        [FunctionName("getIssuanceRequest")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req, ILogger log, ExecutionContext context)
            
        {
            _log = log;
            log.LogInformation("C# HTTP trigger function processed a request.");


            var clientId = getEnvironmentvariable("ClientId");
            var tenantId = getEnvironmentvariable("TenantId");
            var clientSecret = getEnvironmentvariable("ClientSecret");
            var registrationPurpose = getEnvironmentvariable("RegistrationPurpose");
            var issuerAuthority = getEnvironmentvariable("IssuerAuthority");
            var clientName = getEnvironmentvariable("ClientName");

            const string ISSUANCEPAYLOAD = "issuance_request_config.json";
            
            String jsonString = null;
            //they payload template is loaded from disk and modified in the code below to make it easier to get started
            //and having all config in a central location, settings from your function or your local.settings.json. 
            //if you want to manually change the payload in the json file make sure you comment out the code below which will modify it automatically
            //
            string payloadpath = Path.Combine(context.FunctionAppDirectory, ISSUANCEPAYLOAD);
            _log.LogTrace("IssuanceRequest file: {0}", payloadpath);

            if (!System.IO.File.Exists(payloadpath))
            {
                _log.LogError("File not found: {0}", payloadpath);
                return new BadRequestObjectResult(ISSUANCEPAYLOAD + " not found");
            }
            jsonString = System.IO.File.ReadAllText(payloadpath);
            if (string.IsNullOrEmpty(jsonString))
            {
                _log.LogError("Error reading file: {0}", payloadpath);
                return new BadRequestObjectResult(ISSUANCEPAYLOAD + " error reading file");
            }
            
            string state = Guid.NewGuid().ToString();

            //modify payload with new state, the state is used to be able to update the UI when callbacks are received from the VC Service
            JObject payload = JObject.Parse(jsonString);
            if (payload["callback"]["state"] != null)
            {
                payload["callback"]["state"] = state;
            }


            //get the VerifierDID from the appsettings
            if (payload["authority"] != null)
            {
                payload["authority"] = issuerAuthority;
            }

            //we are ignoring the callback by passing it to example.com, we could add the callback later for some data collection
            payload["registration"]["purpose"] = registrationPurpose;
            payload["registration"]["clientName"] = clientName;

            jsonString = JsonConvert.SerializeObject(payload);

            //CALL REST API WITH PAYLOAD
            HttpStatusCode statusCode = HttpStatusCode.OK;
            string response = null;
            try
            {
                //The VC Request API is an authenticated API. We need to clientid and secret (or certificate) to create an access token which 
                //needs to be send as bearer to the VC Request API
                var accessToken = await GetAccessToken();
                if (accessToken.Item1 == String.Empty)
                {
                    _log.LogError(String.Format("failed to acquire accesstoken: {0} : {1}"), accessToken.error, accessToken.error_description);
                    return new BadRequestObjectResult(accessToken.error_description);
                }

                _log.LogInformation($"Request API payload: {jsonString}");

                HttpClient _httpClient = _factory.CreateClient();

                var defaultRequestHeaders = _httpClient.DefaultRequestHeaders;
                defaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.token);

                HttpResponseMessage res = await _httpClient.PostAsync("https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest", new StringContent(jsonString, Encoding.UTF8, "application/json"));


                response = await res.Content.ReadAsStringAsync();
                statusCode = res.StatusCode;

                if (statusCode == HttpStatusCode.Created)
                {
                    _log.LogInformation("succesfully called Request API");
                    JObject requestConfig = JObject.Parse(response);
                    _log.LogInformation("returned from API: " + response);
                    //url is in format {openid-vc://?request_uri=https://beta.did.msidentity.com/v1.0/tenants/a0543408-3932-4ef9-b3e3-6c19ef8f2392/verifiablecredentials/issuanceRequests/471463c4-c642-4c79-9ac1-890de1fecb26}
                    var requestUrl = requestConfig["url"].ToString();
                    requestUrl = requestUrl.Split("openid-vc://?request_uri=")[1];

                    _log.LogInformation("streaming back request from " + requestUrl);
                    //download the request and stream it back to the caller
                    //but make sure to wait at least 10 msec for the request to be synced to all databases

                    //System.Threading.Thread.Sleep(100);
                    var pollyClient = _factory.CreateClient();

                    //retry if you get a not found since it might take a while to sync the requests
                    var pollyContext = new Context("Retry Not Found");
                    var policy = Policy
                        .Handle<HttpRequestException>(ex => ex.Message.Contains("404"))
                        .WaitAndRetryAsync(
                            5,
                            _ => TimeSpan.FromMilliseconds(1),
                            (result, timespan, retryNo, context) =>
                            {
                                Console.WriteLine($"{context.OperationKey}: Retry number {retryNo} within " +
                                    $"{timespan.TotalMilliseconds}ms. Original status code: 404");
                            }
                        );

                    var VCreq = await policy.ExecuteAsync(async ctx =>
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(requestUrl));
                        var response = await _httpClient.SendAsync(request);
                        response.EnsureSuccessStatusCode();
                        return response;
                    }, pollyContext);


                    //HttpResponseMessage VCreq = await pollyClient.GetAsync(requestUrl);

                    string VCreqresponse = await VCreq.Content.ReadAsStringAsync();
                    if (VCreq.StatusCode != HttpStatusCode.OK)
                    {
                        _log.LogInformation("request:" + VCreqresponse);
                        return new NotFoundObjectResult(VCreqresponse);
                    }
                    return new OkObjectResult(VCreqresponse);
                }
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult("Something went wrong calling the API: " + ex.Message);
            }





            return new BadRequestObjectResult("something went wrong!");

        }

        private async Task<(string token, string error, string error_description)> GetAccessToken()
        {

            // Since we are using application permissions this will be a confidential client application
            IConfidentialClientApplication app;
            app = ConfidentialClientApplicationBuilder.Create(getEnvironmentvariable("ClientId"))
                .WithClientSecret(getEnvironmentvariable("ClientSecret"))
                .WithAuthority(String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}", getEnvironmentvariable("TenantId")))
                .Build();

            //configure in memory cache for the access tokens. The tokens are typically valid for 60 seconds,
            //so no need to create new ones for every web request
            app.AddDistributedTokenCache(services =>
            {
                services.AddDistributedMemoryCache();
                services.AddLogging(configure => configure.AddConsole())
                .Configure<LoggerFilterOptions>(options => options.MinLevel = Microsoft.Extensions.Logging.LogLevel.Debug);
            });

            // With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
            // application permissions need to be set statically (in the portal or by PowerShell), and then granted by
            // a tenant administrator. 
            string[] scopes = new string[] { "3db474b9-6a0c-4840-96ac-1fceb342124f/.default" };

            AuthenticationResult result = null;
            try
            {
                result = await app.AcquireTokenForClient(scopes)
                    .ExecuteAsync();
            }
            catch (MsalServiceException ex) when (ex.Message.Contains("AADSTS70011"))
            {
                // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
                // Mitigation: change the scope to be as expected
                return (string.Empty, "500", "Scope provided is not supported");
                //return BadRequest(new { error = "500", error_description = "Scope provided is not supported" });
            }
            catch (MsalServiceException ex)
            {
                // general error getting an access token
                return (String.Empty, "500", "Something went wrong getting an access token for the client API:" + ex.Message);
                //return BadRequest(new { error = "500", error_description = "Something went wrong getting an access token for the client API:" + ex.Message });
            }
            if (result.AuthenticationResultMetadata.TokenSource == TokenSource.Cache)
            {
                _log.LogInformation("much effiencey, much accesstoken from cache");
            }
            else
            {
                _log.LogInformation("new accesstoken");
            }
            return (result.AccessToken, String.Empty, String.Empty);
        }

        public static string getEnvironmentvariable(string name)
        {
            return System.Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
        }
    }
}

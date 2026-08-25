using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IocEnrichmentEngine;

internal enum IndicatorKind
{
    Hash,
    IpAddress,
    Domain
}

internal enum ExitCode
{
    AnalysisComplete = 0,
    MaliciousIndicator = 1,
    InvalidUsage = 2,
    OperationalFailure = 3
}

internal sealed record ApiResult(bool Succeeded, int? StatusCode, string? Body, string? ErrorMessage)
{
    public static ApiResult Ok(int statusCode, string body) => new(true, statusCode, body, null);

    public static ApiResult Fail(string message, int? statusCode = null) => new(false, statusCode, null, message);
}

internal sealed class RunState
{
    public bool HighRiskDetected { get; private set; }

    public bool FailureLogged { get; private set; }

    public void FlagHighRisk() => HighRiskDetected = true;

    public void FlagFailure() => FailureLogged = true;
}

internal static partial class Program
{
    private const string ToolName = "IocEnrichmentEngine";
    private const string ToolVersion = "v1.0";
    private const string Banner = $"{ToolName} {ToolVersion} - Threat Intelligence Lookup Tool";
    private const string CopyrightNotice = "Copyright (c) 2026 barbiegivesoutcookies. All Rights Reserved.";
    private const string AttributionSignature = "barbiegivesoutcookies";
    private const string ReportFileName = "triage_report.txt";

    private const string VirusTotalFileEndpoint = "https://www.virustotal.com/api/v3/files/";
    private const string IpapiGeolocationEndpointFormat = "https://ipapi.co/{0}/json/";
    private const string AbuseIpdbCheckEndpoint = "https://api.abuseipdb.com/api/v2/check";
    private const string UrlhausHostEndpoint = "https://urlhaus-api.abuse.ch/v1/host/";

    private const int RequestTimeoutSeconds = 30;
    private const int AbuseIpdbHighConfidenceThreshold = 50;

    private static readonly HttpClient SharedHttp = BuildSharedHttpClient();

    public static async Task<int> Main(string[] args)
    {
        TextWriter originalOutput = Console.Out;
        TeeTextWriter teeOutput = new(originalOutput);
        Console.SetOut(teeOutput);
        try
        {
            if (!TryParseArguments(args, out IndicatorKind kind, out string indicator))
            {
                PrintBanner();
                PrintUsage(string.Join(' ', args));
                return (int)ExitCode.InvalidUsage;
            }

            PrintBanner();
            RunState state = new();
            switch (kind)
            {
                case IndicatorKind.Hash:
                    await RunHashRoutineAsync(indicator.ToLowerInvariant(), state).ConfigureAwait(false);
                    break;
                case IndicatorKind.IpAddress:
                    await RunIpRoutineAsync(indicator, state).ConfigureAwait(false);
                    break;
                default:
                    await RunDomainRoutineAsync(indicator, state).ConfigureAwait(false);
                    break;
            }

            PrintSummary(state);
            FlushLogToFile(teeOutput);
            return DetermineExitCode(state);
        }
        finally
        {
            Console.SetOut(originalOutput);
        }
    }

    private static void FlushLogToFile(TeeTextWriter teeOutput)
    {
        try
        {
            string capturedOutput = teeOutput.Captured;
            StringBuilder report = new();
            report.AppendLine($"Report Author Attribution: {AttributionSignature}");
            report.AppendLine();
            report.Append(capturedOutput);
            File.WriteAllText(ReportFileName, report.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            WriteLineColored(
                $" [+] Signed report written to '{Path.GetFullPath(ReportFileName)}'.",
                ConsoleColor.Green);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            WriteLineColored(
                $" [X] REPORT LOGGING ERROR: unable to write signed report '{ReportFileName}': {ex.Message}",
                ConsoleColor.Red);
        }
    }

    private static int DetermineExitCode(RunState state)
    {
        if (state.HighRiskDetected)
        {
            return (int)ExitCode.MaliciousIndicator;
        }

        if (state.FailureLogged)
        {
            return (int)ExitCode.OperationalFailure;
        }

        return (int)ExitCode.AnalysisComplete;
    }

    private static HttpClient BuildSharedHttpClient()
    {
        HttpClient client = new()
        {
            Timeout = TimeSpan.FromSeconds(RequestTimeoutSeconds)
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(ToolName, "1.0"));
        return client;
    }

    private static bool TryParseArguments(string[] args, out IndicatorKind kind, out string indicator)
    {
        kind = IndicatorKind.Domain;
        indicator = string.Empty;

        if (args.Length != 2)
        {
            return false;
        }

        switch (args[0].ToLowerInvariant())
        {
            case "--hash":
                kind = IndicatorKind.Hash;
                if (!Sha256HexPattern().IsMatch(args[1]))
                {
                    return false;
                }
                break;
            case "--ip":
                kind = IndicatorKind.IpAddress;
                if (!IPAddress.TryParse(args[1], out IPAddress? parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)
                {
                    return false;
                }
                break;
            case "--domain":
                kind = IndicatorKind.Domain;
                if (!HostnamePattern().IsMatch(args[1]))
                {
                    return false;
                }
                break;
            default:
                return false;
        }

        indicator = args[1];
        return true;
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256HexPattern();

    [GeneratedRegex("^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$")]
    private static partial Regex HostnamePattern();
    private static async Task<ApiResult> SendAsync(HttpRequestMessage request)
    {
        try
        {
            using HttpResponseMessage response = await SharedHttp.SendAsync(request).ConfigureAwait(false);
            string payload = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return ApiResult.Ok((int)response.StatusCode, payload);
        }
        catch (HttpRequestException ex)
        {
            return ApiResult.Fail($"connection failure: {ex.Message}");
        }
        catch (TaskCanceledException)
        {
            return ApiResult.Fail($"request timed out after {RequestTimeoutSeconds}s");
        }
        catch (InvalidOperationException ex)
        {
            return ApiResult.Fail($"invalid request configuration: {ex.Message}");
        }
    }

    private static bool IsSuccessStatus(int? statusCode) => statusCode is >= 200 and < 300;

    private static int ReadIntOrDefault(JsonElement parent, string propertyName, int defaultValue = 0) =>
        parent.TryGetProperty(propertyName, out JsonElement value) && value.TryGetInt32(out int parsed)
            ? parsed
            : defaultValue;

    private static string ReadStringOrDefault(JsonElement parent, string propertyName, string defaultValue = "n/a") =>
        parent.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? defaultValue
            : defaultValue;

    private static void PrintBanner()
    {
        string rule = new('=', 80);
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(rule);
        Console.WriteLine(Banner);
        Console.WriteLine(CopyrightNotice);
        Console.WriteLine(rule);
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintSectionHeader(string title)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(" ----------------------------------------------------------------");
        Console.WriteLine($"  {title}");
        Console.WriteLine(" ----------------------------------------------------------------");
        Console.ResetColor();
    }

    private static void PrintSummary(RunState state)
    {
        Console.WriteLine();
        PrintSectionHeader("SUMMARY");
        if (state.HighRiskDetected)
        {
            WriteLineColored(" [!] ANALYSIS RESULT: HIGH-RISK INDICATOR CONFIRMED (exit code 1).", ConsoleColor.Red);
        }
        else if (state.FailureLogged)
        {
            WriteLineColored(" [!] ANALYSIS RESULT: ENRICHMENT FINISHED WITH ERRORS - RESULTS MAY BE INCOMPLETE (exit code 3).", ConsoleColor.Yellow);
        }
        else
        {
            WriteLineColored(" [+] ANALYSIS RESULT: NO HIGH-RISK FINDINGS (exit code 0).", ConsoleColor.Green);
        }
    }

    private static void PrintUsage(string suppliedArgs)
    {
        Console.WriteLine();
        WriteLineColored(
            string.IsNullOrWhiteSpace(suppliedArgs)
                ? " [!] Missing arguments."
                : $" [!] Invalid or unrecognized arguments: \"{suppliedArgs}\"",
            ConsoleColor.Yellow);
        Console.WriteLine();
        Console.WriteLine(" USAGE:");
        Console.WriteLine($"   {ToolName} <type_flag> <indicator_value>");
        Console.WriteLine();
        Console.WriteLine(" FLAGS:");
        Console.WriteLine("   --hash     SHA-256 file hash, exactly 64 hexadecimal characters");
        Console.WriteLine("   --ip       IPv4 address");
        Console.WriteLine("   --domain   Fully qualified domain name (FQDN)");
        Console.WriteLine();
        Console.WriteLine(" ENVIRONMENT:");
        Console.WriteLine("   VT_API_KEY          VirusTotal v3 API key (reliable hash lookups)");
        Console.WriteLine("   ABUSEIPDB_API_KEY   AbuseIPDB v2 API key (IP abuse reputation)");
        Console.WriteLine("   URLHAUS_AUTH_KEY    abuse.ch URLhaus Auth-Key (domain feed lookups)");
        Console.WriteLine();
        Console.WriteLine(" EXIT CODES:");
        Console.WriteLine("   0  analysis complete, no high-risk findings");
        Console.WriteLine("   1  malicious or high-risk indicator detected");
        Console.WriteLine("   2  invalid syntax or missing arguments");
        Console.WriteLine("   3  network or API error during enrichment");
        Console.WriteLine();
        Console.WriteLine(" EXAMPLES:");
        Console.WriteLine($"   {ToolName} --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        Console.WriteLine($"   {ToolName} --ip 8.8.8.8");
        Console.WriteLine($"   {ToolName} --domain wikipedia.org");
        Console.WriteLine();
    }

    private static void WriteLineColored(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private static void ReportOperationalError(string source, string detail, RunState state)
    {
        state.FlagFailure();
        WriteLineColored($" [X] {source} ERROR: {detail}", ConsoleColor.Red);
    }
    private static async Task RunHashRoutineAsync(string sha256, RunState state)
    {
        string? apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
        bool authenticated = !string.IsNullOrWhiteSpace(apiKey);

        PrintSectionHeader("HASH ROUTINE - VIRUSTOTAL V3 FILE REPORT");
        Console.WriteLine(authenticated
            ? " [+] Hash Auth: VIRUSTOTAL (authenticated)"
            : " [+] Hash Auth: ANONYMOUS FEED FALLBACK");

        using HttpRequestMessage request = new(HttpMethod.Get, VirusTotalFileEndpoint + sha256);
        if (authenticated)
        {
            request.Headers.Add("x-apikey", apiKey);
        }

        ApiResult result = await SendAsync(request).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            ReportOperationalError("VirusTotal", result.ErrorMessage!, state);
            return;
        }

        if (!authenticated && result.StatusCode is 401 or 403)
        {
            WriteLineColored(
                " [!] VirusTotal anonymous access refused (HTTP 401): rate-limited, set VT_API_KEY for reliable access.",
                ConsoleColor.Yellow);
            return;
        }

        if (result.StatusCode == 404)
        {
            WriteLineColored(
                " [-] File hash is unknown to VirusTotal (HTTP 404): no analysis history exists for this artifact.",
                ConsoleColor.Green);
            return;
        }

        if (result.StatusCode == 429)
        {
            if (authenticated)
            {
                ReportOperationalError("VirusTotal", "request quota exceeded (HTTP 429)", state);
            }
            else
            {
                WriteLineColored(
                    " [!] VirusTotal anonymous quota exhausted (HTTP 429): rate-limited, set VT_API_KEY for reliable access.",
                    ConsoleColor.Yellow);
            }
            return;
        }

        if (!IsSuccessStatus(result.StatusCode))
        {
            ReportOperationalError("VirusTotal", $"unexpected HTTP status {result.StatusCode}", state);
            return;
        }

        try
        {
            ParseVirusTotalReport(result.Body!, state);
        }
        catch (JsonException ex)
        {
            ReportOperationalError("VirusTotal", $"malformed JSON payload: {ex.Message}", state);
        }
    }

    private static void ParseVirusTotalReport(string payload, RunState state)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        JsonElement root = document.RootElement;

        if (!root.TryGetProperty("data", out JsonElement data) ||
            !data.TryGetProperty("attributes", out JsonElement attributes) ||
            !attributes.TryGetProperty("last_analysis_stats", out JsonElement stats))
        {
            throw new JsonException("expected data.attributes.last_analysis_stats structure was missing");
        }

        int malicious = ReadIntOrDefault(stats, "malicious");
        int suspicious = ReadIntOrDefault(stats, "suspicious");
        int harmless = ReadIntOrDefault(stats, "harmless");
        int undetected = ReadIntOrDefault(stats, "undetected");
        int timeouts = ReadIntOrDefault(stats, "timeout");
        string threatLabel = attributes.TryGetProperty("popular_threat_classification", out JsonElement classification)
            ? ReadStringOrDefault(classification, "suggested_threat_label", "not classified")
            : "not classified";

        Console.WriteLine(" [-] VirusTotal reputation scorecard:");
        Console.WriteLine($"     malicious   : {malicious}");
        Console.WriteLine($"     suspicious  : {suspicious}");
        Console.WriteLine($"     harmless    : {harmless}");
        Console.WriteLine($"     undetected  : {undetected}");
        Console.WriteLine($"     timeout     : {timeouts}");
        Console.WriteLine($"     threat label: {threatLabel}");

        if (malicious > 0)
        {
            state.FlagHighRisk();
            WriteLineColored(
                $" [!] VERDICT: MALICIOUS - flagged by {malicious} detection engine(s).",
                ConsoleColor.Red);
        }
        else if (suspicious > 0)
        {
            WriteLineColored(
                $" [~] VERDICT: SUSPICIOUS - {suspicious} engine(s) reported suspicious behavior.",
                ConsoleColor.Yellow);
        }
        else
        {
            WriteLineColored(
                $" [+] VERDICT: CLEAN - no detections across {harmless + undetected} reporting engine(s).",
                ConsoleColor.Green);
        }
    }
    private static async Task RunIpRoutineAsync(string ipAddress, RunState state)
    {
        string? abuseKey = Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY");
        bool abuseAuthenticated = !string.IsNullOrWhiteSpace(abuseKey);

        PrintSectionHeader("IP ROUTINE - IPAPI.CO CONTEXT + ABUSEIPDB REPUTATION");
        Console.WriteLine(abuseAuthenticated
            ? " [+] IP Auth: ABUSEIPDB (authenticated)"
            : " [+] IP Auth: ANONYMOUS (AbuseIPDB skipped, geolocation only)");

        await CollectIpapiContextAsync(ipAddress, state).ConfigureAwait(false);

        if (abuseAuthenticated)
        {
            await CollectAbuseIpdbReputationAsync(ipAddress, abuseKey!, state).ConfigureAwait(false);
        }
        else
        {
            Console.WriteLine(" [i] AbuseIPDB check omitted: environment variable ABUSEIPDB_API_KEY is not set.");
        }
    }

    private static async Task CollectIpapiContextAsync(string ipAddress, RunState state)
    {
        string requestUri = string.Format(CultureInfo.InvariantCulture, IpapiGeolocationEndpointFormat, Uri.EscapeDataString(ipAddress));
        using HttpRequestMessage request = new(HttpMethod.Get, requestUri);

        ApiResult result = await SendAsync(request).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            ReportOperationalError("ipapi.co", result.ErrorMessage!, state);
            return;
        }

        if (!IsSuccessStatus(result.StatusCode))
        {
            ReportOperationalError("ipapi.co", $"unexpected HTTP status {result.StatusCode}", state);
            return;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(result.Body!);
            JsonElement root = document.RootElement;

            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("error", out JsonElement errorFlag) &&
                errorFlag.ValueKind == JsonValueKind.True)
            {
                ReportOperationalError("ipapi.co", ReadStringOrDefault(root, "reason", "unknown provider error"), state);
                return;
            }

            Console.WriteLine(" [-] Geolocation & network context (ipapi.co):");
            Console.WriteLine($"     IP          : {ReadStringOrDefault(root, "ip")}");
            Console.WriteLine($"     ASN         : {ReadStringOrDefault(root, "asn")}");
            Console.WriteLine($"     Organization: {ReadStringOrDefault(root, "org")}");
            Console.WriteLine($"     Country     : {ReadStringOrDefault(root, "country_name")} ({ReadStringOrDefault(root, "country")})");
            Console.WriteLine($"     Region      : {ReadStringOrDefault(root, "region")}");
            Console.WriteLine($"     City        : {ReadStringOrDefault(root, "city")}");
            Console.WriteLine($"     Timezone    : {ReadStringOrDefault(root, "timezone")}");
        }
        catch (JsonException ex)
        {
            ReportOperationalError("ipapi.co", $"malformed JSON payload: {ex.Message}", state);
        }
    }
    private static async Task CollectAbuseIpdbReputationAsync(string ipAddress, string apiKey, RunState state)
    {
        string requestUri = $"{AbuseIpdbCheckEndpoint}?ipAddress={Uri.EscapeDataString(ipAddress)}&maxAgeInDays=90";
        using HttpRequestMessage request = new(HttpMethod.Get, requestUri);
        request.Headers.Add("Key", apiKey);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        ApiResult result = await SendAsync(request).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            ReportOperationalError("AbuseIPDB", result.ErrorMessage!, state);
            return;
        }

        if (result.StatusCode == (int)HttpStatusCode.Unauthorized)
        {
            ReportOperationalError("AbuseIPDB", "API key rejected (HTTP 401)", state);
            return;
        }

        if (result.StatusCode == (int)HttpStatusCode.PaymentRequired)
        {
            ReportOperationalError("AbuseIPDB", "subscription limit reached (HTTP 402)", state);
            return;
        }

        if (result.StatusCode == (int)HttpStatusCode.TooManyRequests)
        {
            ReportOperationalError("AbuseIPDB", "rate limit exceeded (HTTP 429)", state);
            return;
        }

        if (!IsSuccessStatus(result.StatusCode))
        {
            ReportOperationalError("AbuseIPDB", $"unexpected HTTP status {result.StatusCode}", state);
            return;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(result.Body!);
            if (!document.RootElement.TryGetProperty("data", out JsonElement data))
            {
                throw new JsonException("expected data object was missing");
            }

            int score = ReadIntOrDefault(data, "abuseConfidenceScore");
            int reports = ReadIntOrDefault(data, "totalReports");

            Console.WriteLine(" [-] AbuseIPDB reputation (90-day window):");
            Console.WriteLine($"     abuse confidence score : {score}/100");
            Console.WriteLine($"     total reports          : {reports}");
            Console.WriteLine($"     ISP                    : {ReadStringOrDefault(data, "isp")}");
            Console.WriteLine($"     country code           : {ReadStringOrDefault(data, "countryCode")}");
            Console.WriteLine($"     last reported at       : {ReadStringOrDefault(data, "lastReportedAt")}");

            if (score >= AbuseIpdbHighConfidenceThreshold)
            {
                state.FlagHighRisk();
                WriteLineColored(
                    $" [!] VERDICT: MALICIOUS - abuse confidence {score}% meets or exceeds the {AbuseIpdbHighConfidenceThreshold}% high-risk threshold.",
                    ConsoleColor.Red);
            }
            else if (score > 0)
            {
                WriteLineColored(
                    $" [~] VERDICT: SUSPICIOUS - abuse confidence {score}% is below the high-risk threshold; manual review advised.",
                    ConsoleColor.Yellow);
            }
            else
            {
                WriteLineColored(
                    " [+] VERDICT: CLEAN - no abuse reports recorded for this address in the last 90 days.",
                    ConsoleColor.Green);
            }
        }
        catch (JsonException ex)
        {
            ReportOperationalError("AbuseIPDB", $"malformed JSON payload: {ex.Message}", state);
        }
    }
    private static async Task RunDomainRoutineAsync(string domain, RunState state)
    {
        string? urlhausKey = Environment.GetEnvironmentVariable("URLHAUS_AUTH_KEY");
        bool urlhausAuthenticated = !string.IsNullOrWhiteSpace(urlhausKey);

        PrintSectionHeader("DOMAIN ROUTINE - LIVE DNS RESOLUTION + URLHAUS CROSS-REFERENCE");
        Console.WriteLine(
            " [i] Output reflects live DNS A/AAAA resolution and abuse.ch URLhaus activity; passive-DNS history is out of scope.");
        Console.WriteLine(urlhausAuthenticated
            ? " [+] Domain Auth: ABUSE.CH URLHAUS (authenticated)"
            : " [+] Domain Auth: ANONYMOUS FEED FALLBACK");

        await ResolveHostAddressesAsync(domain, state).ConfigureAwait(false);
        await QueryUrlhausHostFeedAsync(domain, urlhausAuthenticated ? urlhausKey : null, state).ConfigureAwait(false);
    }

    private static async Task ResolveHostAddressesAsync(string domain, RunState state)
    {
        try
        {
            IPHostEntry entry = await Dns.GetHostEntryAsync(domain).ConfigureAwait(false);
            IPAddress[] addresses = entry.AddressList;
            if (addresses.Length == 0)
            {
                ReportOperationalError("DNS", $"host '{domain}' resolved but returned no address records", state);
                return;
            }

            Console.WriteLine(" [-] Live DNS resolution (A/AAAA records):");
            foreach (IPAddress address in addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork))
            {
                Console.WriteLine($"     A    : {address}");
            }
            foreach (IPAddress address in addresses.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6))
            {
                Console.WriteLine($"     AAAA : {address}");
            }
        }
        catch (SocketException ex)
        {
            ReportOperationalError("DNS", $"resolution failed for '{domain}': {ex.SocketErrorCode}", state);
        }
        catch (Exception ex)
        {
            ReportOperationalError("DNS", $"resolution failed for '{domain}': {ex.Message}", state);
        }
    }

    private static async Task QueryUrlhausHostFeedAsync(string domain, string? authKey, RunState state)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, UrlhausHostEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["host"] = domain })
        };
        if (authKey is not null)
        {
            request.Headers.Add("Auth-Key", authKey);
        }

        ApiResult result = await SendAsync(request).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            ReportOperationalError("URLhaus", result.ErrorMessage!, state);
            return;
        }

        if (authKey is null && result.StatusCode == 401)
        {
            WriteLineColored(
                " [!] abuse.ch URLhaus refused anonymous access (HTTP 401): the feed requires a free registered Auth-Key - set URLHAUS_AUTH_KEY for domain feed lookups.",
                ConsoleColor.Yellow);
            return;
        }

        if (result.StatusCode is 401 or 403)
        {
            ReportOperationalError("URLhaus", $"Auth-Key rejected (HTTP {result.StatusCode})", state);
            return;
        }

        if (result.StatusCode == 429)
        {
            if (authKey is null)
            {
                WriteLineColored(
                    " [!] abuse.ch URLhaus rate limit reached (HTTP 429): set URLHAUS_AUTH_KEY for reliable access.",
                    ConsoleColor.Yellow);
            }
            else
            {
                ReportOperationalError("URLhaus", "request quota exceeded (HTTP 429)", state);
            }
            return;
        }

        if (!IsSuccessStatus(result.StatusCode))
        {
            ReportOperationalError("URLhaus", $"unexpected HTTP status {result.StatusCode}", state);
            return;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(result.Body!);
            JsonElement root = document.RootElement;
            string queryStatus = ReadStringOrDefault(root, "query_status", "unknown");

            if (string.Equals(queryStatus, "ok", StringComparison.OrdinalIgnoreCase))
            {
                state.FlagHighRisk();
                int urlCount = int.TryParse(ReadStringOrDefault(root, "url_count", "0"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedCount)
                    ? parsedCount
                    : 0;

                WriteLineColored(
                    $" [!] VERDICT: MALICIOUS - URLhaus lists this domain hosting malware distribution URLs ({(urlCount > 0 ? $"{urlCount} tracked URL(s)" : "count unavailable")}).",
                    ConsoleColor.Red);
                Console.WriteLine($"     first seen: {ReadStringOrDefault(root, "firstseen")}");
                Console.WriteLine($"     reference : {ReadStringOrDefault(root, "urlhaus_reference")}");

                if (root.TryGetProperty("urls", out JsonElement urls) && urls.ValueKind == JsonValueKind.Array)
                {
                    Console.WriteLine("     observed URLs:");
                    foreach (JsonElement urlEntry in urls.EnumerateArray().Take(5))
                    {
                        Console.WriteLine(
                            $"       [{ReadStringOrDefault(urlEntry, "url_status")}] threat={ReadStringOrDefault(urlEntry, "threat")} {ReadStringOrDefault(urlEntry, "url")}");
                    }
                }
            }
            else if (string.Equals(queryStatus, "no_results", StringComparison.OrdinalIgnoreCase))
            {
                WriteLineColored(
                    " [+] VERDICT: CLEAN - URLhaus has no recorded malware distribution activity for this domain.",
                    ConsoleColor.Green);
            }
            else
            {
                WriteLineColored(
                    $" [~] URLhaus returned status '{queryStatus}'; treat this result as inconclusive.",
                    ConsoleColor.Yellow);
            }
        }
        catch (JsonException ex)
        {
            ReportOperationalError("URLhaus", $"malformed JSON payload: {ex.Message}", state);
        }
    }
}

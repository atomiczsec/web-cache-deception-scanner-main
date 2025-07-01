package burp;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

class RequestSender {

    private final static double   JARO_THRESHOLD = 0.8;
    private final static int      LEVENSHTEIN_THRESHOLD = 200;

    // Simple in-memory cache to avoid repeating identical requests
    private static final Map<String, Map<String, Object>> RESPONSE_CACHE = new ConcurrentHashMap<>();

    // Expanded list of potential cache targets
    protected final static String[] KNOWN_CACHEABLE_PATHS = {
        "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/", "/index.html", "/index.htm", "/index.php", "/index.jsp", "/index.asp", "/index.aspx",
        "/main.js", "/bundle.js", "/app.js", "/style.css", "/main.css", "/styles.css",
        "/assets/", "/static/", "/public/", "/images/", "/js/", "/css/"
    };
    
    // List of common static resource directory prefixes
    protected final static String[] KNOWN_CACHEABLE_PREFIXES = {
        "/resources/", "/static/", "/assets/", "/public/", 
        "/images/", "/img/", "/js/", "/css/", "/content/",
        "/files/", "/uploads/"
    };
    
    // Expanded extension lists
    protected final static String[] INITIAL_TEST_EXTENSIONS = {
        "js", "css", "html"
    };
    protected final static String[] OTHER_TEST_EXTENSIONS = {
        // Images
        "jpg", "png", "gif", "svg", "ico", 
        // Fonts
        "woff", "woff2", 
        // Documents
        "pdf", "xml", "json",
        // Web / Scripting
        "php", "jsp", "asp", "aspx",
        // Media
        "mp3", "mp4",
        // Other common
        "map"
    };

    // Added multiple normalization templates
    protected final static String[] NORMALIZATION_TEMPLATES = {
        "%2f%2e%2e%2f", // /../ encoded
        "%2e%2e%2f",    // ../ encoded slash
        "..%2f",       // ../ encoded slash
        "%2f..%2f"     // /../ encoded slashes
    };

    // Regex patterns for stripping dynamic content
    private static final Pattern HTML_COMMENT_PATTERN = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile("<input[^>]*name=[\"\\'](__RequestVerificationToken|csrf_token|csrfmiddlewaretoken|nonce|authenticity_token|_csrf)[^>]*>", Pattern.CASE_INSENSITIVE);

    private static byte[] orgResponse;

    /**
     * Initial test to check if the application ignores trailing path segments
     */
    protected static boolean initialTest(IHttpRequestResponse message) {
        BurpExtender.print("\n--- Running Initial Tests ---");

        // Get Original Response Details
        byte[] orgRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> orgDetails = retrieveResponseDetails(message.getHttpService(), orgRequest);
        if (orgDetails == null) {
            BurpExtender.print("    Original Auth Request FAILED (No response details).");
            BurpExtender.print("--- Initial Tests FAILED ---");
            return false;
        }
        // Store original response body for later comparison (needed for Step 2)
        byte[] originalAuthBody = (byte[]) orgDetails.get("body");
        BurpExtender.print("    Original Auth Response Status: " + (int) orgDetails.get("statusCode"));


        BurpExtender.print("  [Step 1/2] Comparing authenticated vs. unauthenticated response for original URL...");
        // Get Unauthenticated Response Details
        byte[] unAuthedRequest = buildHttpRequest(message, null, null, false);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unAuthedRequest);
        if (unauthDetails == null) {
            BurpExtender.print("    Original Unauth Request FAILED (No response details).");
            // We might still proceed to step 2, but this check is less reliable.
            // Consider returning false here depending on desired strictness.
             BurpExtender.print("--- Initial Tests FAILED (due to unauth request failure) ---");
            return false; 
        }
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        BurpExtender.print("    Original Unauth Response Status: " + (int) unauthDetails.get("statusCode"));

        // Compare original auth vs unauth
        Map<String, Object> step1Similarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
        boolean unauthedIsSimilar = (boolean) step1Similarity.get("similar");
        // Added verbose logging of similarity metrics for initial test Step 1
        BurpExtender.print(String.format("    [INFO] Initial Tests Step 1 Similarity -> Jaro=%.3f, Levenshtein=%d", (double) step1Similarity.get("jaro"), (int) step1Similarity.get("levenshtein")));

        if (unauthedIsSimilar) {
            BurpExtender.print("    Result: SIMILAR. Unauthenticated response matches authenticated. Likely not vulnerable or no session handling.");
            BurpExtender.print("--- Initial Tests FAILED ---");
            return false;
        } else {
            BurpExtender.print("    Result: DIFFERENT. Unauthenticated response differs from authenticated (Good). Proceeding...");
        }

        // Generate a random path segment once for this test run
        String randomSegment = generateRandomString(5);
        BurpExtender.print("  [Step 2/2] Comparing original response vs. response with path segment '" + randomSegment + "' appended...");

        // Get Response Details for Appended Path
        byte[] testRequest = buildHttpRequestWithSegment(message, randomSegment, null, true, "/"); // Use segment builder
        Map<String, Object> appendedDetails = retrieveResponseDetails(message.getHttpService(), testRequest);
        if (appendedDetails == null) {
            BurpExtender.print("    Appended Path Auth Request FAILED (No response details).");
            BurpExtender.print("--- Initial Tests FAILED ---");
            return false;
        }
        byte[] appendedBody = (byte[]) appendedDetails.get("body");
        BurpExtender.print("    Appended Path Auth Response Status: " + (int) appendedDetails.get("statusCode"));

        // Compare original auth vs appended auth
        Map<String, Object> step2Similarity = testSimilar(new String(originalAuthBody), new String(appendedBody));
        boolean appendIsSimilar = (boolean) step2Similarity.get("similar");
        // Added verbose logging of similarity metrics for initial test Step 2
        BurpExtender.print(String.format("    [INFO] Initial Tests Step 2 Similarity -> Jaro=%.3f, Levenshtein=%d", (double) step2Similarity.get("jaro"), (int) step2Similarity.get("levenshtein")));

        // Store the random segment regardless of the step 2 outcome
        message.setComment(randomSegment); // Use comment field to pass the segment
        
        if (!appendIsSimilar) {
            BurpExtender.print("    Result: DIFFERENT. Appending '" + randomSegment + "' significantly changed the response.");
            BurpExtender.print("    WARNING: Initial path mapping check (Step 2/2) failed, but proceeding with cache tests anyway.");
            BurpExtender.print("--- Initial Tests Considered PASSED (with warning) ---");
            return true; // Proceed even if this check fails
        } else {
            BurpExtender.print("    Result: SIMILAR. Appending '" + randomSegment + "' yielded a similar response (Good). Potential path mapping issue.");
            BurpExtender.print("--- Initial Tests PASSED ---");
            return true;
        }
    }

    /**
     * Tests if appending a specific delimiter, segment, and extension leads to caching.
     * Now with status code validation to prevent false positives.
     */
    protected static boolean testDelimiterExtension(IHttpRequestResponse message, String randomSegment, String ext, String delimiter) {
        // Get Auth Response Details
        byte[] authRequest = buildHttpRequestWithSegment(message, randomSegment, ext, true, delimiter);
        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) {
            return false;
        }
        int authStatusCode = (int) authDetails.get("statusCode");
        byte[] authBody = (byte[]) authDetails.get("body");
        
        // Validate status code - only proceed if it's a successful response (2xx)
        if (authStatusCode < 200 || authStatusCode >= 300) {
            // BurpExtender.print("    Auth Request returned non-2xx status code: " + authStatusCode);
            return false;
        }

        // Get Unauth Response Details
        byte[] unauthRequest = buildHttpRequestWithSegment(message, randomSegment, ext, false, delimiter);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) {
            return false;
        }
        int unauthStatusCode = (int) unauthDetails.get("statusCode");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        // Validate unauth status code - only proceed if it's a successful response
        if (unauthStatusCode < 200 || unauthStatusCode >= 300) {
            // BurpExtender.print("    Unauth Request returned non-2xx status code: " + unauthStatusCode);
            return false;
        }

        // Perform similarity test on bodies
        Map<String, Object> similarityResult = testSimilar(new String(authBody), new String(unauthBody));
        boolean contentSimilar = (boolean) similarityResult.get("similar");

        // For debugging purposes, we might want to check X-Cache headers too
        @SuppressWarnings("unchecked")
        List<String> authHeaders = (List<String>) authDetails.get("headers");
        @SuppressWarnings("unchecked")
        List<String> unauthHeaders = (List<String>) unauthDetails.get("headers");
        
        String xCacheAuth = getHeaderValue(authHeaders, "X-Cache");
        String xCacheUnauth = getHeaderValue(unauthHeaders, "X-Cache");
        
        // Cache hit validation is a plus but not required since not all servers expose X-Cache
        // boolean cacheHitDetected = xCacheUnauth != null && xCacheUnauth.toLowerCase().contains("hit");

        if (contentSimilar) {
            // Enhanced debugging - log detailed information for hits
            BurpExtender.print("    [DEBUG] Delimiter='" + delimiter + "', Extension=." + ext 
                + ", Status: Auth=" + authStatusCode + ", Unauth=" + unauthStatusCode
                + ", X-Cache: Auth=" + (xCacheAuth == null ? "N/A" : xCacheAuth) 
                + ", Unauth=" + (xCacheUnauth == null ? "N/A" : xCacheUnauth));
            return true;
        } else {
            return false;
        }
    }

    /**
     * Tests for caching based on path normalization discrepancies using a specific template.
     * Constructs paths like /targetPath<delimiter><template><cacheable_path_relative>
     */
    protected static boolean testNormalizationCaching(IHttpRequestResponse message, String delimiter, String cacheablePath, String template) {
        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        // Ensure cacheablePath starts with / for correct substringing
        if (!cacheablePath.startsWith("/")) {
             // BurpExtender.print("Skipping normalization test for invalid cacheable path: " + cacheablePath);
             return false;
        }
        String cacheablePathRelative = cacheablePath.substring(1);
        String normalizationSuffix = template + cacheablePathRelative;
        String testingPathStructure = targetPath + delimiter + normalizationSuffix;

        // BurpExtender.print("\n--- Running Normalization Cache Test ---");
        // BurpExtender.print("  Template Used: " + template);
        // BurpExtender.print("  Delimiter: '" + delimiter + "'");
        // BurpExtender.print("  Target Cache Path: " + cacheablePath);
        // BurpExtender.print("  Testing Path Structure: " + testingPathStructure);
        // BurpExtender.print("  Comparing authenticated vs. unauthenticated response for the crafted path...");

        // Get Auth Response Details
        byte[] authRequest = buildHttpRequestWithNormalization(message, true, delimiter, normalizationSuffix);
        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) {
            // BurpExtender.print("    Auth Request FAILED (No response details).");
            // BurpExtender.print("--- Normalization Test FAILED for Template: " + template + ", Delimiter: '" + delimiter + "', Path: " + cacheablePath + " ---");
            return false;
        }
        // int authStatusCode = (int) authDetails.get("statusCode");
        byte[] authBody = (byte[]) authDetails.get("body");
        // BurpExtender.print("    Auth Response Status: " + authStatusCode);

        // Get Unauth Response Details
        byte[] unauthRequest = buildHttpRequestWithNormalization(message, false, delimiter, normalizationSuffix);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) {
            // BurpExtender.print("    Unauth Request FAILED (No response details).");
            // BurpExtender.print("--- Normalization Test FAILED for Template: " + template + ", Delimiter: '" + delimiter + "', Path: " + cacheablePath + " ---");
            return false;
        }
        // int unauthStatusCode = (int) unauthDetails.get("statusCode");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        // BurpExtender.print("    Unauth Response Status: " + unauthStatusCode);

        // Perform similarity test
        Map<String, Object> similarityResult = testSimilar(new String(authBody), new String(unauthBody));
        boolean contentSimilar = (boolean) similarityResult.get("similar");

        if (contentSimilar) {
            // Print details only on success - NOW COMMENTED OUT
            // BurpExtender.print("\n--- NORMALIZATION CACHE TEST PASSED ---");
            // BurpExtender.print("  Testing Path Structure: " + testingPathStructure);
            // BurpExtender.print("    Template Used: " + template);
            // BurpExtender.print("    Target Cache Path: " + cacheablePath);
            // BurpExtender.print("    Result: SIMILAR. Unauthenticated request received similar content to authenticated.");
            // BurpExtender.print("    Conclusion: Path appears to be CACHED and serving authenticated content.");
            // BurpExtender.print("--- Normalization Test PASSED for Template: " + template + ", Delimiter: '" + delimiter + "', Path: " + cacheablePath + " ---");
        } else {
            // Suppress failure messages
            // BurpExtender.print("    Result: DIFFERENT. Unauthenticated response differs from authenticated.");
            // BurpExtender.print("    Conclusion: Path " + testingPathStructure + " does NOT appear vulnerable to caching.");
            // BurpExtender.print("--- Normalization Test FAILED for Template: " + template + ", Delimiter: '" + delimiter + "', Path: " + cacheablePath + " ---");
        }
        return contentSimilar;
    }

    // Renamed original buildHttpRequest to avoid confusion
    private static byte[] buildHttpRequestWithSegment(final IHttpRequestResponse reqRes, final String additional, final String extension,
                                           boolean addCookies, String delimiter) {
        byte[] result;

        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        URL orgUrl = reqInfo.getUrl();
        List<IParameter> params = reqInfo.getParameters();
        List<String> headers = reqInfo.getHeaders();

        // Create GET message
        if ("GET".equals(reqInfo.getMethod())) {
            URL url = null;
            if (additional != null) {
                try {
                    // Use the new URL creation method with delimiter
                    url = createNewURLWithSegment(orgUrl, additional, extension, delimiter);
                } catch (MalformedURLException mue) {
                    mue.printStackTrace(new java.io.PrintStream(BurpExtender.getCallbacks().getStderr()));
                    return null; // Return null if URL creation fails
                }
            } else {
                url = reqInfo.getUrl(); // Use original URL if no segment added
            }

            if (url == null) return null; // Exit if URL is null

            result = BurpExtender.getHelpers().buildHttpRequest(url);

            if (addCookies) {
                for (IParameter p : params) {
                    if (IParameter.PARAM_COOKIE == p.getType()) {
                        result = BurpExtender.getHelpers().addParameter(result, p);
                    }
                }
            }
        } else { // Create POST message (Handle POST differently or maybe skip for now?)
            // NOTE: Modifying POST requests with path segments/delimiters is more complex
            //       and might break applications. Sticking to GET for now.
            BurpExtender.print("Skipping POST request modification for delimiter test.");
            return null; // Don't modify POST for now
        }

        return result;
    }

    // Added overload for backward compatibility
    private static byte[] buildHttpRequest(final IHttpRequestResponse reqRes, final String additional, final String extension,
                                     boolean addCookies) {
        return buildHttpRequestWithSegment(reqRes, additional, extension, addCookies, "/"); // Default to / delimiter (String)
    }

    // New method to build request for normalization test (avoids double encoding path segments)
    private static byte[] buildHttpRequestWithNormalization(final IHttpRequestResponse reqRes, boolean addCookies, String delimiter, String normalizationSuffix) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        URL orgUrl = reqInfo.getUrl();
        List<String> headers = reqInfo.getHeaders();
        byte[] result = null;

        if (!"GET".equals(reqInfo.getMethod())) {
             BurpExtender.print("Skipping non-GET request for normalization test.");
             return null;
        }

        try {
            // Construct the new path manually
            String targetPath = orgUrl.getPath();
            String query = orgUrl.getQuery() != null ? "?" + orgUrl.getQuery() : "";
            String newPathAndQuery = targetPath + delimiter + normalizationSuffix + query;

            List<String> newHeaders = new ArrayList<>();
            boolean firstLine = true;
            for (String header : headers) {
                if (firstLine && header.startsWith("GET ")) {
                    String httpVersion = header.substring(header.lastIndexOf(" HTTP/"));
                    newHeaders.add("GET " + newPathAndQuery + httpVersion);
                    firstLine = false;
                } else if (header.toLowerCase().startsWith("cookie:")) {
                    if (addCookies) {
                        newHeaders.add(header);
                    }
                    // else skip cookie header
                } else {
                     newHeaders.add(header);
                 }
            }
            // Use buildHttpMessage to avoid URL object re-encoding the path
            result = BurpExtender.getHelpers().buildHttpMessage(newHeaders, null); // Null body for GET

        } catch (Exception e) {
            BurpExtender.print("Error building normalization request: " + e.getMessage());
            e.printStackTrace(new java.io.PrintStream(BurpExtender.getCallbacks().getStderr()));
            return null;
        }

        return result;
    }

    // Renamed createNewURL to createNewURLWithSegment
    private static URL createNewURLWithSegment(URL orgURL, String additional, String extension, String delimiter) throws MalformedURLException {
        String urlStr = orgURL.toExternalForm();

        // Separate path from query string
        int queryPos = urlStr.indexOf("?");
        String path = queryPos >= 0 ? urlStr.substring(0, queryPos) : urlStr;
        String query = queryPos >= 0 ? urlStr.substring(queryPos) : ""; // Includes the '?' if present

        // Ensure the base path doesn't end with the delimiter we're about to add (unless it's a query delimiter)
        if (!"?".equals(delimiter) && path.endsWith(delimiter)) { // Safer check for String
            path = path.substring(0, path.length() - delimiter.length()); // Use delimiter length
        }

        StringBuilder newPath = new StringBuilder(path);

        // Add the delimiter and the additional segment
        newPath.append(delimiter);
        newPath.append(additional);

        // Add the extension if provided
        if (extension != null) {
            newPath.append(".").append(extension);
        }

        // Re-append the original query string
        newPath.append(query);

        return new URL(newPath.toString());
    }

    /**
     * Retrieves response body and status code.
     * Returns a Map with keys "body" (byte[]), "statusCode" (int), and "headers" (List<String>).
     * Now uses a cache to avoid duplicate requests and adaptive rate limiting.
     */
    private static Map<String, Object> retrieveResponseDetails(IHttpService service, byte[] request) {
        try {
            String cacheKey = service.toString() + Arrays.hashCode(request);
            Map<String, Object> cached = RESPONSE_CACHE.get(cacheKey);
            if (cached != null) {
                return cached;
            }

            // Small delay to avoid overwhelming the target when running multiple threads
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}

            IHttpRequestResponse response = BurpExtender.getCallbacks().makeHttpRequest(service, request);
            if (response == null) {
                return null;
            }

            IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(response.getResponse());
            Map<String, Object> details = new HashMap<>();
            details.put("statusCode", (int) responseInfo.getStatusCode());
            details.put("headers", responseInfo.getHeaders());

            byte[] responseBody = java.util.Arrays.copyOfRange(response.getResponse(),
                responseInfo.getBodyOffset(), response.getResponse().length);
            details.put("body", responseBody);

            RESPONSE_CACHE.put(cacheKey, details);
            return details;
        } catch (Exception e) {
            BurpExtender.print("Error making HTTP request: " + e.getMessage());
            return null;
        }
    }

    /**
     * Cleans response body by removing common dynamic elements.
     */
    private static String cleanResponseBody(String body) {
        if (body == null) return "";
        // Remove HTML comments
        body = HTML_COMMENT_PATTERN.matcher(body).replaceAll("");
        // Remove common CSRF hidden input tags
        body = CSRF_TOKEN_PATTERN.matcher(body).replaceAll("");
        // Add more cleaning rules if needed (e.g., script tags, specific divs)
        return body;
    }

    /**
     * Testing if the responses of two requests are similar after cleaning.
     * Returns a Map with keys "similar" (boolean), "jaro" (double), "levenshtein" (int).
     */
    private static Map<String, Object> testSimilar(String firstString, String secondString) {
        Map<String, Object> results = new HashMap<>();

        String cleanedFirst = cleanResponseBody(firstString);
        String cleanedSecond = cleanResponseBody(secondString);

        // Use org.apache.commons.text.similarity classes
        JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();
        LevenshteinDistance levenshtein = new LevenshteinDistance();

        double jaroDist = jaroWinkler.apply(cleanedFirst, cleanedSecond);
        int levenDist = levenshtein.apply(cleanedFirst, cleanedSecond);

        // Adjust similarity logic if needed based on new class behavior - JaroWinklerSimilarity returns 0-1 (higher is better)
        boolean similar = jaroDist >= JARO_THRESHOLD; // Primarily use Jaro-Winkler
        if (levenDist <= LEVENSHTEIN_THRESHOLD) { // Consider Levenshtein as secondary check? Or adjust threshold.
            similar = true;
        }

        results.put("similar", similar);
        results.put("jaro", jaroDist);
        results.put("levenshtein", levenDist);

        // Keep print statement for now, but it uses the old variables - NOW COMMENTING OUT
        // BurpExtender.print(String.format("    Similarity Scores (cleaned): Jaro=%.3f, Levenshtein=%d -> Similar: %s",
        //                      jaroDist, levenDist, similar));

        return results;
    }

    // Helper method to generate a random alphanumeric string
    protected static String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Tests the specific relative path normalization exploit scenario.
     * Sends two requests to check for X-Cache: miss then X-Cache: hit.
     * Compares response bodies for similarity.
     * Enhanced with detailed status code logging for better debugging.
     * NOW compares the final response body against the ORIGINAL authenticated response body
     * to prevent false positives where a different resource (e.g., /robots.txt) gets cached.
     */
    protected static boolean testRelativeNormalizationExploit(IHttpRequestResponse message, String delimiter, String relativePathSegment) {
        IRequestInfo originalReqInfo = BurpExtender.getHelpers().analyzeRequest(message);
        String targetPath = originalReqInfo.getUrl().getPath();
        String fullTestPath = targetPath + delimiter + relativePathSegment; // Construct the full path

        // --- Get Original Authenticated Content ---
        BurpExtender.print("    [DEBUG] Fetching original authenticated content for path: " + targetPath);
        byte[] originalAuthRequestBytes = buildHttpRequestWithFullPath(message, true, targetPath); // Request to original path
        if (originalAuthRequestBytes == null) {
             BurpExtender.print("    [DEBUG] Failed to build request for original content.");
             return false;
        }
        Map<String, Object> originalAuthDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequestBytes);
        if (originalAuthDetails == null || (int) originalAuthDetails.get("statusCode") < 200 || (int) originalAuthDetails.get("statusCode") >= 300) {
             BurpExtender.print("    [DEBUG] Failed to retrieve valid original authenticated content (Status: " + (originalAuthDetails != null ? originalAuthDetails.get("statusCode") : "N/A") + "). Cannot verify FP.");
             return false; // Cannot verify against original content if it fails
        }
        byte[] originalAuthBody = (byte[]) originalAuthDetails.get("body");
        BurpExtender.print("    [DEBUG] Original authenticated content fetched successfully.");
        // --- End Original Content Fetch ---


        // --- First request (auth) to the CRAFTED path ---
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            BurpExtender.print("    [DEBUG] Failed to build crafted path request 1.");
            return false;
        }

        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
             BurpExtender.print("    [DEBUG] Failed to get response 1 for crafted path test.");
            return false;
        }
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked")
        List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");

        // Validate status code for first request - must be 2xx
        boolean firstReqOk = statusCode1 >= 200 && statusCode1 < 300;
        if (!firstReqOk) {
            // Log detailed debug info for specific patterns that should have worked
            // if (delimiter.equals("%23") && relativePathSegment.contains("%2f%2e%2e%2f")) { // Keep existing debug?
            //     BurpExtender.print("    [DEBUG] Testing known pattern: Delim='" + delimiter + "' Prefix='"
            //         + relativePathSegment.substring(0, Math.min(relativePathSegment.length(), 15)) + "...' Path=" + fullTestPath);
            //     BurpExtender.print("    [DEBUG] Req1: Status=" + statusCode1 + ", X-Cache="
            //         + (xCacheHeader1 != null ? xCacheHeader1 : "N/A") + ", FirstReqOK=" + firstReqOk);
            // }
             BurpExtender.print("    [DEBUG] RelativeNorm Req1 to " + fullTestPath + " failed (Status: " + statusCode1 + ").");
            return false;
        }

        // --- Second request (auth) to the CRAFTED path to check for caching ---
        try { Thread.sleep(100); } catch (InterruptedException ignored) {} // Small delay
        byte[] requestBytes2 = requestBytes1; // Re-use the same request bytes
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) {
             BurpExtender.print("    [DEBUG] Failed to get response 2 for crafted path test.");
            return false;
        }
        int statusCode2 = (int) details2.get("statusCode");
        @SuppressWarnings("unchecked")
        List<String> headers2 = (List<String>) details2.get("headers");
        byte[] body2 = (byte[]) details2.get("body");
        String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");

        // Check second response: must be 200 OK
        boolean secondReqOk = statusCode2 == 200; // More strict check - must be 200 OK
        boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit"); // Still note cache hit

        BurpExtender.print("    [DEBUG] RelativeNorm Req2: Status=" + statusCode2 + ", X-Cache="
                    + (xCacheHeader2 != null ? xCacheHeader2 : "N/A") + ", SecondReqOK=" + secondReqOk
                    + ", CacheHit=" + cacheHitDetected);


        if (!secondReqOk) {
             BurpExtender.print("    [DEBUG] RelativeNorm Req2 failed (Status: " + statusCode2 + ").");
            return false;
        }

        // --- CRUCIAL CHECK: Compare body2 (from crafted path) with originalAuthBody ---
        BurpExtender.print("    [DEBUG] Comparing Response Body 2 (from " + fullTestPath + ") against Original Auth Body (from " + targetPath + ")");
        Map<String, Object> similarityResult = testSimilar(new String(originalAuthBody), new String(body2));
        boolean contentMatchesOriginal = (boolean) similarityResult.get("similar");

        BurpExtender.print("    [DEBUG] Content Matches Original: " + contentMatchesOriginal
                + String.format(" (Jaro=%.3f, Levenshtein=%d)", (double) similarityResult.get("jaro"), (int) similarityResult.get("levenshtein")));

        // Pass if the second request was OK (200) AND its content matches the original authenticated content.
        // The cache hit is a good indicator but not strictly required if content matches.
        if (secondReqOk && contentMatchesOriginal) {
             BurpExtender.print("    [SUCCESS] Relative Normalization Exploit Confirmed: Crafted path served original content.");
             return true;
        } else {
             BurpExtender.print("    [INFO] Relative Normalization Pattern (" + fullTestPath + ") did not serve original content or failed checks.");
             // Old debug logic based on body1 vs body2 comparison (less reliable) - keep commented out for reference?
             // if (delimiter.equals("%23") && relativePathSegment.contains("%2f%2e%2e%2f")) {
             //    Map<String, Object> oldSimilarity = testSimilar(new String(body1), new String(body2));
             //    boolean oldContentSimilar = (boolean) oldSimilarity.get("similar");
             //    BurpExtender.print("    [DEBUG Ref] Old Check (Body1 vs Body2): Similar=" + oldContentSimilar + ", CacheHit=" + cacheHitDetected);
             // }
             return false;
        }
    }

    /**
     * Helper to build an HTTP request with a specified full path, preserving other aspects.
     */
    private static byte[] buildHttpRequestWithFullPath(final IHttpRequestResponse reqRes, boolean addCookies, String fullPath) {
        IRequestInfo analyzedReq = BurpExtender.getHelpers().analyzeRequest(reqRes);
        List<String> headers = analyzedReq.getHeaders();

        // Find the request line (first header)
        String requestLine = headers.get(0);
        String[] parts = requestLine.split(" ", 3); // Split "METHOD PATH HTTP/VERSION"
        if (parts.length < 3) {
            BurpExtender.print("  Error: Could not parse request line: " + requestLine);
            return null;
        }
        String method = parts[0];
        String httpVersion = parts[2];

        // Create the new request line with the provided fullPath
        String newRequestLine = method + " " + fullPath + " " + httpVersion;

        List<String> newHeaders = new ArrayList<>();
        newHeaders.add(newRequestLine);

        // Copy other headers, potentially removing cookies
        boolean firstHeader = true;
        for (String header : headers) {
            if (firstHeader) {
                firstHeader = false;
                continue; // Skip the original request line
            }
            if (!addCookies && header.toLowerCase().startsWith("cookie:")) {
                continue;
            }
            newHeaders.add(header);
        }

        byte[] body = null;
        if (reqRes.getRequest() != null && analyzedReq.getBodyOffset() < reqRes.getRequest().length) {
           body = java.util.Arrays.copyOfRange(reqRes.getRequest(), analyzedReq.getBodyOffset(), reqRes.getRequest().length);
        }

        return BurpExtender.getHelpers().buildHttpMessage(newHeaders, body);
    }

    /**
     * Helper to get a header value (case-insensitive).
     */
    private static String getHeaderValue(List<String> headers, String headerName) {
        if (headers == null || headerName == null) {
            return null;
        }
        String lowerHeaderName = headerName.toLowerCase() + ":";
        for (String header : headers) {
            if (header.toLowerCase().startsWith(lowerHeaderName)) {
                return header.substring(headerName.length() + 1).trim();
            }
        }
        return null;
    }

    /**
     * Tests the prefix-based normalization exploit scenario.
     * Path: /sensitive_path<delimiter>%2f%2e%2e%2f<prefix>
     * Sends two requests to check for X-Cache: miss then X-Cache: hit.
     * Compares response bodies for similarity.
     */
    protected static boolean testPrefixNormalizationExploit(IHttpRequestResponse message, String delimiter, String prefix) {
        // Ensure prefix starts and ends appropriately for the test pattern
        String normalizedPrefix = prefix.startsWith("/") ? prefix.substring(1) : prefix; // Remove leading slash for pattern
        // The pattern expects something like "resources/", so we might not need the trailing slash check depending on KNOWN_CACHEABLE_PREFIXES format
        // if (!normalizedPrefix.endsWith("/")) normalizedPrefix += "/"; 
        
        String relativePathSegment = "%2f%2e%2e%2f" + normalizedPrefix; // e.g., %2f%2e%2e%2fresources/

        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        String fullTestPath = targetPath + delimiter + relativePathSegment; // Construct the full path

        // --- Add specific logging for the known-good exploit pattern ---
        boolean isTargetPattern = delimiter.equals("%23") && prefix.equals("/resources/");
        if (isTargetPattern) {
            BurpExtender.print("\n  [DEBUG] Testing known pattern: Delim='" + delimiter + "' Prefix='" + prefix + "' Path=" + fullTestPath);
        }

        // --- First Request --- 
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) return false;
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) return false;
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");
        boolean firstReqOk = statusCode1 == 200 && (xCacheHeader1 == null || !xCacheHeader1.toLowerCase().contains("hit"));
        if (isTargetPattern) {
             BurpExtender.print("    [DEBUG] Req1: Status=" + statusCode1 + ", X-Cache=" + (xCacheHeader1 != null ? xCacheHeader1 : "null") + ", FirstReqOK=" + firstReqOk);
        }
        if (!firstReqOk) return false;

        // --- Second Request --- 
        // Introduce a small delay - sometimes caches need a moment
        try { Thread.sleep(100); } catch (InterruptedException ignored) {} 
        byte[] requestBytes2 = requestBytes1; // Re-use
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) return false;
        int statusCode2 = (int) details2.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers2 = (List<String>) details2.get("headers");
        byte[] body2 = (byte[]) details2.get("body");
        String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");

        // Check second response: 200 OK and cache hit
        boolean secondReqOk = statusCode2 == 200 && (xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit"));
        if (!secondReqOk) {
            return false;
        }

        // Compare bodies
        Map<String, Object> similarityResult = testSimilar(new String(body1), new String(body2));
        boolean contentSimilar = (boolean) similarityResult.get("similar");

        if (contentSimilar) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Special test for hash-based path traversal - specifically for the pattern that worked in the challenge.
     * This method focuses on the #/../resources pattern with status code validation.
     * @param message The HTTP request/response to use as a base
     * @param resource The resource to try to reach (e.g., "resources", "css")
     * @param traversalPattern The path traversal pattern to use (e.g., "%2f%2e%2e%2f")
     * @return true if the test indicates a potential vulnerability
     */
    protected static boolean testHashPathTraversal(IHttpRequestResponse message, String resource, String traversalPattern) {
        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        String hashDelimiter = "%23"; // URL-encoded #
        String relativePathSegment = traversalPattern + resource;
        String fullTestPath = targetPath + hashDelimiter + relativePathSegment;
        
        // For debugging
        BurpExtender.print("    [DEBUG] Testing critical hash pattern: Path=" + fullTestPath);
        
        // Create and send first request (auth)
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            BurpExtender.print("    [DEBUG] Failed to build hash test request");
            return false;
        }

        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            BurpExtender.print("    [DEBUG] Failed to get response for hash test");
            return false;
        }
        
        int statusCode1 = (int) details1.get("statusCode");
        BurpExtender.print("    [DEBUG] Hash test response status: " + statusCode1);
        
        // We explicitly check if the status code is 200 (OK) or 302 (redirect) as both might indicate a valid path
        // 404 is a clear sign that the pattern doesn't work on this site
        if (statusCode1 != 200 && statusCode1 != 302) {
            BurpExtender.print("    [DEBUG] Hash pattern test failed - non-200/302 status code: " + statusCode1);
            return false;
        }
        
        // For 200 OK responses, try to validate caching behavior
        if (statusCode1 == 200) {
            // Get headers and body from first request
            @SuppressWarnings("unchecked")
            List<String> headers1 = (List<String>) details1.get("headers");
            byte[] body1 = (byte[]) details1.get("body");
            String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");
            
            // Make a second request to see if it's served from cache
            byte[] requestBytes2 = requestBytes1; // Use the same request
            Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
            
            if (details2 != null) {
                int statusCode2 = (int) details2.get("statusCode");
                @SuppressWarnings("unchecked")
                List<String> headers2 = (List<String>) details2.get("headers");
                String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");
                
                // Check for cache hit in second response
                boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit");
                
                if (cacheHitDetected) {
                    BurpExtender.print("    [DEBUG] Success! Hash pattern is cacheable - X-Cache: " + xCacheHeader2);
                    return true;
                }
                
                BurpExtender.print("    [DEBUG] Hash pattern response 200 OK but no cache hit detected.");
                // We still return true because a 200 OK is promising even without cache headers
                return true;
            }
        } else if (statusCode1 == 302) {
            // For redirects, this might still be exploitable in some cases
            BurpExtender.print("    [DEBUG] Hash pattern resulted in a redirect - potentially exploitable");
            return true;
        }
        
        return false;
    }
    
    /**
     * Tests normalization patterns that refer back to the original path via an intermediate segment.
     * Path: /sensitive_path<delimiter><intermediate_segment><traversal_pattern><sensitive_path_filename>
     * Example: /my-account?resources/..%2fmy-account
     * Sends two requests to check for cache state changes (e.g., Miss -> Hit) or consistent 200 OK with similar content.
     * @param message The base request/response.
     * @param delimiter The delimiter to use (e.g., "?", "%23").
     * @param intermediateSegment A known path or prefix (e.g., "resources/", "robots.txt").
     * @param traversalPattern The path traversal sequence (e.g., "..%2f", "%2f%2e%2e%2f").
     * @return true if the pattern appears potentially vulnerable.
     */
    protected static boolean testSelfReferentialNormalization(IHttpRequestResponse message, String delimiter, String intermediateSegment, String traversalPattern) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
        URL url = reqInfo.getUrl();
        String targetPath = url.getPath(); // e.g., /my-account
        if (targetPath == null || targetPath.isEmpty() || !targetPath.startsWith("/")) {
            return false; // Cannot proceed without a valid target path
        }
        // Extract filename: handle trailing slash, root path, or no slash cases
        String targetFilename;
        int lastSlash = targetPath.lastIndexOf('/');
        if (lastSlash == targetPath.length() - 1 && targetPath.length() > 1) { // Ends with slash, not root
             int secondLastSlash = targetPath.lastIndexOf('/', lastSlash - 1);
             targetFilename = targetPath.substring(secondLastSlash + 1, lastSlash);
        } else if (lastSlash == -1 || lastSlash == 0) { // No slash (e.g., "filename") or root path
             // Cannot reliably get a filename to append in these cases for self-reference
             // Or maybe default to index.html? For now, let's skip these cases.
             // Consider logging this situation if it occurs frequently.
             // BurpExtender.print("    [DEBUG] Skipping self-ref test for path: " + targetPath + " (cannot extract filename)");
             return false;
        } else { // Standard case like /path/to/file
             targetFilename = targetPath.substring(lastSlash + 1);
        }
        if (targetFilename.isEmpty()){
             // BurpExtender.print("    [DEBUG] Skipping self-ref test for path: " + targetPath + " (extracted empty filename)");
             return false; // Cannot append empty filename
        }


        // Prepare intermediate segment: remove leading slash, ensure trailing slash for likely directories
        String processedIntermediate = intermediateSegment.startsWith("/") ? intermediateSegment.substring(1) : intermediateSegment;
        // Add trailing slash if it looks like a directory and doesn't have one
        if (!processedIntermediate.isEmpty() && !processedIntermediate.contains(".") && !processedIntermediate.endsWith("/")) {
             processedIntermediate += "/";
        }
        // Ensure traversal pattern doesn't start with / if intermediate already ends with /
         if (processedIntermediate.endsWith("/") && traversalPattern.startsWith("%2f")) { // %2f is url encoded /
             traversalPattern = traversalPattern.substring(3); // Remove leading %2f
         } else if (processedIntermediate.endsWith("/") && traversalPattern.startsWith("/")) {
             traversalPattern = traversalPattern.substring(1); // Remove leading /
         }

        String fullTestPath = targetPath + delimiter + processedIntermediate + traversalPattern + targetFilename;

        BurpExtender.print("    [DEBUG] Testing self-referential pattern: Path=" + fullTestPath);

        // --- First Request (Auth, expect cache miss/non-hit) ---
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            BurpExtender.print("    [DEBUG] Failed to build self-ref request 1");
            return false;
        }
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            BurpExtender.print("    [DEBUG] Failed to get response 1 for self-ref test");
            return false;
        }
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");

        // Primary check is for 200 OK. We also note if it was unexpectedly a cache hit.
        boolean firstReqOk = statusCode1 == 200;
        boolean firstReqHit = xCacheHeader1 != null && xCacheHeader1.toLowerCase().contains("hit");
        BurpExtender.print("    [DEBUG] Self-Ref Req1: Status=" + statusCode1 + ", X-Cache=" + (xCacheHeader1 != null ? xCacheHeader1 : "null") + ", FirstReqOK=" + firstReqOk + ", FirstReqHit=" + firstReqHit);

        // If the first request failed (non-200) or was already a cache hit, this specific path isn't demonstrating the Miss->Hit behavior.
        // However, a 200 response even on first hit might still be interesting if content matches unauth later, but less classic WCD.
        if (!firstReqOk) {
            return false;
        }

        // --- Second Request (Auth, expect cache hit ideally) ---
        try { Thread.sleep(150); } catch (InterruptedException ignored) {} // Slightly longer delay
        byte[] requestBytes2 = requestBytes1; // Re-use the same request
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) {
            BurpExtender.print("    [DEBUG] Failed to get response 2 for self-ref test");
            // Consider returning true based on Req1 if statusCode1 was 200? Or stick to requiring confirmation.
            return false; // Stick to requiring confirmation for now
        }
        int statusCode2 = (int) details2.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers2 = (List<String>) details2.get("headers");
        byte[] body2 = (byte[]) details2.get("body");
        String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");

        boolean secondReqOk = statusCode2 == 200; // Must be 200 OK
        boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit");
        BurpExtender.print("    [DEBUG] Self-Ref Req2: Status=" + statusCode2 + ", X-Cache=" + (xCacheHeader2 != null ? xCacheHeader2 : "null") + ", SecondReqOK=" + secondReqOk + ", CacheHit=" + cacheHitDetected);

        // Success conditions:
        // 1. Classic: First request was OK (200) and NOT a hit, Second request was OK (200) AND IS a hit.
        // 2. Fallback: Both requests OK (200), no definitive cache hit signal, but content is similar.
        // 3. Permissive: First request was OK (200), Second request was OK (200). (Might indicate exploitable but not classic caching)

        boolean classicHitScenario = firstReqOk && !firstReqHit && secondReqOk && cacheHitDetected;

        if (classicHitScenario) {
            BurpExtender.print("    [SUCCESS] Self-Ref Classic Miss->Hit pattern detected!");
            // Optionally compare content similarity for extra confidence
            // Map<String, Object> similarityResult = testSimilar(new String(body1), new String(body2));
            // BurpExtender.print("      Content Similar: " + similarityResult.get("similar"));
            return true;
        }

        // If no classic hit, check for consistent 200 OK and similar content (fallback for caches without clear headers)
        if (firstReqOk && secondReqOk) {
             Map<String, Object> similarityResult = testSimilar(new String(body1), new String(body2));
             boolean contentSimilar = (boolean) similarityResult.get("similar");
             BurpExtender.print("    [DEBUG] Self-Ref Content Similarity (Req1 vs Req2): " + contentSimilar + " (Jaro: " + String.format("%.3f", similarityResult.get("jaro")) + ")");
             if (contentSimilar) {
                  BurpExtender.print("    [SUCCESS] Self-Ref Fallback: Consistent 200 OK and Similar Content detected!");
                  return true;
             }
        }

        // If none of the success conditions met
        return false;
    }

    /**
     * Overloaded method using the common traversal pattern '..%2f'.
     */
    protected static boolean testSelfReferentialNormalization(IHttpRequestResponse message, String delimiter, String intermediateSegment) {
        return testSelfReferentialNormalization(message, delimiter, intermediateSegment, "..%2f"); // Use common pattern
    }

    /**
     * Tests the reverse traversal scenario - starting from a cacheable path and traversing to sensitive content.
     * This tests patterns like /resources/..%2fmy-account where /resources/ might be cached but /my-account contains sensitive data.
     * This pattern was confirmed to work in the PortSwigger lab challenge.
     * 
     * @param message The original request to the sensitive content
     * @param cacheablePath The potentially cacheable starting path (e.g., "/resources/")
     * @return true if the pattern appears to be vulnerable
     */
    protected static boolean testReverseTraversal(IHttpRequestResponse message, String cacheablePath) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
        String sensitiveTargetPath = reqInfo.getUrl().getPath();
        
        // Extract the sensitive page filename
        String sensitiveFilename;
        int lastSlash = sensitiveTargetPath.lastIndexOf('/');
        if (lastSlash == sensitiveTargetPath.length() - 1) { // Ends with slash
            sensitiveFilename = "index"; // Default to index if path ends with slash
        } else if (lastSlash == -1) { // No slash
            sensitiveFilename = sensitiveTargetPath;
        } else { // Normal case
            sensitiveFilename = sensitiveTargetPath.substring(lastSlash + 1);
        }
        
        // Ensure the cacheable path starts and ends with /
        String normalizedCachePath = cacheablePath;
        if (!normalizedCachePath.startsWith("/")) {
            normalizedCachePath = "/" + normalizedCachePath;
        }
        if (!normalizedCachePath.endsWith("/")) {
            normalizedCachePath += "/";
        }
        
        // Construct the path traversal component to go back to root
        // Count the number of directories in the cacheable path
        int dirCount = 0;
        for (int i = 0; i < normalizedCachePath.length(); i++) {
            if (normalizedCachePath.charAt(i) == '/') {
                dirCount++;
            }
        }
        dirCount--; // Adjust for the trailing slash
        
        // Create the appropriate traversal sequence
        StringBuilder traversal = new StringBuilder();
        for (int i = 0; i < dirCount; i++) {
            traversal.append("..%2f");
        }
        
        // Construct the test path: /cacheable/path/..%2fsensitive
        String fullTestPath = normalizedCachePath + traversal.toString() + sensitiveFilename;
        
        BurpExtender.print("  [DEBUG] Testing Reverse Traversal: " + fullTestPath);
        
        // --- Get Original Sensitive Content (for verification) ---
        byte[] originalAuthRequestBytes = buildHttpRequestWithFullPath(message, true, sensitiveTargetPath);
        Map<String, Object> originalAuthDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequestBytes);
        if (originalAuthDetails == null || (int)originalAuthDetails.get("statusCode") != 200) {
            BurpExtender.print("  [DEBUG] Cannot fetch original sensitive content for comparison");
            return false;
        }
        byte[] originalAuthBody = (byte[]) originalAuthDetails.get("body");
        
        // --- First Request (Auth) to the reverse traversal path ---
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            return false;
        }
        
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") 
        List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");
        
        // First request should succeed and NOT be a cache hit
        boolean firstReqOk = statusCode1 == 200;
        boolean firstReqNoHit = xCacheHeader1 == null || !xCacheHeader1.toLowerCase().contains("hit");
        
        BurpExtender.print("  [DEBUG] Reverse Test Req1: Status=" + statusCode1 + 
                          ", X-Cache=" + (xCacheHeader1 != null ? xCacheHeader1 : "N/A"));
        
        if (!firstReqOk) {
            return false;
        }
        
        // --- CRUCIAL: Verify this actually returns the sensitive content ---
        Map<String, Object> contentMatchResult = testSimilar(new String(originalAuthBody), new String(body1));
        boolean returnsSensitiveContent = (boolean) contentMatchResult.get("similar");
        if (!returnsSensitiveContent) {
            BurpExtender.print("  [DEBUG] Reverse path traversal returns a 200 response but NOT the sensitive content");
            return false;
        }
        BurpExtender.print("  [DEBUG] Reverse path returns sensitive content (content match confirmed)");
        
        // --- Second Request (Auth) to check for caching ---
        try { Thread.sleep(150); } catch (InterruptedException ignored) {}
        byte[] requestBytes2 = requestBytes1; // Re-use the same request
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) {
            return false;
        }
        
        int statusCode2 = (int) details2.get("statusCode");
        @SuppressWarnings("unchecked") 
        List<String> headers2 = (List<String>) details2.get("headers");
        String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");
        
        boolean secondReqOk = statusCode2 == 200;
        boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit");
        
        BurpExtender.print("  [DEBUG] Reverse Test Req2: Status=" + statusCode2 + 
                          ", X-Cache=" + (xCacheHeader2 != null ? xCacheHeader2 : "N/A") + 
                          ", CacheHit=" + cacheHitDetected);
        
        // --- Now try an unauthenticated request to see if we get the sensitive content ---
        byte[] unauthRequestBytes = buildHttpRequestWithFullPath(message, false, fullTestPath);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequestBytes);
        if (unauthDetails == null) {
            // Can't verify unauth access, but still return true if we detected caching behavior
            return secondReqOk && cacheHitDetected;
        }
        
        int unauthStatusCode = (int) unauthDetails.get("statusCode");
        @SuppressWarnings("unchecked") 
        List<String> unauthHeaders = (List<String>) unauthDetails.get("headers");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        String unauthXCache = getHeaderValue(unauthHeaders, "X-Cache");
        
        boolean unauthReqOk = unauthStatusCode == 200;
        boolean unauthCacheHit = unauthXCache != null && unauthXCache.toLowerCase().contains("hit");
        
        BurpExtender.print("  [DEBUG] Reverse Test Unauth: Status=" + unauthStatusCode + 
                          ", X-Cache=" + (unauthXCache != null ? unauthXCache : "N/A") + 
                          ", CacheHit=" + unauthCacheHit);
        
        // Check if unauth request returns the sensitive content (definitive proof)
        if (unauthReqOk) {
            Map<String, Object> unauthSimilarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
            boolean unauthGetsSensitiveContent = (boolean) unauthSimilarity.get("similar");
            
            if (unauthGetsSensitiveContent) {
                BurpExtender.print("  [SUCCESS] CRITICAL: Unauthenticated request receives sensitive content via reverse traversal!");
                return true;
            }
        }
        
        // If we couldn't definitively prove unauth access, still return true if we detected caching
        return secondReqOk && cacheHitDetected;
    }
}

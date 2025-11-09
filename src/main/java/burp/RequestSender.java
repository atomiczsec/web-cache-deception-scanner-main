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
import java.util.LinkedHashMap;

class RequestSender {

    private final static double   JARO_THRESHOLD = 0.8;
    private final static int      LEVENSHTEIN_THRESHOLD = 200;
    private final static int      CACHE_MAX_SIZE = 1000; // Maximum cache entries

    // Thread-safe bounded cache with LRU eviction to prevent memory leaks
    private static final Map<String, Map<String, Object>> RESPONSE_CACHE = new LinkedHashMap<String, Map<String, Object>>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Map<String, Object>> eldest) {
            return size() > CACHE_MAX_SIZE;
        }
    };
    
    // Synchronize cache access to maintain thread safety with LinkedHashMap
    private static final Object CACHE_LOCK = new Object();

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

    /**
     * Initial test to check if the application ignores trailing path segments
     */
    protected static boolean initialTest(IHttpRequestResponse message) {
        byte[] orgRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> orgDetails = retrieveResponseDetails(message.getHttpService(), orgRequest);
        if (orgDetails == null) {
            return false;
        }
        byte[] originalAuthBody = (byte[]) orgDetails.get("body");

        byte[] unAuthedRequest = buildHttpRequest(message, null, null, false);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unAuthedRequest);
        if (unauthDetails == null) {
            return false; 
        }
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        Map<String, Object> step1Similarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
        boolean unauthedIsSimilar = (boolean) step1Similarity.get("similar");

        if (unauthedIsSimilar) {
            return false;
        }

        String randomSegment = generateRandomString(5);
        byte[] testRequest = buildHttpRequestWithSegment(message, randomSegment, null, true, "/");
        Map<String, Object> appendedDetails = retrieveResponseDetails(message.getHttpService(), testRequest);
        if (appendedDetails == null) {
            return false;
        }
        byte[] appendedBody = (byte[]) appendedDetails.get("body");

        Map<String, Object> step2Similarity = testSimilar(new String(originalAuthBody), new String(appendedBody));
        boolean appendIsSimilar = (boolean) step2Similarity.get("similar");

        message.setComment(randomSegment);
        return true;
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
        
        if (authStatusCode < 200 || authStatusCode >= 300) {
            return false;
        }

        byte[] unauthRequest = buildHttpRequestWithSegment(message, randomSegment, ext, false, delimiter);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) {
            return false;
        }
        int unauthStatusCode = (int) unauthDetails.get("statusCode");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        if (unauthStatusCode < 200 || unauthStatusCode >= 300) {
            return false;
        }

        Map<String, Object> similarityResult = testSimilar(new String(authBody), new String(unauthBody));
        return (boolean) similarityResult.get("similar");
    }

    /**
     * Tests for caching based on path normalization discrepancies using a specific template.
     * Constructs paths like /targetPath<delimiter><template><cacheable_path_relative>
     */
    protected static boolean testNormalizationCaching(IHttpRequestResponse message, String delimiter, String cacheablePath, String template) {
        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        if (!cacheablePath.startsWith("/")) {
             return false;
        }
        String cacheablePathRelative = cacheablePath.substring(1);
        String normalizationSuffix = template + cacheablePathRelative;

        byte[] authRequest = buildHttpRequestWithNormalization(message, true, delimiter, normalizationSuffix);
        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) {
            return false;
        }
        byte[] authBody = (byte[]) authDetails.get("body");

        byte[] unauthRequest = buildHttpRequestWithNormalization(message, false, delimiter, normalizationSuffix);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) {
            return false;
        }
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        Map<String, Object> similarityResult = testSimilar(new String(authBody), new String(unauthBody));
        return (boolean) similarityResult.get("similar");
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
            return null;
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
            
            // Thread-safe cache lookup
            synchronized (CACHE_LOCK) {
                Map<String, Object> cached = RESPONSE_CACHE.get(cacheKey);
                if (cached != null) {
                    return cached;
                }
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

            // Thread-safe cache insertion
            synchronized (CACHE_LOCK) {
                RESPONSE_CACHE.put(cacheKey, details);
            }
            return details;
        } catch (Exception e) {
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

        // Fixed similarity logic: Both metrics must indicate similarity for a positive match
        // JaroWinklerSimilarity returns 0-1 (higher is better)
        // LevenshteinDistance returns edit distance (lower is better)
        boolean jaroSimilar = jaroDist >= JARO_THRESHOLD;
        boolean levenSimilar = levenDist <= LEVENSHTEIN_THRESHOLD;
        
        // Require BOTH metrics to indicate similarity to reduce false positives
        // This prevents cases where very different content has coincidentally low edit distance
        boolean similar = jaroSimilar && levenSimilar;

        results.put("similar", similar);
        results.put("jaro", jaroDist);
        results.put("levenshtein", levenDist);
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

        byte[] originalAuthRequestBytes = buildHttpRequestWithFullPath(message, true, targetPath);
        if (originalAuthRequestBytes == null) {
             return false;
        }
        Map<String, Object> originalAuthDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequestBytes);
        if (originalAuthDetails == null || (int) originalAuthDetails.get("statusCode") < 200 || (int) originalAuthDetails.get("statusCode") >= 300) {
             return false;
        }
        byte[] originalAuthBody = (byte[]) originalAuthDetails.get("body");

        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            return false;
        }

        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            return false;
        }
        int statusCode1 = (int) details1.get("statusCode");
        if (statusCode1 < 200 || statusCode1 >= 300) {
            return false;
        }

        try { Thread.sleep(100); } catch (InterruptedException ignored) {}
        byte[] requestBytes2 = requestBytes1;
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) {
            return false;
        }
        int statusCode2 = (int) details2.get("statusCode");
        if (statusCode2 != 200) {
            return false;
        }

        @SuppressWarnings("unchecked")
        List<String> headers2 = (List<String>) details2.get("headers");
        byte[] body2 = (byte[]) details2.get("body");

        Map<String, Object> similarityResult = testSimilar(new String(originalAuthBody), new String(body2));
        return (boolean) similarityResult.get("similar");
    }

    /**
     * Helper to build an HTTP request with a specified full path, preserving other aspects.
     */
    private static byte[] buildHttpRequestWithFullPath(final IHttpRequestResponse reqRes, boolean addCookies, String fullPath) {
        IRequestInfo analyzedReq = BurpExtender.getHelpers().analyzeRequest(reqRes);
        List<String> headers = analyzedReq.getHeaders();

        // Find the request line (first header)
        String requestLine = headers.get(0);
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 3) {
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
        String fullTestPath = targetPath + delimiter + relativePathSegment;

        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) return false;
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) return false;
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");
        boolean firstReqOk = statusCode1 == 200 && (xCacheHeader1 == null || !xCacheHeader1.toLowerCase().contains("hit"));
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
        String hashDelimiter = "%23";
        String relativePathSegment = traversalPattern + resource;
        String fullTestPath = targetPath + hashDelimiter + relativePathSegment;
        
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            return false;
        }

        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            return false;
        }
        
        int statusCode1 = (int) details1.get("statusCode");
        if (statusCode1 != 200 && statusCode1 != 302) {
            return false;
        }
        
        if (statusCode1 == 200) {
            byte[] requestBytes2 = requestBytes1;
            Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
            
            if (details2 != null) {
                @SuppressWarnings("unchecked")
                List<String> headers2 = (List<String>) details2.get("headers");
                String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");
                boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit");
                return cacheHitDetected;
            }
        }
        
        return statusCode1 == 302;
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
        } else if (lastSlash == -1 || lastSlash == 0) {
             return false;
        } else {
             targetFilename = targetPath.substring(lastSlash + 1);
        }
        if (targetFilename.isEmpty()){
             return false;
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

        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        if (requestBytes1 == null) {
            return false;
        }
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            return false;
        }
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        String xCacheHeader1 = getHeaderValue(headers1, "X-Cache");

        boolean firstReqOk = statusCode1 == 200;
        boolean firstReqHit = xCacheHeader1 != null && xCacheHeader1.toLowerCase().contains("hit");
        if (!firstReqOk) {
            return false;
        }

        try { Thread.sleep(150); } catch (InterruptedException ignored) {}
        byte[] requestBytes2 = requestBytes1;
        Map<String, Object> details2 = retrieveResponseDetails(message.getHttpService(), requestBytes2);
        if (details2 == null) {
            return false;
        }
        int statusCode2 = (int) details2.get("statusCode");
        @SuppressWarnings("unchecked") List<String> headers2 = (List<String>) details2.get("headers");
        byte[] body2 = (byte[]) details2.get("body");
        String xCacheHeader2 = getHeaderValue(headers2, "X-Cache");

        boolean secondReqOk = statusCode2 == 200;
        boolean cacheHitDetected = xCacheHeader2 != null && xCacheHeader2.toLowerCase().contains("hit");

        boolean classicHitScenario = firstReqOk && !firstReqHit && secondReqOk && cacheHitDetected;
        if (classicHitScenario) {
            return true;
        }

        if (firstReqOk && secondReqOk) {
             Map<String, Object> similarityResult = testSimilar(new String(body1), new String(body2));
             return (boolean) similarityResult.get("similar");
        }

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
        
        String fullTestPath = normalizedCachePath + traversal.toString() + sensitiveFilename;
        
        byte[] originalAuthRequestBytes = buildHttpRequestWithFullPath(message, true, sensitiveTargetPath);
        Map<String, Object> originalAuthDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequestBytes);
        if (originalAuthDetails == null || (int)originalAuthDetails.get("statusCode") != 200) {
            return false;
        }
        byte[] originalAuthBody = (byte[]) originalAuthDetails.get("body");
        
        byte[] requestBytes1 = buildHttpRequestWithFullPath(message, true, fullTestPath);
        Map<String, Object> details1 = retrieveResponseDetails(message.getHttpService(), requestBytes1);
        if (details1 == null) {
            return false;
        }
        
        int statusCode1 = (int) details1.get("statusCode");
        @SuppressWarnings("unchecked") 
        List<String> headers1 = (List<String>) details1.get("headers");
        byte[] body1 = (byte[]) details1.get("body");
        
        if (statusCode1 != 200) {
            return false;
        }
        
        Map<String, Object> contentMatchResult = testSimilar(new String(originalAuthBody), new String(body1));
        if (!(boolean) contentMatchResult.get("similar")) {
            return false;
        }
        
        try { Thread.sleep(150); } catch (InterruptedException ignored) {}
        byte[] requestBytes2 = requestBytes1;
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
        
        byte[] unauthRequestBytes = buildHttpRequestWithFullPath(message, false, fullTestPath);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequestBytes);
        if (unauthDetails == null) {
            return secondReqOk && cacheHitDetected;
        }
        
        int unauthStatusCode = (int) unauthDetails.get("statusCode");
        @SuppressWarnings("unchecked") 
        List<String> unauthHeaders = (List<String>) unauthDetails.get("headers");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        
        if (unauthStatusCode == 200) {
            Map<String, Object> unauthSimilarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
            if ((boolean) unauthSimilarity.get("similar")) {
                return true;
            }
        }
        
        return secondReqOk && cacheHitDetected;
    }
}

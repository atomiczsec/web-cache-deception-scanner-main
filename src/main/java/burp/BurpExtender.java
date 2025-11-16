package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintStream;
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
    private static ForkJoinPool executor;
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
        callbacks.printOutput("[WCD] [WARNING] " + message);
    }
    
    protected static void logError(String message) {
        callbacks.printOutput("[WCD] [ERROR] " + message);
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

        int parallelism = Math.max(2, Runtime.getRuntime().availableProcessors());
        executor = new ForkJoinPool(parallelism, ForkJoinPool.defaultForkJoinWorkerThreadFactory, null, true);
        logInfo("Version " + VERSION + " loaded with parallelism: " + parallelism);
    }


    private void runScannerForRequest(IHttpRequestResponse iHttpRequestResponse) {
        synchronized (this) {
            if (executor != null && !executor.isShutdown()) {
                try {
                    executor.execute(new ScannerThread(iHttpRequestResponse));
                } catch (RejectedExecutionException e) {
                    logWarning("Executor unavailable, falling back to new thread: " + e.getMessage());
                    new Thread(new ScannerThread(iHttpRequestResponse)).start();
                }
            } else {
                new Thread(new ScannerThread(iHttpRequestResponse)).start();
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> items = new ArrayList<>();

        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == iContextMenuInvocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == iContextMenuInvocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == iContextMenuInvocation.getInvocationContext()) {
            IHttpRequestResponse[] arr = iContextMenuInvocation.getSelectedMessages();
            JMenuItem item = new JMenuItem("Web Cache Deception Test");
            MenuItemListener mil = new MenuItemListener(arr);
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
                if (!RequestSender.initialTest(reqRes)) {
                    logWarning("Scan aborted: Initial path mapping tests failed");
                    return;
                }
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

                String randomSegment = reqRes.getComment();
                if (randomSegment == null || randomSegment.isEmpty()) {
                    randomSegment = "test";
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

                updateStatus("Testing delimiter + extensions...");
                List<String> allExtensions = new ArrayList<>(Arrays.asList(RequestSender.INITIAL_TEST_EXTENSIONS));
                allExtensions.addAll(Arrays.asList(RequestSender.OTHER_TEST_EXTENSIONS));

                for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                    for (String extension : allExtensions) {
                        if (RequestSender.testDelimiterExtension(reqRes, randomSegment, extension, delimiter)) {
                            vulnerableDelimiterCombinations.computeIfAbsent(delimiter, k -> new HashSet<>()).add(extension);
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

                updateStatus("Testing path normalization...");
                List<String> knownPaths = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PATHS);
                List<String> normalizationTemplates = Arrays.asList(RequestSender.NORMALIZATION_TEMPLATES);
                
                for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                    Map<String, String> successfulPathsForDelimiter = new HashMap<>();
                    for (String knownPath : knownPaths) {
                        for (String template : normalizationTemplates) {
                            if (RequestSender.testNormalizationCaching(reqRes, delimiter, knownPath, template)) {
                                successfulPathsForDelimiter.put(knownPath, template);
                            }
                        }
                    }
                    if (!successfulPathsForDelimiter.isEmpty()) {
                        successfulNormalizationDetails.put(delimiter, successfulPathsForDelimiter);
                    }
                }

                updateStatus("Testing relative normalization...");
                String specificRelativePath = "%2f%2e%2e%2frobots.txt";
                for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                    if (RequestSender.testRelativeNormalizationExploit(reqRes, delimiter, specificRelativePath)) {
                        successfulRelativeExploits.put(delimiter, specificRelativePath);
                    }
                }

                updateStatus("Testing prefix normalization...");
                List<String> knownPrefixes = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PREFIXES);
                for (String delimiter : Arrays.asList(RequestSender.ADVANCED_DELIMITERS)) {
                    for (String prefix : knownPrefixes) {
                        if (RequestSender.testPrefixNormalizationExploit(reqRes, delimiter, prefix)) {
                            successfulPrefixExploits.put(delimiter, prefix);
                            break;
                        }
                    }
                }

                updateStatus("Testing reverse traversal...");
                String[] reverseTraversalPaths = {
                    "/resources/", "/static/", "/assets/", "/css/", "/js/", "/images/", "/public/"
                };
                for (String cachePath : reverseTraversalPaths) {
                    if (RequestSender.testReverseTraversal(reqRes, cachePath)) {
                        successfulReverseTraversals.put(cachePath, "");
                    }
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
                    generateExploitDetails(reqRes, successfulSelfRefExploits, hashTraversalVulnerable, 
                                         successfulTraversalPath, vulnerableDelimiterCombinations, 
                                         successfulNormalizationDetails, successfulPrefixExploits, 
                                         successfulRelativeExploits, successfulReverseTraversals,
                                         successfulHeaderAttacks, successfulHPPAttacks,
                                         successfulCaseAttacks, successfulUnicodeAttacks, detectedCDN);
                    
                    callbacks.addScanIssue(issue);
                } else {
                    logInfo("No vulnerabilities found: " + targetUrlStr);
                }

            } catch (Throwable t) {
                logError("ERROR: " + t.getMessage());
                t.printStackTrace(new PrintStream(callbacks.getStderr()));
            }
        }
        
        private void generateExploitDetails(IHttpRequestResponse reqRes, 
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
            }
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
        synchronized (this) {
            if (executor != null && !executor.isShutdown()) {
                executor.shutdown();
                try {
                    // Wait for tasks to complete
                    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                        logWarning("Some scanning tasks may not have completed cleanly");
                    }
                } catch (InterruptedException e) {
                    executor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}

